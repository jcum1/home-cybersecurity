# Watch-Alerts.ps1
# Polls the security-alerts Elasticsearch index and shows Windows desktop notifications.
#
# USAGE:
#   powershell -ExecutionPolicy Bypass -File scripts\Watch-Alerts.ps1
#
# Runs continuously, checking every 30 seconds for new alerts.
# Shows a Windows balloon notification when a new alert is detected.
# Press Ctrl+C to stop.

$EsUrl = "https://localhost:9200"
$Index = "security-alerts"
$Username = "elastic"
$Password = $env:ELASTIC_PASSWORD
$PollInterval = 30  # seconds

if (-not $Password) {
    Write-Error "ELASTIC_PASSWORD environment variable is not set. Set it with: setx ELASTIC_PASSWORD '<your-password>'"
    exit 1
}

# Track the last alert timestamp we've seen
$script:LastSeen = (Get-Date).ToUniversalTime().ToString("o")

Add-Type -AssemblyName System.Windows.Forms

# Create a persistent notification icon
$notifyIcon = New-Object System.Windows.Forms.NotifyIcon
$notifyIcon.Icon = [System.Drawing.SystemIcons]::Shield
$notifyIcon.Visible = $true
$notifyIcon.Text = "Security Alert Monitor"

function Show-Alert {
    param([string]$Title, [string]$Message, [string]$Level = "Warning")

    $tipIcon = switch ($Level) {
        "Critical" { [System.Windows.Forms.ToolTipIcon]::Error }
        "Warning"  { [System.Windows.Forms.ToolTipIcon]::Warning }
        default    { [System.Windows.Forms.ToolTipIcon]::Info }
    }

    $notifyIcon.BalloonTipTitle = $Title
    $notifyIcon.BalloonTipText = $Message
    $notifyIcon.BalloonTipIcon = $tipIcon
    $notifyIcon.ShowBalloonTip(10000)
}

function Check-Alerts {
    $cred = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${Username}:${Password}"))

    $body = @{
        query = @{
            bool = @{
                must = @(
                    @{ range = @{ alert_timestamp = @{ gt = $script:LastSeen } } }
                )
            }
        }
        sort = @(
            @{ alert_timestamp = @{ order = "desc" } }
        )
        size = 50
    } | ConvertTo-Json -Depth 10

    try {
        # PowerShell 5.1 does not support -SkipCertificateCheck or CA cert pinning
        # for Invoke-RestMethod. TrustAll callback is the standard workaround for
        # self-signed ES certs in PS 5.1.
        if (-not ([System.Management.Automation.PSTypeName]'TrustAll').Type) {
            Add-Type @"
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public class TrustAll {
    public static void Enable() {
        ServicePointManager.ServerCertificateValidationCallback =
            (sender, cert, chain, errors) => true;
    }
}
"@
        }
        [TrustAll]::Enable()

        $response = Invoke-RestMethod -Uri "$EsUrl/$Index/_search" `
            -Method POST -Body $body `
            -Headers @{ "Authorization" = "Basic $cred"; "Content-Type" = "application/json" } `
            -ErrorAction Stop

        $hits = $response.hits.hits
        if ($hits.Count -gt 0) {
            # Update LastSeen to the newest alert
            $newest = $hits[0]._source.alert_timestamp
            if ($newest) {
                $script:LastSeen = $newest
            }

            foreach ($hit in $hits) {
                $src = $hit._source
                $ruleName = $src.rule_name
                $message = $src.message

                # Determine severity from rule name
                $level = "Warning"
                if ($ruleName -match "Threat") { $level = "Critical" }
                if ($ruleName -match "Defender.*Down") { $level = "Critical" }

                Write-Host "  [!] ALERT: $ruleName - $message" -ForegroundColor Red
                Show-Alert -Title "Security Alert: $ruleName" -Message $message -Level $level
                Start-Sleep -Milliseconds 500  # small delay between multiple notifications
            }
        }
    }
    catch {
        # Index might not exist yet (no alerts fired) - that's fine
        if ($_.Exception.Message -notmatch "index_not_found") {
            Write-Host "  [~] Check failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

# ── Main Loop ──────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "=============================================="
Write-Host "  Security Alert Monitor"
Write-Host "=============================================="
Write-Host "  Polling: $EsUrl/$Index"
Write-Host "  Interval: every ${PollInterval}s"
Write-Host "  Desktop notifications: ON"
Write-Host ""
Write-Host "  Watching for alerts... (Ctrl+C to stop)"
Write-Host ""

# Show startup notification
Show-Alert -Title "Security Monitor Active" `
    -Message "Watching for security alerts every ${PollInterval}s" `
    -Level "Info"

try {
    while ($true) {
        Check-Alerts
        Start-Sleep -Seconds $PollInterval
    }
}
finally {
    $notifyIcon.Visible = $false
    $notifyIcon.Dispose()
    Write-Host "`n  Monitor stopped."
}
