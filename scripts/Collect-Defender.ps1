# Collect-Defender.ps1
# Captures Windows Defender AV status and any recent threat detections.
# Outputs one JSON object per line (NDJSON).
#
# What to look for:
#   - ANY threat detections (these are real security events)
#   - Real-time protection disabled
#   - Definitions more than 1-2 days old

$LogDir = "$env:USERPROFILE\Observability\logs\pslogs"
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

$Timestamp = (Get-Date -Format "yyyyMMdd-HHmmss")
$OutFile = "$LogDir\defender-$Timestamp.json"
$CollectedAt = (Get-Date -Format "o")

$Lines = @()

try {
    $status = Get-MpComputerStatus -ErrorAction Stop
    $Lines += [PSCustomObject]@{
        "@timestamp"                = $CollectedAt
        collector                   = "Collect-Defender"
        record_type                 = "av_status"
        antivirus_enabled           = $status.AntivirusEnabled
        realtime_protection_enabled = $status.RealTimeProtectionEnabled
        antispyware_enabled         = $status.AntispywareEnabled
        definitions_age_days        = $status.AntispywareSignatureAge
        last_quick_scan             = if ($status.QuickScanStartTime) { $status.QuickScanStartTime.ToString("o") } else { $null }
    } | ConvertTo-Json -Compress
} catch {
    $Lines += [PSCustomObject]@{
        "@timestamp" = $CollectedAt
        collector    = "Collect-Defender"
        record_type  = "av_status"
        error        = $_.Exception.Message
    } | ConvertTo-Json -Compress
}

try {
    Get-MpThreatDetection -ErrorAction Stop | ForEach-Object {
        $Lines += [PSCustomObject]@{
            "@timestamp"       = $CollectedAt
            collector          = "Collect-Defender"
            record_type        = "threat_detection"
            threat_id          = $_.ThreatID
            process_name       = $_.ProcessName
            action_success     = $_.ActionSuccess
            detection_time     = if ($_.InitialDetectionTime) { $_.InitialDetectionTime.ToString("o") } else { $null }
            resources_affected = ($_.Resources -join "; ")
        } | ConvertTo-Json -Compress
    }
} catch { }

$Lines | Out-File -FilePath $OutFile -Encoding utf8

Write-Host "Defender status written to $OutFile"
