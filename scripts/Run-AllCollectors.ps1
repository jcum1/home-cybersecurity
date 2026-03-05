# Run-AllCollectors.ps1
# Master script: runs all telemetry collectors in sequence.
#
# USAGE:
#   Manual run:  powershell -ExecutionPolicy Bypass -File scripts\Run-AllCollectors.ps1
#
# SCHEDULE (no admin needed):
#   Open Task Scheduler → Create Task (not "Basic Task")
#   Trigger: On a schedule (e.g. every 5 minutes)
#   Action:  powershell.exe -ExecutionPolicy Bypass -NonInteractive -File "C:\Users\jcurtis1\git\home-cybersecurity\scripts\Run-AllCollectors.ps1"
#   Run whether user is logged on or not: leave unchecked (user-mode only)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "=== Security Telemetry Collection $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===" -ForegroundColor Cyan

$Collectors = @(
    "Collect-Processes.ps1",
    "Collect-Network.ps1",
    "Collect-DNS.ps1",
    "Collect-Defender.ps1",
    "Collect-ScheduledTasks.ps1"
)

foreach ($script in $Collectors) {
    $fullPath = Join-Path $ScriptDir $script
    Write-Host "Running $script..." -ForegroundColor Yellow
    try {
        & $fullPath
    } catch {
        Write-Warning "  $script failed: $($_.Exception.Message)"
    }
}

# Clean up log files older than 7 days
$LogDir = "$env:USERPROFILE\Observability\logs\pslogs"
$OldFiles = Get-ChildItem -Path $LogDir -Filter "*.json" -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-7) }
if ($OldFiles) {
    $OldFiles | Remove-Item -Force
    Write-Host "Cleaned up $($OldFiles.Count) log files older than 7 days" -ForegroundColor DarkGray
}

Write-Host "=== Collection complete ===" -ForegroundColor Green
