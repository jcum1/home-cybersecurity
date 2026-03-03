# Collect-Processes.ps1
# Captures a snapshot of all running processes.
# Outputs one JSON object per line (NDJSON) so Filebeat and Python can parse it easily.
#
# What to look for:
#   - Processes running from unusual paths (Temp, Downloads, AppData\Roaming)
#   - Processes with no path (could be injected code)
#   - Processes you don't recognise
#   - High memory or CPU usage from unknown processes

$LogDir = "$env:USERPROFILE\Observability\logs\pslogs"
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

$Timestamp = (Get-Date -Format "yyyyMMdd-HHmmss")
$OutFile = "$LogDir\processes-$Timestamp.json"
$CollectedAt = (Get-Date -Format "o")

Get-Process | ForEach-Object {
    $proc = $_
    try { $path = $proc.MainModule.FileName } catch { $path = $null }

    [PSCustomObject]@{
        "@timestamp"   = $CollectedAt
        collector      = "Collect-Processes"
        pid            = $proc.Id
        name           = $proc.Name
        path           = $path
        cpu_seconds    = [math]::Round($proc.TotalProcessorTime.TotalSeconds, 2)
        working_set_mb = [math]::Round($proc.WorkingSet64 / 1MB, 2)
        start_time     = if ($proc.StartTime) { $proc.StartTime.ToString("o") } else { $null }
        responding     = $proc.Responding
    } | ConvertTo-Json -Compress
} | Out-File -FilePath $OutFile -Encoding utf8

Write-Host "Processes written to $OutFile"
