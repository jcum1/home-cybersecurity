# Collect-Network.ps1
# Captures active TCP connections joined with process names.
# Outputs one JSON object per line (NDJSON).
#
# What to look for:
#   - Connections to unexpected foreign IPs or high port numbers
#   - Processes that shouldn't be making network connections (e.g. notepad.exe)
#   - Many simultaneous connections from one process (could be scanning)
#   - ESTABLISHED connections from processes running out of Temp/Downloads

$LogDir = "$env:USERPROFILE\Observability\logs\pslogs"
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

$Timestamp = (Get-Date -Format "yyyyMMdd-HHmmss")
$OutFile = "$LogDir\network-$Timestamp.json"
$CollectedAt = (Get-Date -Format "o")

$ProcessMap = @{}
Get-Process | ForEach-Object { $ProcessMap[[int]$_.Id] = $_.Name }

Get-NetTCPConnection | ForEach-Object {
    [PSCustomObject]@{
        "@timestamp"   = $CollectedAt
        collector      = "Collect-Network"
        local_address  = $_.LocalAddress
        local_port     = $_.LocalPort
        remote_address = $_.RemoteAddress
        remote_port    = $_.RemotePort
        state          = $_.State.ToString()
        pid            = $_.OwningProcess
        process_name   = $ProcessMap[[int]$_.OwningProcess]
    } | ConvertTo-Json -Compress
} | Out-File -FilePath $OutFile -Encoding utf8

Write-Host "Network connections written to $OutFile"
