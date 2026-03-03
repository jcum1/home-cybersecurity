# Collect-DNS.ps1
# Captures the Windows DNS client cache - every domain your machine resolved recently.
# Outputs one JSON object per line (NDJSON).
#
# What to look for:
#   - Domains you don't recognise
#   - Very short TTLs (under 60s) - "fast flux", often used by malware C2
#   - Unusual TLDs (.xyz, .top, .ru, .cn) in unexpected contexts
#   - Long random-looking names (e.g. "a8f3kq2b.xyz") - may be DGA malware

$LogDir = "$env:USERPROFILE\Observability\logs\pslogs"
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

$Timestamp = (Get-Date -Format "yyyyMMdd-HHmmss")
$OutFile = "$LogDir\dns-$Timestamp.json"
$CollectedAt = (Get-Date -Format "o")

Get-DnsClientCache | ForEach-Object {
    [PSCustomObject]@{
        "@timestamp" = $CollectedAt
        collector    = "Collect-DNS"
        entry        = $_.Entry
        record_name  = $_.Name
        record_type  = $_.Type.ToString()
        data         = $_.Data
        ttl_seconds  = $_.TimeToLive
        status       = $_.Status.ToString()
    } | ConvertTo-Json -Compress
} | Out-File -FilePath $OutFile -Encoding utf8

Write-Host "DNS cache written to $OutFile"
