# Collect-ScheduledTasks.ps1
# Lists all Windows scheduled tasks.
# Persistence via scheduled tasks is one of the most common attacker techniques.
# Outputs one JSON object per line (NDJSON).
#
# What to look for:
#   - is_suspicious = true (running from Temp, Downloads, AppData\Roaming, etc.)
#   - Tasks you don't recognise, especially with no Author or Description
#   - Tasks with obfuscated or encoded command lines (long base64 strings)
#   - Tasks created recently compared to older snapshots

$LogDir = "$env:USERPROFILE\Observability\logs\pslogs"
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

$Timestamp = (Get-Date -Format "yyyyMMdd-HHmmss")
$OutFile = "$LogDir\scheduled-tasks-$Timestamp.json"
$CollectedAt = (Get-Date -Format "o")

$SuspiciousPaths = @("\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\", "\\downloads\\", "\\public\\", "\\appdata\\roaming\\")

Get-ScheduledTask | ForEach-Object {
    $task = $_
    $actionStr = ($task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join " | "
    $isSuspicious = ($SuspiciousPaths | Where-Object { $actionStr.ToLower() -like "*$_*" }).Count -gt 0

    [PSCustomObject]@{
        "@timestamp"  = $CollectedAt
        collector     = "Collect-ScheduledTasks"
        task_name     = $task.TaskName
        task_path     = $task.TaskPath
        state         = $task.State.ToString()
        author        = $task.Author
        description   = $task.Description
        action        = $actionStr
        is_suspicious = $isSuspicious
    } | ConvertTo-Json -Compress
} | Out-File -FilePath $OutFile -Encoding utf8

Write-Host "Scheduled tasks written to $OutFile"
