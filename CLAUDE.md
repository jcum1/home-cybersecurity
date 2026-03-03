# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Purpose

Home lab cybersecurity observability project for monitoring a Windows 11 workstation.
No admin rights required. Uses Elasticsearch + Kibana + Filebeat + PowerShell telemetry scripts.
OSQuery is optionally supported once binaries are available (see below).

## Architecture and Data Flow

```
PowerShell scripts (scripts\Run-AllCollectors.ps1)
    └─► ~/Observability/logs/pslogs/*.json
            └─► Filebeat ──► Elasticsearch (HTTPS) ──► Kibana

OSQuery daemon (optional, needs binary — see below)
    └─► ~/Observability/logs/osquery/*.log
            └─► Filebeat ──► Elasticsearch ──► Kibana
```

## Quick Start

**Step 1 — Reset the elastic password** (do this once):
```bat
elasticsearch-9.2.4\bin\elasticsearch-reset-password.bat -u elastic -i
```
Note the new password. Then edit `filebeat-9.2.4-windows-x86_64\filebeat.yml` and replace `CHANGE_ME`.

**Step 2 — Start the stack:**
```bat
start-stack.bat
```
This opens three separate windows: Elasticsearch, Kibana, and Filebeat.

**Step 3 — Collect telemetry:**
```bat
powershell -ExecutionPolicy Bypass -File scripts\Run-AllCollectors.ps1
```

**Step 4 — View in Kibana:**
- Navigate to http://localhost:5601
- Go to Discover → create a data view for `filebeat-*`

## Key Files

| File | Purpose |
|------|---------|
| `elasticsearch-9.2.4/config/elasticsearch.yml` | ES config — TLS on, binds 0.0.0.0:9200, xpack security enabled |
| `kibana-9.2.4/config/kibana.yml` | Kibana config — points to https://localhost:9200 via service token |
| `filebeat-9.2.4-windows-x86_64/filebeat.yml` | Filebeat config — reads pslogs + osquery, outputs to ES over HTTPS |
| `osquery.conf` | OSQuery scheduled queries config (ready to use once binary is available) |
| `scripts/Run-AllCollectors.ps1` | Master collector — runs all five PS scripts in sequence |
| `scripts/Collect-Processes.ps1` | Snapshot of running processes |
| `scripts/Collect-Network.ps1` | Active TCP connections with process names |
| `scripts/Collect-DNS.ps1` | DNS client cache (what domains have been resolved) |
| `scripts/Collect-Defender.ps1` | Windows Defender status and threat detections |
| `scripts/Collect-ScheduledTasks.ps1` | Scheduled tasks (common malware persistence mechanism) |
| `start-stack.bat` | Convenience launcher for all three stack components |

## Starting Individual Components

```bat
# Elasticsearch (HTTPS on port 9200)
elasticsearch-9.2.4\bin\elasticsearch.bat

# Kibana (HTTP on port 5601)
kibana-9.2.4\bin\kibana.bat

# Filebeat (reads logs, ships to ES)
filebeat-9.2.4-windows-x86_64\filebeat.exe -e -c filebeat-9.2.4-windows-x86_64\filebeat.yml

# OSQuery interactive shell (when binary is available)
osquery-5.21.0.windows_x86_64\osqueryi.exe

# OSQuery daemon
osquery-5.21.0.windows_x86_64\osqueryd.exe --config_path=osquery.conf
```

## Elasticsearch Security Notes

- HTTPS required for all ES API calls (port 9200).
- CA cert: `elasticsearch-9.2.4/config/certs/http_ca.crt`
- Reset elastic password: `elasticsearch-9.2.4\bin\elasticsearch-reset-password.bat -u elastic -i`
- Generate new Kibana enrollment token: `elasticsearch-9.2.4\bin\elasticsearch-create-enrollment-token.bat -s kibana`

## OSQuery Binaries (optional)

The `osquery-5.21.0.windows_x86_64` directory only has Chocolatey installer files, not the executables.
To get `osqueryi.exe` / `osqueryd.exe` without admin rights:

```bat
msiexec /a osquery-5.21.0.msi /qb TARGETDIR=C:\Users\jcurtis1\osquery-extracted
```

Then copy the extracted `.exe` files into `osquery-5.21.0.windows_x86_64\`.

## Current State

- Elasticsearch: TLS + xpack security configured, certs in `elasticsearch-9.2.4/config/certs/`.
- Kibana: Enrolled, points to `https://localhost:9200` via service account token.
- Filebeat: Configured for Windows paths, HTTPS output, needs elastic password set.
- PowerShell scripts: All five collectors written and ready to run.
- OSQuery config: Written but binaries not yet extracted.
- Log directories: `~/Observability/logs/osquery/` and `~/Observability/logs/pslogs/` exist.
