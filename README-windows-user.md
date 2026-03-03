
# Windows Endpoint Cybersecurity Observability (ELK, No-Admin)

## 1. Overview
- Goal: Monitor Windows workstation using ELK Stack.
- Constraints: No admin rights, no VirtualBox, no packet capture.
- Tools: Elasticsearch, Kibana, Filebeat (portable), OSQuery, PowerShell scripts.

## 2. Install Portable ELK Stack
- Download Elasticsearch ZIP → extract to user folder.
- Run `bin/elasticsearch.bat`.
- Download Kibana ZIP → extract to user folder.
- Run `bin/kibana.bat`.

## 3. Install OSQuery (User-Mode)
- Download osquery ZIP → extract to profile.
- Run `osqueryi.exe` for interactive queries.
- Create `osquery.conf` with scheduled queries.
- Run `osqueryd.exe --config_path=osquery.conf`.
- Output logs to `~/Observability/logs/osquery/`.

## 4. Install Filebeat (User-Mode)
- Download Filebeat ZIP → extract.
- Configure `filebeat.yml`:
  - Watch OSQuery logs.
  - Watch PowerShell-generated logs.
- Run Filebeat manually:
  - `filebeat.exe -e -c filebeat.yml`.

## 5. Create User-Mode Telemetry Scripts
- PowerShell scripts output JSON/CSV into `~/Observability/logs/pslogs/`.
- Suggested telemetry:
  - Running processes.
  - DNS cache.
  - Browser history exports.
  - Defender detections.
  - Network connections (user-visible only).

## 6. Send Logs into Elasticsearch
- OSQuery scheduled logs → Filebeat → Elasticsearch.
- PowerShell logs → Filebeat → Elasticsearch.
- Browser/Defender logs → Filebeat → Elasticsearch.

## 7. Build Kibana Dashboards
- Endpoint overview (processes, connections, DNS).
- Behavioral detections.
- Rare processes or unusual ports.
- Suspicious DNS answers.

## 8. Testing
- Browse web, launch apps.
- Trigger safe Defender alert (EICAR).
- Confirm ingestion paths:
  - OSQuery → Filebeat → Elasticsearch → Kibana.
  - PS scripts → Filebeat → Elasticsearch → Kibana.

## 9. Optional Future Expansion (Requires Admin)
- Sysmon installation.
- Full Winlogbeat ingestion.
- Packet capture (Npcap).
- Wazuh agent.
- Suricata/Zeek on Windows.
