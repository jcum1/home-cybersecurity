PROJECT: Home Network Cybersecurity Observability (VirtualBox Edition)

1. Install VirtualBox on Windows 11
* Download VirtualBox from the official site
* Install VirtualBox Extension Pack
* Verify virtualization is enabled in BIOS (VT‑x/AMD‑V)

2. Create the Linux VM (Ubuntu Server)
* Download Ubuntu Server 22.04 LTS ISO
* Create new VM in VirtualBox
* Assign 2 CPU cores, 4–8 GB RAM, 40–60 GB disk
* Set network mode to “Bridged Adapter”
* Attach ISO and install Ubuntu
* Install VirtualBox Guest Additions (optional)

3. Prepare the VM for monitoring
* Update system packages
* Identify primary network interface (likely eth0)
* Enable packet capture permissions
* Disable firewall inside VM (optional for lab use)

4. Install Zeek
* Add Zeek repository or build from source
* Install Zeek package
* Configure Zeek to monitor the bridged network interface
* Test Zeek with a manual packet capture
* Verify logs appear in /opt/zeek/logs or /var/log/zeek

5. Install Suricata
* Install Suricata from Ubuntu repo or OISF PPA
* Configure Suricata in IDS mode
* Set interface to bridged adapter interface
* Enable Emerging Threats ruleset
* Verify alerts appear in /var/log/suricata

6. Choose a log storage and visualization stack Option A: ELK Stack (Elasticsearch + Kibana + Filebeat) Option B: Grafana Loki (Loki + Promtail + Grafana)

7. Install and configure ELK (if chosen)
* Install Elasticsearch
* Install Kibana
* Install Filebeat
* Enable Zeek and Suricata modules in Filebeat
* Point Filebeat to Elasticsearch
* Verify dashboards load in Kibana

8. Install and configure Loki stack (if chosen)
* Install Loki
* Install Promtail
* Configure Promtail to watch Zeek and Suricata log directories
* Install Grafana
* Add Loki as a data source
* Build dashboards for network activity and alerts

9. Add Sysmon to Windows 11 for endpoint visibility
* Download Sysmon from Sysinternals
* Install using a recommended config file
* Choose a log shipper:
* Winlogbeat (for ELK)
* Promtail (for Loki)
* Verify Windows logs appear in your dashboard

10. Build Python analysis tools (optional but recommended)
* Install Python on Windows or inside the VM
* Use pandas or PyShark to parse Zeek logs
* Create scripts for:
* New device detection
* Suspicious DNS detection
* Outbound connection analysis
* Traffic anomaly detection
* Optionally build a CLI dashboard using Rich or Textual

11. Test the monitoring pipeline
* Generate benign traffic (web browsing, DNS lookups)
* Trigger simple alerts (port scans from another device)
* Confirm logs flow from: Zeek → Log shipper → Storage → Dashboard Suricata → Log shipper → Storage → Dashboard Sysmon → Log shipper → Storage → Dashboard

12. Optional: Expand the setup later
* Add a managed switch with port mirroring
* Move Zeek/Suricata to a Raspberry Pi
* Add Wazuh for host‑based monitoring
* Add honeypots for threat research