"""Quick review of the latest telemetry batch."""
import json
import pathlib

LOG_DIR = pathlib.Path.home() / "Observability" / "logs" / "pslogs"

def load(prefix):
    files = sorted(LOG_DIR.glob(f"{prefix}-*.json"), reverse=True)
    if not files:
        return []
    records = []
    with open(files[0], encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return records

# PROCESSES
procs = load("processes")
sus_frags = ["\\temp\\", "\\downloads\\", "appdata\\roaming", "appdata\\local\\temp"]
suspicious = [p for p in procs if p.get("path") and any(f in p["path"].lower() for f in sus_frags)]
print(f"=== PROCESSES ({len(procs)} total) ===")
print(f"Suspicious paths: {len(suspicious)}")
for p in suspicious:
    print(f"  [!] {p['name']} PID {p['pid']} -> {p.get('path')}")
top = sorted(procs, key=lambda x: x.get("working_set_mb", 0), reverse=True)[:5]
print("Top memory:")
for p in top:
    print(f"  {p.get('working_set_mb',0):>8.1f} MB  {p['name']}")

# NETWORK
conns = load("network")
est = [c for c in conns if c.get("state") == "Established"]
local_ips = {"127.0.0.1", "::1", "0.0.0.0", "::"}
normal_ports = {80, 443, 53, 67, 68, 123, 5353}
external = [c for c in est if c.get("remote_address") not in local_ips
            and not str(c.get("remote_address", "")).startswith("192.168.")]
unusual = [c for c in external if c.get("remote_port") not in normal_ports]
print(f"\n=== NETWORK ({len(conns)} total | {len(est)} established | {len(external)} external) ===")
print(f"External on unusual ports: {len(unusual)}")
for c in unusual:
    nm = c.get("process_name") or f"PID {c.get('pid', '?')}"
    print(f"  [~] {nm} -> {c.get('remote_address', '?')}:{c.get('remote_port', '?')}")
print("All external established:")
for c in external:
    nm = c.get("process_name") or f"PID {c.get('pid', '?')}"
    print(f"  {nm} -> {c.get('remote_address', '?')}:{c.get('remote_port', '?')}")

# DNS
dns = load("dns")
bad_tlds = [".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".pw", ".cn", ".ru", ".su", ".cc"]
short_ttl = [d for d in dns if 0 < d.get("ttl_seconds", 9999) < 60]
odd_tld = [d for d in dns if any(d.get("entry", "").lower().endswith(t) for t in bad_tlds)]
print(f"\n=== DNS ({len(dns)} entries) ===")
print(f"Short TTL: {len(short_ttl)} | Unusual TLD: {len(odd_tld)}")
for d in short_ttl[:5]:
    print(f"  [~] {d.get('entry', '?')}  TTL={d.get('ttl_seconds', '?')}s")
for d in odd_tld[:5]:
    print(f"  [~] {d.get('entry', '?')}")
if not short_ttl and not odd_tld:
    print("  [OK] Nothing unusual")

# DEFENDER
defs = load("defender")
print(f"\n=== DEFENDER ===")
for d in defs:
    if d.get("record_type") == "av_status":
        print(f"  AV: {d.get('antivirus_enabled')} | RT: {d.get('realtime_protection_enabled')} | Defs age: {d.get('definitions_age_days')}d")
    if d.get("record_type") == "threat_detection":
        print(f"  [!!!] THREAT: {d.get('process_name')} at {d.get('detection_time')}")
if not any(d.get("record_type") == "threat_detection" for d in defs):
    print("  [OK] No threats")

# SCHEDULED TASKS
tasks = load("scheduled-tasks")
sus_tasks = [t for t in tasks if t.get("is_suspicious")]
print(f"\n=== SCHEDULED TASKS ({len(tasks)} total) ===")
print(f"Suspicious: {len(sus_tasks)}")
for t in sus_tasks:
    print(f"  [!] {t.get('task_name', '?')} -> {t.get('action', '?')}")
if not sus_tasks:
    print("  [OK] None suspicious")
