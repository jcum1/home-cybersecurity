"""
analyze.py - Security Telemetry Analyzer
=========================================
Reads the JSON files produced by the PowerShell collectors and prints a
security-focused report, flagging anything worth investigating.

USAGE:
    python scripts/analyze.py

WHAT THIS TEACHES:
    The core skill of a security analyst is knowing what "normal" looks like
    so you can spot what isn't. This script builds that baseline automatically
    and surfaces anomalies for you to investigate.
"""

import json
import pathlib
import re
import sys
from collections import defaultdict

# ── Configuration ─────────────────────────────────────────────────────────────

LOG_DIR = pathlib.Path.home() / "Observability" / "logs" / "pslogs"

# Processes that are always expected to have network connections
KNOWN_NETWORK_PROCESSES = {
    "chrome", "firefox", "msedge", "opera", "brave",
    "svchost", "lsass", "system", "onedrive", "teams",
    "outlook", "dropbox", "zoom", "slack", "discord",
    "python", "python3", "powershell", "curl", "wget",
    "msteams", "skype", "spotify",
}

# Path fragments that are suspicious for a running process
SUSPICIOUS_PATH_FRAGMENTS = [
    r"\\temp\\", r"\\tmp\\", r"\\downloads\\",
    r"\\appdata\\roaming\\", r"\\appdata\\local\\temp\\",
    r"\\public\\", r"\\recycle", r"\\windows\\fonts\\",
]

# Ports that are entirely normal to see
COMMON_PORTS = {80, 443, 53, 67, 68, 123, 5353, 8080, 8443}

# TLDs that warrant a second look (not inherently malicious, just worth noting)
UNUSUAL_TLDS = {".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".pw",
                ".cn", ".ru", ".su", ".cc", ".info"}

# ── Helpers ───────────────────────────────────────────────────────────────────

RESET  = "\033[0m"
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"

def header(title: str) -> None:
    width = 70
    print(f"\n{BOLD}{CYAN}{'─' * width}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{'─' * width}{RESET}")

def finding(level: str, message: str, detail: str = "") -> None:
    """Print a single finding. level: 'HIGH', 'MEDIUM', 'INFO', 'OK'"""
    icons = {"HIGH": f"{RED}[!]{RESET}", "MEDIUM": f"{YELLOW}[~]{RESET}",
             "INFO": f"{CYAN}[i]{RESET}", "OK": f"{GREEN}[✓]{RESET}"}
    icon = icons.get(level, "[?]")
    print(f"  {icon}  {message}")
    if detail:
        for line in detail.strip().splitlines():
            print(f"       {line}")

def load_latest(prefix: str) -> list[dict]:
    """Load the most recent JSON file matching a prefix."""
    files = sorted(LOG_DIR.glob(f"{prefix}-*.json"), reverse=True)
    if not files:
        return []
    records = []
    with open(files[0], encoding="utf-8-sig") as f:  # utf-8-sig strips the Windows BOM
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return records

def is_suspicious_path(path: str) -> bool:
    if not path:
        return False
    p = path.lower()
    return any(re.search(frag, p) for frag in SUSPICIOUS_PATH_FRAGMENTS)

def looks_like_dga(domain: str) -> bool:
    """Very simple heuristic: long, high-entropy label with no vowel pattern."""
    label = domain.split(".")[0].lower()
    if len(label) < 10:
        return False
    vowels = sum(1 for c in label if c in "aeiou")
    consonants = sum(1 for c in label if c.isalpha() and c not in "aeiou")
    # High consonant-to-vowel ratio suggests random generation
    return consonants > 0 and (vowels == 0 or consonants / vowels > 5)

# ── Analysers ─────────────────────────────────────────────────────────────────

def analyse_processes(records: list[dict]) -> None:
    header("PROCESSES")
    if not records:
        finding("INFO", "No process data found. Run Collect-Processes.ps1 first.")
        return

    finding("INFO", f"Total processes: {len(records)}")

    no_path = [r for r in records if not r.get("path")]
    suspicious = [r for r in records if is_suspicious_path(r.get("path", ""))]
    big_mem = sorted(records, key=lambda r: r.get("working_set_mb", 0), reverse=True)[:5]

    if no_path:
        names = ", ".join(r["name"] for r in no_path[:10])
        finding("MEDIUM",
                f"{len(no_path)} process(es) with no executable path",
                f"These may be system threads or injected code. Names: {names}")
    else:
        finding("OK", "All processes have a known executable path.")

    if suspicious:
        for r in suspicious:
            finding("HIGH",
                    f"Process running from suspicious location: {r['name']} (PID {r['pid']})",
                    f"Path: {r.get('path')}")
    else:
        finding("OK", "No processes running from Temp/Downloads/unusual locations.")

    print(f"\n  {BOLD}Top 5 processes by memory:{RESET}")
    for r in big_mem:
        print(f"    {r.get('working_set_mb', 0):>8.1f} MB  {r['name']} (PID {r['pid']})")


def analyse_network(records: list[dict]) -> None:
    header("NETWORK CONNECTIONS")
    if not records:
        finding("INFO", "No network data found. Run Collect-Network.ps1 first.")
        return

    established = [r for r in records if r.get("state") == "Established"]
    finding("INFO", f"Total TCP connections: {len(records)}  |  Established: {len(established)}")

    # Group established connections by process
    by_process: dict[str, list] = defaultdict(list)
    for r in established:
        name = r.get("process_name") or f"PID {r.get('pid')}"
        by_process[name].append(r)

    # Flag processes making connections that are not in the known-good list
    unusual = {name: conns for name, conns in by_process.items()
               if name.lower() not in KNOWN_NETWORK_PROCESSES}
    if unusual:
        finding("MEDIUM", f"{len(unusual)} process(es) with outbound connections not in the known-good list:")
        for name, conns in list(unusual.items())[:8]:
            remotes = ", ".join(
                f"{c['remote_address']}:{c['remote_port']}" for c in conns[:3]
            )
            label = name if name else f"PID {conns[0].get('pid', '?')}"
            print(f"    {YELLOW}{label}{RESET} → {remotes}")
    else:
        finding("OK", "All network connections are from expected processes.")

    # Flag unusual remote ports
    weird_ports = [r for r in established
                   if r.get("remote_port") not in COMMON_PORTS
                   and r.get("remote_address") not in ("0.0.0.0", "::", "127.0.0.1", "::1")
                   and r.get("remote_port", 0) > 0]
    if weird_ports:
        finding("INFO", f"{len(weird_ports)} connection(s) to non-standard remote ports (not 80/443/53):")
        for r in weird_ports[:8]:
            proc = r.get("process_name") or f"PID {r.get('pid', '?')}"
            print(f"    {proc} → {r['remote_address']}:{r['remote_port']}")


def analyse_dns(records: list[dict]) -> None:
    header("DNS CACHE")
    if not records:
        finding("INFO", "No DNS data found. Run Collect-DNS.ps1 first.")
        return

    finding("INFO", f"Total cached DNS entries: {len(records)}")

    # Short TTL
    short_ttl = [r for r in records if 0 < r.get("ttl_seconds", 9999) < 60
                 and r.get("status") == "Success"]
    if short_ttl:
        finding("MEDIUM", f"{len(short_ttl)} entry/entries with very short TTL (< 60s) — possible fast-flux:")
        for r in short_ttl[:5]:
            print(f"    {r['entry']}  TTL={r['ttl_seconds']}s")
    else:
        finding("OK", "No suspiciously short DNS TTLs.")

    # Unusual TLDs
    unusual_tld = [r for r in records
                   if any(r.get("entry", "").lower().endswith(tld) for tld in UNUSUAL_TLDS)]
    if unusual_tld:
        finding("INFO", f"{len(unusual_tld)} entry/entries with unusual TLDs:")
        for r in unusual_tld[:8]:
            print(f"    {r['entry']}")

    # DGA-like names
    dga_like = [r for r in records if looks_like_dga(r.get("entry", ""))]
    if dga_like:
        finding("MEDIUM", f"{len(dga_like)} entry/entries with DGA-like (random-looking) names:")
        for r in dga_like[:5]:
            print(f"    {r['entry']}")
    else:
        finding("OK", "No DGA-like domain names detected.")


def analyse_defender(records: list[dict]) -> None:
    header("WINDOWS DEFENDER")
    if not records:
        finding("INFO", "No Defender data found. Run Collect-Defender.ps1 first.")
        return

    status_rec = next((r for r in records if r.get("record_type") == "av_status"), None)
    detections  = [r for r in records if r.get("record_type") == "threat_detection"]

    if status_rec:
        if status_rec.get("error"):
            finding("INFO", f"Could not read AV status: {status_rec['error']}")
        else:
            av_ok   = status_rec.get("antivirus_enabled")
            rt_ok   = status_rec.get("realtime_protection_enabled")
            age     = status_rec.get("definitions_age_days", "?")

            finding("OK" if av_ok else "HIGH",
                    f"Antivirus enabled: {av_ok}")
            finding("OK" if rt_ok else "HIGH",
                    f"Real-time protection enabled: {rt_ok}")
            finding("OK" if isinstance(age, int) and age <= 2 else "MEDIUM",
                    f"Definition age: {age} day(s)")

    if detections:
        finding("HIGH", f"{len(detections)} THREAT DETECTION(S) FOUND:")
        for d in detections:
            print(f"    Process: {d.get('process_name')}  |  Detected: {d.get('detection_time')}")
            print(f"    Resources: {d.get('resources_affected')}")
    else:
        finding("OK", "No threat detections on record.")


def analyse_scheduled_tasks(records: list[dict]) -> None:
    header("SCHEDULED TASKS")
    if not records:
        finding("INFO", "No scheduled task data found. Run Collect-ScheduledTasks.ps1 first.")
        return

    finding("INFO", f"Total scheduled tasks: {len(records)}")

    suspicious = [r for r in records if r.get("is_suspicious")]
    no_author  = [r for r in records
                  if not r.get("author") and r.get("state") in ("Ready", "Running")]

    if suspicious:
        finding("HIGH", f"{len(suspicious)} scheduled task(s) running from suspicious paths:")
        for r in suspicious[:5]:
            print(f"    Name:   {r['task_name']}")
            print(f"    Action: {r.get('action')}")
    else:
        finding("OK", "No scheduled tasks running from suspicious locations.")

    if no_author:
        finding("MEDIUM",
                f"{len(no_author)} active task(s) have no listed author (unusual for legitimate software):")
        for r in no_author[:5]:
            print(f"    {r['task_name']}  |  {r.get('action', '')[:80]}")

# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print(f"\n{BOLD}Security Telemetry Report{RESET}")
    print(f"Log directory: {LOG_DIR}")

    if not LOG_DIR.exists():
        print(f"\n{RED}Log directory does not exist: {LOG_DIR}{RESET}")
        print("Run the collectors first:")
        print("  powershell -ExecutionPolicy Bypass -File scripts\\Run-AllCollectors.ps1")
        sys.exit(1)

    analyse_processes(load_latest("processes"))
    analyse_network(load_latest("network"))
    analyse_dns(load_latest("dns"))
    analyse_defender(load_latest("defender"))
    analyse_scheduled_tasks(load_latest("scheduled-tasks"))

    header("SUMMARY")
    print(f"""
  {BOLD}Legend:{RESET}
    {RED}[!] HIGH{RESET}    — Investigate immediately
    {YELLOW}[~] MEDIUM{RESET}  — Worth a closer look
    {CYAN}[i] INFO{RESET}    — Informational, no action needed
    {GREEN}[✓] OK{RESET}     — Looks normal

  {BOLD}Next steps:{RESET}
    1. Look up any HIGH or MEDIUM findings on VirusTotal or Google
    2. Run the collectors again tomorrow and compare — changes over time are key
    3. Add this script to Windows Task Scheduler for daily automated reports
""")

if __name__ == "__main__":
    main()
