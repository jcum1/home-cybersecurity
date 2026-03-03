"""
deploy-alerts.py - Deploy Kibana Security Alert Rules
======================================================
Creates connectors and alert rules in Kibana via the Alerting API.

USAGE:
    python scripts/deploy-alerts.py

This creates:
  - 2 connectors (server-log + index writer)
  - 6 alert rules for security monitoring
"""

import json
import urllib.request
import urllib.error
import base64
import sys

KIBANA_URL = "http://localhost:5601"
USERNAME = "elastic"
PASSWORD = "Q3DgSMX82*lD2oO_HhKv"
DATA_VIEW_ID = "08d0cbeb-79dc-4dff-bcc4-6cbeef30022b"
ALERTS_INDEX = "security-alerts"


def api_call(method, path, body=None):
    """Make an authenticated Kibana API call."""
    url = f"{KIBANA_URL}{path}"
    auth = base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("kbn-xsrf", "true")
    req.add_header("Authorization", f"Basic {auth}")
    if data:
        req.add_header("Content-Type", "application/json")
    resp = urllib.request.urlopen(req)
    return json.loads(resp.read().decode())


def find_connector_by_name(name):
    """Find an existing connector by name, return its ID or None."""
    connectors = api_call("GET", "/api/actions/connectors")
    for c in connectors:
        if c.get("name") == name:
            return c["id"]
    return None


def find_rule_by_name(name):
    """Find an existing rule by name, return its ID or None."""
    result = api_call("GET", "/api/alerting/rules/_find?per_page=100")
    for r in result.get("data", []):
        if r.get("name") == name:
            return r["id"]
    return None


def ensure_connector(name, connector_type, config=None):
    """Create a connector if it doesn't exist, or return existing ID."""
    existing_id = find_connector_by_name(name)
    if existing_id:
        # Delete and recreate to ensure config is current
        try:
            api_call("DELETE", f"/api/actions/connector/{existing_id}")
        except urllib.error.HTTPError:
            pass

    body = {
        "name": name,
        "connector_type_id": connector_type,
        "config": config or {},
    }
    result = api_call("POST", "/api/actions/connector", body)
    return result["id"]


def create_rule(name, kql_query, threshold, interval, tags, log_connector_id, index_connector_id):
    """Create an ES query alert rule with KQL."""
    # Delete existing rule with same name
    existing_id = find_rule_by_name(name)
    if existing_id:
        try:
            api_call("DELETE", f"/api/alerting/rule/{existing_id}")
        except urllib.error.HTTPError:
            pass

    actions = [
        {
            "id": log_connector_id,
            "group": "query matched",
            "params": {
                "level": "warn",
                "message": (
                    f"SECURITY ALERT: {name} | "
                    "Matches: {{context.hits}} | "
                    "Time: {{context.date}}"
                ),
            },
            "frequency": {
                "notify_when": "onActionGroupChange",
                "throttle": None,
                "summary": False,
            },
        },
        {
            "id": index_connector_id,
            "group": "query matched",
            "params": {
                "documents": [
                    {
                        "rule_name": name,
                        "message": f"{name} triggered",
                        "alert_timestamp": "{{context.date}}",
                        "hits": "{{context.hits}}",
                    }
                ],
            },
            "frequency": {
                "notify_when": "onActionGroupChange",
                "throttle": None,
                "summary": False,
            },
        },
    ]

    body = {
        "name": name,
        "consumer": "alerts",
        "rule_type_id": ".es-query",
        "schedule": {"interval": interval},
        "params": {
            "searchConfiguration": {
                "query": {
                    "query": kql_query,
                    "language": "kuery",
                },
                "index": DATA_VIEW_ID,
            },
            "searchType": "searchSource",
            "aggType": "count",
            "groupBy": "all",
            "threshold": [threshold],
            "thresholdComparator": ">",
            "timeWindowSize": 15,
            "timeWindowUnit": "m",
            "size": 100,
            "excludeHitsFromPreviousRun": True,
        },
        "actions": actions,
        "tags": tags,
        "enabled": True,
    }
    return api_call("POST", "/api/alerting/rule", body)


# ── Alert Rule Definitions ────────────────────────────────────────────────────

RULES = [
    {
        "name": "Threat Detection",
        "query": 'collector: "Collect-Defender" AND record_type: "threat_detection"',
        "threshold": 0,
        "interval": "1m",
        "tags": ["security", "critical", "defender"],
    },
    {
        "name": "Defender Protection Down",
        "query": (
            'collector: "Collect-Defender" AND record_type: "av_status" '
            "AND (antivirus_enabled: false OR realtime_protection_enabled: false)"
        ),
        "threshold": 0,
        "interval": "5m",
        "tags": ["security", "high", "defender"],
    },
    {
        "name": "Suspicious Scheduled Task",
        "query": 'collector: "Collect-ScheduledTasks" AND is_suspicious: true',
        "threshold": 0,
        "interval": "5m",
        "tags": ["security", "high", "persistence"],
    },
    {
        "name": "Suspicious Process",
        "query": 'collector: "Collect-Processes" AND is_suspicious: true',
        "threshold": 0,
        "interval": "5m",
        "tags": ["security", "high", "execution"],
    },
    {
        "name": "Non-Standard Port Spike",
        "query": (
            'collector: "Collect-Network" AND state: "Established" '
            "AND NOT remote_port: 80 AND NOT remote_port: 443 "
            "AND NOT remote_port: 53 AND NOT remote_port: 0 "
            'AND NOT remote_address: "127.0.0.1" '
            'AND NOT remote_address: "::1" '
            'AND NOT remote_address: "0.0.0.0" '
            'AND NOT remote_address: "::"'
        ),
        "threshold": 20,
        "interval": "5m",
        "tags": ["security", "medium", "network"],
    },
    {
        "name": "Short TTL DNS Spike",
        "query": 'collector: "Collect-DNS" AND ttl_seconds < 60 AND ttl_seconds > 0',
        "threshold": 10,
        "interval": "5m",
        "tags": ["security", "medium", "dns"],
    },
]


def main():
    print("Deploying Kibana Security Alerts...")
    print(f"  Kibana: {KIBANA_URL}")
    print(f"  Alerts index: {ALERTS_INDEX}\n")

    # ── Step 1: Create Connectors ──────────────────────────────────────────
    print("  Step 1: Creating connectors...")
    try:
        log_id = ensure_connector("Security Alert Logger", ".server-log")
        print(f"    [+] Created: Security Alert Logger (ID: {log_id})")
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"    [!] FAILED: server-log connector")
        print(f"        {body[:300]}")
        sys.exit(1)

    try:
        index_id = ensure_connector(
            "Security Alert Index Writer",
            ".index",
            config={"index": ALERTS_INDEX, "executionTimeField": "alert_timestamp"},
        )
        print(f"    [+] Created: Security Alert Index Writer (ID: {index_id})")
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"    [!] FAILED: index connector")
        print(f"        {body[:300]}")
        sys.exit(1)

    # ── Step 2: Create Alert Rules ─────────────────────────────────────────
    print("\n  Step 2: Creating alert rules...")
    created = 0
    for r in RULES:
        try:
            create_rule(
                r["name"], r["query"], r["threshold"],
                r["interval"], r["tags"],
                log_id, index_id,
            )
            print(f"    [+] Created: {r['name']} (every {r['interval']}, threshold > {r['threshold']})")
            created += 1
        except urllib.error.HTTPError as e:
            body = e.read().decode()
            print(f"    [!] FAILED: {r['name']}")
            try:
                print(f"        {json.loads(body).get('message', body[:300])}")
            except json.JSONDecodeError:
                print(f"        {body[:300]}")

    print(f"\n    Created {created}/{len(RULES)} alert rules")

    # ── Step 3: Summary ────────────────────────────────────────────────────
    print(f"\n{'=' * 60}")
    print(f"  {'SUCCESS' if created == len(RULES) else 'PARTIAL'}! {created}/{len(RULES)} alerts deployed.")
    print(f"")
    print(f"  View alerts in Kibana:")
    print(f"    http://localhost:5601/app/management/insightsAndAlerting/triggersActions/rules")
    print(f"")
    print(f"  View connectors:")
    print(f"    http://localhost:5601/app/management/insightsAndAlerting/triggersActionsConnectors")
    print(f"")
    print(f"  Alert rules check every 1-5 minutes and write to:")
    print(f"    - Kibana server log (warnings)")
    print(f"    - Elasticsearch index: {ALERTS_INDEX}")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
