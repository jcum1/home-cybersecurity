"""
deploy-dashboards.py - Build and deploy Kibana Security Dashboards
==================================================================
Creates Lens visualizations and a dashboard in Kibana via the Saved Objects API.

USAGE:
    python scripts/deploy-dashboards.py

This creates a "Security Overview" dashboard in Kibana with panels for
processes, network connections, DNS, Defender status, and scheduled tasks.
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
ALERTS_DATA_VIEW_ID = "sec-alerts-dataview"
DATA_VIEW_REF = {
    "type": "index-pattern",
    "id": DATA_VIEW_ID,
    "name": "indexpattern-datasource-layer-layer0",
}
ALERTS_DATA_VIEW_REF = {
    "type": "index-pattern",
    "id": ALERTS_DATA_VIEW_ID,
    "name": "indexpattern-datasource-layer-layer0",
}


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


def create_lens(vis_id, title, query, datasource_states, visualization, ref=None):
    """Create a Lens visualization via the Kibana API."""
    body = {
        "attributes": {
            "title": title,
            "visualizationType": visualization["_type"],
            "state": {
                "datasourceStates": datasource_states,
                "visualization": {k: v for k, v in visualization.items() if k != "_type"},
                "query": {"query": query, "language": "kuery"},
                "filters": [],
            },
        },
        "references": [ref or DATA_VIEW_REF],
    }
    return api_call("POST", f"/api/saved_objects/lens/{vis_id}?overwrite=true", body)


def layer(columns):
    """Build a formBased datasource state from column definitions."""
    col_map = {}
    col_order = []
    for c in columns:
        col_map[c["id"]] = {k: v for k, v in c.items() if k != "id"}
        col_order.append(c["id"])
    return {
        "formBased": {
            "layers": {
                "layer0": {
                    "columns": col_map,
                    "columnOrder": col_order,
                    "incompleteColumns": {},
                }
            }
        }
    }


# ── Column builders (avoid repetition) ──────────────────────────────────────

def col_timestamp(col_id="colTimestamp"):
    return {"id": col_id, "dataType": "date", "isBucketed": True,
            "operationType": "date_histogram", "sourceField": "@timestamp",
            "params": {"interval": "auto"}, "label": "Timestamp"}

def col_count(col_id="colCount", label="Count"):
    return {"id": col_id, "dataType": "number", "isBucketed": False,
            "operationType": "count", "sourceField": "___records___", "label": label}

def col_terms(col_id, field, label, size=10, order_col="colCount"):
    return {"id": col_id, "dataType": "string", "isBucketed": True,
            "operationType": "terms", "sourceField": field,
            "params": {"size": size, "orderBy": {"columnId": order_col, "type": "column"}, "orderDirection": "desc"},
            "label": label}


# ── Visualization Definitions ───────────────────────────────────────────────

VISUALIZATIONS = [
    # 1. Event Volume Over Time (stacked area by collector)
    {
        "id": "sec-event-volume",
        "title": "Event Volume Over Time",
        "query": "",
        "ds": layer([
            col_timestamp(),
            col_terms("colCollector", "collector", "Collector", size=10, order_col="colCount"),
            col_count(),
        ]),
        "viz": {
            "_type": "lnsXY",
            "layers": [{"layerId": "layer0", "layerType": "data", "seriesType": "area_stacked",
                         "xAccessor": "colTimestamp", "accessors": ["colCount"], "splitAccessor": "colCollector"}],
            "legend": {"isVisible": True, "position": "right"},
            "preferredSeriesType": "area_stacked",
        },
    },

    # 2. Process Count Over Time (line)
    {
        "id": "sec-proc-count",
        "title": "Process Count Over Time",
        "query": "collector: \"Collect-Processes\"",
        "ds": layer([
            col_timestamp(),
            col_count(label="Process Count"),
        ]),
        "viz": {
            "_type": "lnsXY",
            "layers": [{"layerId": "layer0", "layerType": "data", "seriesType": "line",
                         "xAccessor": "colTimestamp", "accessors": ["colCount"]}],
            "legend": {"isVisible": False},
            "preferredSeriesType": "line",
        },
    },

    # 3. Top Processes by Memory (horizontal bar)
    {
        "id": "sec-top-memory",
        "title": "Top Processes by Memory (MB)",
        "query": "collector: \"Collect-Processes\" AND working_set_mb > 0",
        "ds": layer([
            col_terms("colName", "name", "Process", size=10, order_col="colMem"),
            {"id": "colMem", "dataType": "number", "isBucketed": False,
             "operationType": "max", "sourceField": "working_set_mb",
             "label": "Memory (MB)"},
        ]),
        "viz": {
            "_type": "lnsXY",
            "layers": [{"layerId": "layer0", "layerType": "data", "seriesType": "bar_horizontal",
                         "xAccessor": "colName", "accessors": ["colMem"]}],
            "legend": {"isVisible": False},
            "preferredSeriesType": "bar_horizontal",
        },
    },

    # 4. Network Connections by State (pie)
    {
        "id": "sec-net-state",
        "title": "Network Connections by State",
        "query": "collector: \"Collect-Network\"",
        "ds": layer([
            col_terms("colState", "state", "State", size=10, order_col="colCount"),
            col_count(),
        ]),
        "viz": {
            "_type": "lnsPie",
            "shape": "pie",
            "layers": [{"layerId": "layer0", "layerType": "data",
                         "primaryGroups": ["colState"], "metrics": ["colCount"],
                         "numberDisplay": "percent", "categoryDisplay": "default",
                         "legendDisplay": "default"}],
        },
    },

    # 5. External Connections by Process (horizontal bar)
    {
        "id": "sec-ext-conns",
        "title": "External Connections by Process",
        "query": "collector: \"Collect-Network\" AND state: \"Established\" AND NOT remote_address: \"127.0.0.1\" AND NOT remote_address: \"::1\" AND NOT remote_address: \"0.0.0.0\" AND NOT remote_address: \"::\"",
        "ds": layer([
            col_terms("colProcess", "process_name", "Process", size=15, order_col="colCount"),
            col_count(label="Connections"),
        ]),
        "viz": {
            "_type": "lnsXY",
            "layers": [{"layerId": "layer0", "layerType": "data", "seriesType": "bar_horizontal",
                         "xAccessor": "colProcess", "accessors": ["colCount"]}],
            "legend": {"isVisible": False},
            "preferredSeriesType": "bar_horizontal",
        },
    },

    # 6. Non-Standard Port Connections (table)
    {
        "id": "sec-unusual-ports",
        "title": "Non-Standard Port Connections",
        "query": "collector: \"Collect-Network\" AND state: \"Established\" AND NOT remote_port: 80 AND NOT remote_port: 443 AND NOT remote_port: 53 AND NOT remote_port: 0 AND NOT remote_address: \"127.0.0.1\" AND NOT remote_address: \"::1\" AND NOT remote_address: \"0.0.0.0\" AND NOT remote_address: \"::\"",
        "ds": layer([
            col_terms("colProcess", "process_name", "Process", size=20, order_col="colCount"),
            col_terms("colRemoteIP", "remote_address", "Remote IP", size=20, order_col="colCount"),
            col_terms("colPort", "remote_port", "Port", size=20, order_col="colCount"),
            col_count(),
        ]),
        "viz": {
            "_type": "lnsDatatable",
            "layerId": "layer0",
            "layerType": "data",
            "columns": [{"columnId": "colProcess"}, {"columnId": "colRemoteIP"},
                        {"columnId": "colPort"}, {"columnId": "colCount"}],
        },
    },

    # 7. DNS Short TTL Entries (table)
    {
        "id": "sec-dns-ttl",
        "title": "DNS - Short TTL Entries (< 60s)",
        "query": "collector: \"Collect-DNS\" AND ttl_seconds < 60 AND ttl_seconds > 0",
        "ds": layer([
            col_terms("colEntry", "entry", "Domain", size=20, order_col="colCount"),
            {"id": "colTTL", "dataType": "number", "isBucketed": False,
             "operationType": "min", "sourceField": "ttl_seconds",
             "label": "Min TTL (s)"},
            col_count(label="Times Seen"),
        ]),
        "viz": {
            "_type": "lnsDatatable",
            "layerId": "layer0",
            "layerType": "data",
            "columns": [{"columnId": "colEntry"}, {"columnId": "colTTL"}, {"columnId": "colCount"}],
        },
    },

    # 8. Defender Definition Age (metric)
    {
        "id": "sec-defender",
        "title": "Defender Definition Age (days)",
        "query": "collector: \"Collect-Defender\" AND record_type: \"av_status\"",
        "ds": layer([
            {"id": "colAge", "dataType": "number", "isBucketed": False,
             "operationType": "last_value", "sourceField": "definitions_age_days",
             "params": {"sortField": "@timestamp"},
             "label": "Definition Age (days)"},
        ]),
        "viz": {
            "_type": "lnsMetric",
            "layerId": "layer0",
            "layerType": "data",
            "metricAccessor": "colAge",
        },
    },

    # 9. Suspicious Scheduled Tasks (metric)
    {
        "id": "sec-sus-tasks",
        "title": "Suspicious Scheduled Tasks",
        "query": "collector: \"Collect-ScheduledTasks\" AND is_suspicious: true",
        "ds": layer([
            col_count(label="Suspicious Tasks"),
        ]),
        "viz": {
            "_type": "lnsMetric",
            "layerId": "layer0",
            "layerType": "data",
            "metricAccessor": "colCount",
        },
    },

    # 10. Threat Detections (metric)
    {
        "id": "sec-threats",
        "title": "Threat Detections",
        "query": "collector: \"Collect-Defender\" AND record_type: \"threat_detection\"",
        "ds": layer([
            col_count(label="Threats Detected"),
        ]),
        "viz": {
            "_type": "lnsMetric",
            "layerId": "layer0",
            "layerType": "data",
            "metricAccessor": "colCount",
        },
    },
]

# ── Alerts Panel (uses separate data view) ─────────────────────────────────

ALERTS_VIS = {
    "id": "sec-alerts-table",
    "title": "Active Alerts",
    "query": "",
    "ds": layer([
        col_terms("colRuleName", "rule_name", "Alert Rule", size=20, order_col="colCount"),
        col_terms("colMessage", "message", "Message", size=20, order_col="colCount"),
        col_count(label="Times Fired"),
    ]),
    "viz": {
        "_type": "lnsDatatable",
        "layerId": "layer0",
        "layerType": "data",
        "columns": [{"columnId": "colRuleName"}, {"columnId": "colMessage"}, {"columnId": "colCount"}],
    },
    "ref": ALERTS_DATA_VIEW_REF,
}

# ── Dashboard Layout ────────────────────────────────────────────────────────

LAYOUT = [
    ("sec-alerts-table",  0,  0, 48, 10),   # Alerts panel at the top
    ("sec-event-volume",  0, 10, 48, 12),
    ("sec-proc-count",    0, 22, 24, 12),
    ("sec-top-memory",   24, 22, 24, 12),
    ("sec-net-state",     0, 34, 16, 14),
    ("sec-ext-conns",    16, 34, 32, 14),
    ("sec-unusual-ports", 0, 48, 24, 14),
    ("sec-dns-ttl",      24, 48, 24, 14),
    ("sec-defender",      0, 62, 16, 8),
    ("sec-sus-tasks",    16, 62, 16, 8),
    ("sec-threats",      32, 62, 16, 8),
]


def main():
    print("Deploying Kibana Security Dashboard...")
    print(f"  Kibana: {KIBANA_URL}")
    print(f"  Data view: {DATA_VIEW_ID}\n")

    # ── Create alerts data view ────────────────────────────────────────────
    print("  Creating alerts data view...")
    try:
        try:
            api_call("DELETE", f"/api/saved_objects/index-pattern/{ALERTS_DATA_VIEW_ID}")
        except urllib.error.HTTPError:
            pass
        api_call("POST", f"/api/saved_objects/index-pattern/{ALERTS_DATA_VIEW_ID}?overwrite=true", {
            "attributes": {
                "title": "security-alerts",
                "timeFieldName": "alert_timestamp",
            },
        })
        print("  [+] Created: security-alerts data view\n")
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"  [~] Alerts data view: {body[:200]}\n")

    # ── Create alerts visualization ────────────────────────────────────────
    try:
        try:
            api_call("DELETE", f"/api/saved_objects/lens/{ALERTS_VIS['id']}")
        except urllib.error.HTTPError:
            pass
        create_lens(
            ALERTS_VIS["id"], ALERTS_VIS["title"], ALERTS_VIS["query"],
            ALERTS_VIS["ds"], ALERTS_VIS["viz"], ALERTS_VIS["ref"],
        )
        print(f"  [+] Created: {ALERTS_VIS['title']}")
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"  [!] FAILED: {ALERTS_VIS['title']}")
        try:
            print(f"      {json.loads(body).get('message', body[:200])}")
        except json.JSONDecodeError:
            print(f"      {body[:200]}")

    created = 0
    for v in VISUALIZATIONS:
        try:
            try:
                api_call("DELETE", f"/api/saved_objects/lens/{v['id']}")
            except urllib.error.HTTPError:
                pass
            create_lens(v["id"], v["title"], v["query"], v["ds"], v["viz"])
            print(f"  [+] Created: {v['title']}")
            created += 1
        except urllib.error.HTTPError as e:
            body = e.read().decode()
            print(f"  [!] FAILED: {v['title']}")
            try:
                print(f"      {json.loads(body).get('message', body[:200])}")
            except json.JSONDecodeError:
                print(f"      {body[:200]}")

    print(f"\n  Created {created}/{len(VISUALIZATIONS)} visualizations")

    print("\n  Building dashboard...")

    panels = []
    refs = []
    for i, (vis_id, x, y, w, h) in enumerate(LAYOUT):
        pid = f"panel{i}"
        panels.append({
            "version": "9.2.4",
            "type": "lens",
            "gridData": {"x": x, "y": y, "w": w, "h": h, "i": pid},
            "panelIndex": pid,
            "embeddableConfig": {},
            "panelRefName": f"panel_{pid}",
        })
        refs.append({"name": f"panel_{pid}", "type": "lens", "id": vis_id})

    dash_body = {
        "attributes": {
            "title": "Security Overview",
            "description": "Home cybersecurity lab - process, network, DNS, Defender, and scheduled task monitoring",
            "panelsJSON": json.dumps(panels),
            "timeRestore": True,
            "timeTo": "now",
            "timeFrom": "now-24h",
            "refreshInterval": {"pause": False, "value": 300000},
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "query": {"query": "", "language": "kuery"},
                    "filter": []
                })
            },
        },
        "references": refs,
    }

    try:
        try:
            api_call("DELETE", "/api/saved_objects/dashboard/sec-overview")
        except urllib.error.HTTPError:
            pass
        api_call("POST", "/api/saved_objects/dashboard/sec-overview", dash_body)
        print("  [+] Created: Security Overview dashboard")
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"  [!] FAILED to create dashboard")
        try:
            print(f"      {json.loads(body).get('message', body[:200])}")
        except json.JSONDecodeError:
            print(f"      {body[:200]}")
        sys.exit(1)

    print(f"\n{'=' * 60}")
    print(f"  SUCCESS! Dashboard deployed.")
    print(f"")
    print(f"  Open Kibana:")
    print(f"    http://localhost:5601/app/dashboards")
    print(f"")
    print(f"  Click 'Security Overview' to see your dashboard!")
    print(f"  Set time range to 'Today' for best results.")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
