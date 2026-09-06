#!/bin/bash
set -euo pipefail

python3 <<'PY'
import glob
import hashlib
import json

with open("enriched_queue.json", encoding="utf-8") as f:
    queue = json.load(f)

alerts = {a.get("alert_id"): a for a in queue}
selected = []

for path in sorted(glob.glob("tickets/*.json")):
    with open(path, encoding="utf-8") as f:
        for ticket in json.load(f):
            if (ticket.get("classification") == "true_positive"
                    and ticket.get("recommended_action")
                    in ("escalate_tier2", "monitor")):
                selected.append(ticket)

incidents = []

for ticket in selected:
    ids = ticket.get("contributing_alerts") or [ticket.get("alert_id")]
    source = [alerts[i] for i in ids if i in alerts]
    if not source:
        continue

    first = source[0]
    host = (
        first.get("event_summary", {}).get("hostname")
        or first.get("event_record", {}).get("hostname")
        or "unknown"
    )
    title = first.get("rule_title", "security alert")

    seed = str(ticket.get("ticket_id") or ticket.get("alert_id"))
    incident_id = "INC-" + hashlib.sha256(
        seed.encode()
    ).hexdigest()[:12].upper()

    timeline = []
    iocs = set()
    techniques = set()
    assets = {}

    for alert in source:
        event = alert.get("event_record", {})
        summary = alert.get("event_summary", {})

        timeline.append({
            "timestamp": event.get("timestamp", summary.get("timestamp")),
            "hostname": event.get("hostname", summary.get("hostname")),
            "event_category": event.get("event_category"),
            "description": alert.get("rule_title", "security event")
        })

        for field in ("src_ip", "dst_ip", "dst_host",
                      "user", "process_name"):
            if event.get(field):
                iocs.add(str(event[field]))

        techniques.update(alert.get("attack_techniques", []))

        asset = alert.get("asset", {})
        name = asset.get("hostname", host)
        assets[name] = {
            "hostname": name,
            "criticality": asset.get("criticality"),
            "data_classification": asset.get("data_classification"),
            "network_zone": asset.get("network_zone")
        }

    timeline.sort(key=lambda x: x.get("timestamp") or "")

    text = (title + " " + ticket.get("justification", "")).lower()
    if "credential" in text or "privilege" in text:
        containment = "disable_account"
    elif "c2" in text or "command-and-control" in text:
        containment = "isolate_host"
    elif "egress" in text or "malicious destination" in text:
        containment = "block_ip_at_egress"
    elif "brute" in text or "ssh" in text:
        containment = "block_source_ip"
    else:
        containment = "isolate_host"

    incidents.append({
        "incident_id": incident_id,
        "summary": f"{title} detected on {host}.",
        "timeline": timeline,
        "affected_assets": list(assets.values()),
        "iocs": sorted(iocs),
        "attack_techniques": sorted(techniques),
        "recommended_containment": containment,
        "related_incidents": []
    })

for a in incidents:
    a_hosts = {x["hostname"] for x in a["affected_assets"]}
    a_iocs = set(a["iocs"])

    for b in incidents:
        if a["incident_id"] == b["incident_id"]:
            continue
        b_hosts = {x["hostname"] for x in b["affected_assets"]}
        if a_hosts & b_hosts or a_iocs & set(b["iocs"]):
            a["related_incidents"].append(b["incident_id"])

with open("incidents.json", "w", encoding="utf-8") as f:
    json.dump(incidents, f, indent=2)
    f.write("\n")

print("incidents assembled")
for incident in incidents:
    asset = incident["affected_assets"][0]["hostname"]
    print(f"  {incident['incident_id']}  {asset}  "
          f"{incident['recommended_containment']}")
print(f"total incidents         : {len(incidents)}")
print("incidents.json written")
PY
