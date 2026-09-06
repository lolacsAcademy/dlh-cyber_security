#!/bin/bash
set -euo pipefail

python3 <<'PY'
import json
import os
from datetime import datetime

with open("enriched_queue.json", encoding="utf-8") as f:
    alerts = json.load(f)

previous = {}
ticket_files = [
    "batch1_clearcut_tp.json",
    "batch2_clearcut_fp.json",
    "batch4_auth.json",
    "batch5_proc_net.json"
]

for name in ticket_files:
    path = os.path.join("tickets", name)
    if not os.path.exists(path):
        continue
    with open(path, encoding="utf-8") as f:
        for ticket in json.load(f):
            previous[ticket.get("alert_id")] = ticket

def stamp(alert):
    value = alert.get("event_summary", {}).get("timestamp", "")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))

by_host = {}
for alert in alerts:
    host = alert.get("event_summary", {}).get("hostname")
    if not host:
        host = alert.get("event_record", {}).get("hostname")
    if host:
        by_host.setdefault(host, []).append(alert)

incidents = []
regrouped = 0

for host, host_alerts in by_host.items():
    host_alerts.sort(key=stamp)
    groups = []
    current = []

    for alert in host_alerts:
        if not current:
            current = [alert]
        elif (stamp(alert) - stamp(current[-1])).total_seconds() <= 600:
            current.append(alert)
        else:
            if len(current) >= 2:
                groups.append(current)
            current = [alert]

    if len(current) >= 2:
        groups.append(current)

    for group in groups:
        start = group[0].get("event_summary", {}).get("timestamp")
        end = group[-1].get("event_summary", {}).get("timestamp")
        confidence = (
            "high_confidence" if len(group) >= 3
            else "medium_confidence"
        )

        ids = [a.get("alert_id") for a in group]
        true_before = any(
            previous.get(i, {}).get("classification") == "true_positive"
            for i in ids
        )

        highest = max(a.get("priority_score", 0) or 0 for a in group)
        classification = (
            "true_positive"
            if true_before or highest >= 10
            else "false_positive"
        )

        techniques = sorted({
            tech
            for a in group
            for tech in a.get("attack_techniques", [])
        })

        criticality = max(
            (str(a.get("asset", {}).get("criticality", "")).lower()
             for a in group),
            key=lambda x: {
                "critical": 4, "high": 3, "medium": 2, "low": 1
            }.get(x, 0),
            default=""
        )

        action = "monitor"
        if confidence == "high_confidence" and criticality in ("critical", "high"):
            action = "escalate_tier2"

        incidents.append({
            "ticket_id": f"incident_{host}_{start}",
            "classification": classification,
            "confidence": confidence,
            "contributing_alerts": ids,
            "incident_window": {"start": start, "end": end},
            "attack_techniques": techniques,
            "recommended_action": action
        })

        regrouped += len(group)

        for alert_id in ids:
            if alert_id in previous:
                previous[alert_id]["grouped"] = True

for name in ticket_files:
    path = os.path.join("tickets", name)
    if not os.path.exists(path):
        continue
    with open(path, encoding="utf-8") as f:
        original = json.load(f)
    changed = []
    for ticket in original:
        alert_id = ticket.get("alert_id")
        changed.append(previous.get(alert_id, ticket))
    with open(path, "w", encoding="utf-8") as f:
        json.dump(changed, f, indent=2)
        f.write("\n")

os.makedirs("tickets", exist_ok=True)
out = "tickets/batch6_incidents.json"

with open(out, "w", encoding="utf-8") as f:
    json.dump(incidents, f, indent=2)
    f.write("\n")

print("batch 6 correlated incidents")
for incident in incidents:
    print(
        f"  {incident['ticket_id']}  "
        f"alerts={len(incident['contributing_alerts'])}  "
        f"{incident['confidence']}  "
        f"{incident['recommended_action']}"
    )
print(f"incidents assembled      : {len(incidents)}")
print(f"alerts regrouped         : {regrouped}")
print(out)
PY
