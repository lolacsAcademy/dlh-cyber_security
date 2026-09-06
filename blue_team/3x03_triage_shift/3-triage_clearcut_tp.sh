#!/bin/bash
set -euo pipefail

python3 <<'PY'
import json
import os

with open("enriched_queue.json", encoding="utf-8") as f:
    alerts = json.load(f)

tickets = []

for alert in alerts:
    if alert.get("priority_band") != "critical":
        continue

    malicious = [
        hit for hit in alert.get("ioc_hits", [])
        if hit.get("reputation") == "malicious"
    ]
    if not malicious:
        continue

    baseline = alert.get("baseline_host_profile", {})
    violations = baseline.get("violations", [])
    if not violations:
        continue

    violation = violations[0]
    ioc = malicious[0]

    refs = [str(alert.get("event_ref", ""))]
    refs += [
        str(x) for x in alert.get("correlation_primitives", [])
    ]

    tickets.append({
        "alert_id": alert.get("alert_id"),
        "classification": "true_positive",
        "recommended_action": "escalate_tier2",
        "justification": (
            f"Malicious {ioc.get('category', 'IOC')} and "
            f"baseline violation: {violation}"
        ),
        "evidence_refs": refs
    })

os.makedirs("tickets", exist_ok=True)

with open("tickets/batch1_clearcut_tp.json", "w", encoding="utf-8") as f:
    json.dump(tickets, f, indent=2)
    f.write("\n")

print("batch 1 clear-cut true positives")
for ticket in tickets:
    print(f"  {ticket['alert_id']}  ESCALATE")

print(f"batch size               : {len(tickets)}")
print(f"tickets written          : {len(tickets)}")
print("tickets/batch1_clearcut_tp.json")
PY
