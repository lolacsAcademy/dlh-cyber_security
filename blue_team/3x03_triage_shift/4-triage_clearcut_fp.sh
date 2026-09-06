#!/bin/bash
set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
ASSETS="$HANDOFF_DIR/context/asset_inventory.json"

python3 - "$ASSETS" <<'PY'
import json
import os
import sys
import ipaddress

with open("enriched_queue.json", encoding="utf-8") as f:
    alerts = json.load(f)

with open(sys.argv[1], encoding="utf-8") as f:
    inventory = json.load(f)

prefix = "svc_"
subnets = []

if isinstance(inventory, dict):
    prefix = inventory.get("service_account_prefix", prefix)
    subnets = inventory.get("management_subnets", [])

def in_management(ip):
    try:
        return any(
            ipaddress.ip_address(ip) in ipaddress.ip_network(net)
            for net in subnets
        )
    except (ValueError, TypeError):
        return False

tickets = []

for a in alerts:
    event = a.get("event_record", {})
    profile = a.get("baseline_host_profile", {})
    hits = a.get("ioc_hits", [])
    category = str(a.get("rule_category", a.get("event_category", ""))).lower()

    reason = None

    user = str(event.get("user", event.get("target_user", "")))
    if user.startswith(prefix) and category in ("auth", "authentication", "process"):
        reason = "service_account_activity"

    elif category == "network" and in_management(event.get("src_ip")):
        reason = "management_subnet"

    elif event.get("process_name") in profile.get("process", {}).get("expected", []):
        reason = "baseline_match"

    elif hits and all(h.get("reputation") == "clean" for h in hits) \
            and not profile.get("violations"):
        reason = "clean_ioc_no_deviation"

    if not reason:
        continue

    tickets.append({
        "alert_id": a.get("alert_id"),
        "classification": "false_positive",
        "recommended_action": "tune_rule",
        "justification": f"False positive signature matched: {reason}.",
        "fp_reason": reason,
        "evidence_refs": [str(a.get("event_ref", ""))]
    })

os.makedirs("tickets", exist_ok=True)

with open("tickets/batch2_clearcut_fp.json", "w", encoding="utf-8") as f:
    json.dump(tickets, f, indent=2)
    f.write("\n")

print("batch 2 clear-cut false positives")
for t in tickets:
    print(f"  {t['alert_id']}  CLOSE  {t['fp_reason']}")
print(f"batch size               : {len(tickets)}")
print(f"tickets written          : {len(tickets)}")
print("tickets/batch2_clearcut_fp.json")
PY
