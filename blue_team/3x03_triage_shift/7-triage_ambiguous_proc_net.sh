#!/bin/bash
set -euo pipefail

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x03_assets}"

python3 - "$ASSETS_DIR/ioc_context.json" <<'PY'
import json
import os
import sys

with open("enriched_queue.json", encoding="utf-8") as f:
    alerts = json.load(f)

with open(sys.argv[1], encoding="utf-8") as f:
    ioc_data = json.load(f)

iocs = ioc_data.get("indicators", {})

handled = set()
for name in ("batch1_clearcut_tp.json",
             "batch2_clearcut_fp.json",
             "batch3.json",
             "batch4_auth.json"):
    path = os.path.join("tickets", name)
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            handled.update(x.get("alert_id") for x in json.load(f))

tickets = []

for a in alerts:
    if a.get("alert_id") in handled:
        continue

    event = a.get("event_record", {})
    category = str(
        a.get("rule_category", event.get("event_category", ""))
    ).lower()

    if category not in ("process", "network"):
        continue

    asset_level = str(a.get("asset", {}).get("criticality", "")).lower()
    profile = a.get("baseline_host_profile", {})

    process_name = event.get("process_name")
    parent = event.get("parent_process")
    command = event.get("command_line")
    dst_ip = event.get("dst_ip")
    dst_host = event.get("dst_host")
    dst_port = event.get("dst_port")

    hits = list(a.get("ioc_hits", []))

    for value in (dst_ip, dst_host):
        if value and str(value) in iocs:
            hit = dict(iocs[str(value)])
            hit["indicator"] = str(value)
            if hit not in hits:
                hits.append(hit)

    reps = {h.get("reputation") for h in hits if isinstance(h, dict)}
    violations = profile.get("violations", [])

    known_elsewhere = bool(
        profile.get("known_elsewhere")
        or profile.get("process", {}).get("known_elsewhere")
        or profile.get("network", {}).get("known_elsewhere")
    )

    fp_reason = None

    if "malicious" in reps:
        classification = "true_positive"
        action = "escalate_tier2"
        reason = "Malicious IOC matched the process or destination."

    elif "suspicious" in reps and asset_level in ("critical", "high"):
        classification = "true_positive"
        action = "monitor"
        reason = f"Suspicious IOC matched on {asset_level} asset."

    elif ("suspicious" in reps
          and asset_level in ("medium", "low")
          and known_elsewhere):
        classification = "false_positive"
        action = "tune_rule"
        fp_reason = "suspicious_but_baseline_known_elsewhere"
        reason = "Suspicious IOC is baseline-known on another host."

    elif "clean" in reps and not violations:
        classification = "false_positive"
        action = "tune_rule"
        fp_reason = "clean_ioc_no_deviation"
        reason = "Clean IOC and no baseline deviation."

    else:
        classification = "true_positive"
        action = "monitor"
        reason = (
            f"Checked process={process_name}, parent={parent}, "
            f"command_line={command}, dst_ip={dst_ip}, "
            f"dst_host={dst_host}, dst_port={dst_port}, "
            f"IOC={sorted(str(x) for x in reps)}."
        )

    ticket = {
        "alert_id": a.get("alert_id"),
        "classification": classification,
        "recommended_action": action,
        "justification": reason,
        "evidence_refs": [str(a.get("event_ref", ""))]
    }

    if fp_reason:
        ticket["fp_reason"] = fp_reason

    tickets.append(ticket)

os.makedirs("tickets", exist_ok=True)

with open("tickets/batch5_proc_net.json", "w", encoding="utf-8") as f:
    json.dump(tickets, f, indent=2)
    f.write("\n")

print("batch 5 ambiguous process and network")
for t in tickets:
    print(f"  {t['alert_id']}  {t['classification']}  "
          f"{t['recommended_action']}")
print(f"batch size               : {len(tickets)}")
print(f"tickets written          : {len(tickets)}")
print("tickets/batch5_proc_net.json")
PY
