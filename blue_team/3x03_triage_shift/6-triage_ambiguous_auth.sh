#!/bin/bash
set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"

python3 - "$HANDOFF_DIR/data/enriched_events.json" \
"$BASELINE_PKG/baselines/baseline_summary.json" <<'PY'
import json
import os
import sys
from collections import defaultdict, deque

events_file, baseline_file = sys.argv[1:3]

with open("enriched_queue.json", encoding="utf-8") as f:
    queue = json.load(f)

with open(baseline_file, encoding="utf-8") as f:
    baseline = json.load(f)

handled = set()
for name in ("batch1_clearcut_tp.json",
             "batch2_clearcut_fp.json",
             "batch3.json"):
    path = os.path.join("tickets", name)
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            handled.update(
                x.get("alert_id") for x in json.load(f)
            )

alerts = []
users = set()

for a in queue:
    category = str(
        a.get("rule_category",
              a.get("event_record", {}).get("event_category", ""))
    ).lower()

    if category in ("auth", "authentication") \
            and a.get("alert_id") not in handled:
        alerts.append(a)
        user = a.get("event_record", {}).get("user")
        if user:
            users.add(str(user))

history = defaultdict(lambda: deque(maxlen=20))

with open(events_file, encoding="utf-8") as f:
    for line in f:
        if not line.strip():
            continue
        e = json.loads(line)
        user = str(e.get("user", ""))
        category = str(e.get("event_category", "")).lower()
        if user in users and category in ("auth", "authentication"):
            history[user].append(e)

user_profiles = baseline.get("auth", {}).get("users", {})
max_fail = baseline.get("auth", {}).get("max_failures_1h_window", 0)

tickets = []

for a in alerts:
    e = a.get("event_record", {})
    user = str(e.get("user", ""))
    src = e.get("src_ip")
    host = e.get("hostname")
    asset = a.get("asset", {})
    criticality = str(asset.get("criticality", "")).lower()

    profile = user_profiles.get(user, {})
    known_ips = profile.get("source_ips", [])
    known_hosts = profile.get("hosts", [])

    unknown_ip = src not in known_ips
    unknown_host = host not in known_hosts
    hits = a.get("ioc_hits", [])
    burst = e.get("failure_count", 0) or 0

    if unknown_ip and criticality in ("critical", "high") and unknown_host:
        classification = "true_positive"
        action = "escalate_tier2"
        reason = (
            f"Unknown source IP {src}; user {user} has never logged "
            f"in to host {host}; asset criticality is {criticality}."
        )
        fp_reason = None

    elif unknown_ip and criticality in ("medium", "low") and not hits:
        classification = "false_positive"
        action = "tune_rule"
        reason = (
            f"Unknown source IP {src} on {criticality} asset with no IOC hit."
        )
        fp_reason = "unknown_ip_low_asset"

    elif src in known_ips and max_fail < burst <= max_fail * 2:
        classification = "false_positive"
        action = "tune_rule"
        reason = (
            f"Known source IP {src}; failure burst {burst} is between "
            f"baseline maximum {max_fail} and {max_fail * 2}."
        )
        fp_reason = "baseline_edge_burst"

    else:
        classification = "true_positive"
        action = "monitor"
        reason = (
            f"Ambiguous authentication: user={user}, src_ip={src}, "
            f"host={host}, criticality={criticality}, IOC hits={len(hits)}."
        )
        fp_reason = None

    ticket = {
        "alert_id": a.get("alert_id"),
        "classification": classification,
        "recommended_action": action,
        "justification": reason,
        "evidence_refs": [str(a.get("event_ref", ""))],
        "auth_history": list(history[user])
    }

    if fp_reason:
        ticket["fp_reason"] = fp_reason

    tickets.append(ticket)

os.makedirs("tickets", exist_ok=True)

with open("tickets/batch4_auth.json", "w", encoding="utf-8") as f:
    json.dump(tickets, f, indent=2)
    f.write("\n")

print("batch 4 ambiguous authentication")
for t in tickets:
    print(f"  {t['alert_id']}  {t['classification']}  "
          f"{t['recommended_action']}")
print(f"batch size               : {len(tickets)}")
print(f"tickets written          : {len(tickets)}")
print("tickets/batch4_auth.json")
PY
