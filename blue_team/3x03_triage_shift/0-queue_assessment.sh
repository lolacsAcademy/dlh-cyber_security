#!/bin/bash

CATALOG_DIR="${CATALOG_DIR:-$HOME/3x02_package/detection_catalog}"
QUEUE="$CATALOG_DIR/alerts/alert_queue.json"
SCHEMA="$CATALOG_DIR/alerts/alert_queue_schema.json"

python3 - "$QUEUE" "$SCHEMA" <<'PY'
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

queue_file, schema_file = sys.argv[1], sys.argv[2]

with open(queue_file, encoding="utf-8") as f:
    queue = json.load(f)

with open(schema_file, encoding="utf-8") as f:
    schema = json.load(f)

alerts = queue if isinstance(queue, list) else queue.get("alerts", [])
required = schema.get("items", schema).get("required", [])

errors = []
bands = Counter()
rules = Counter()
hosts = Counter()
tactics = Counter()
scores = defaultdict(float)
timestamps = []

for alert in alerts:
    missing = [field for field in required if field not in alert]
    if missing:
        errors.append({
            "alert_id": alert.get("alert_id"),
            "errors": ["missing: " + ", ".join(missing)]
        })

    score = alert.get("priority_score", 0)
    if score >= 20:
        bands["critical"] += 1
    elif score >= 10:
        bands["high"] += 1
    elif score >= 5:
        bands["medium"] += 1
    else:
        bands["low"] += 1

    rule_id = alert.get("rule_id", "unknown")
    rules[rule_id] += 1

    summary = alert.get("event_summary", {})
    host = summary.get("hostname", alert.get("hostname", "unknown"))
    hosts[host] += 1
    scores[host] += score

    timestamp = summary.get("timestamp")
    if timestamp:
        timestamps.append(timestamp)

    tags = alert.get("rule_tags", alert.get("tags", []))
    for tag in tags:
        if isinstance(tag, str) and tag.lower().startswith("attack.tactic."):
            tactics[tag.split(".")[-1]] += 1

result = {
    "queue_size": len(alerts),
    "validation_errors": errors,
    "by_priority_band": {
        "critical": bands["critical"],
        "high": bands["high"],
        "medium": bands["medium"],
        "low": bands["low"]
    },
    "by_rule": dict(rules.most_common()),
    "by_hostname": dict(hosts.most_common()),
    "by_attack_tactic": dict(tactics.most_common()),
    "time_span": {
        "first": min(timestamps) if timestamps else None,
        "last": max(timestamps) if timestamps else None
    },
    "top_targets": [
        {"hostname": host, "priority_score": score}
        for host, score in sorted(
            scores.items(), key=lambda x: (-x[1], x[0])
        )[:3]
    ]
}

with open("queue_assessment.json", "w", encoding="utf-8") as f:
    json.dump(result, f, indent=2)
    f.write("\n")

date = datetime.now(timezone.utc).date()
print(f"=== SHIFT BRIEFING {date} ===")
print(f"queue size           : {len(alerts)} alerts")
print(f"validation errors    : {len(errors)}")
print(f"time span            : {result['time_span']['first']} -> {result['time_span']['last']}")
print("priority bands")
for band in ("critical", "high", "medium", "low"):
    print(f"  {band:<10}: {bands[band]}")

print("top rules (5)")
for rule, count in rules.most_common(5):
    print(f"  {rule:<32} {count}")

print("top hosts (3 by cumulative score)")
for item in result["top_targets"]:
    print(f"  {item['hostname']:<20} score {item['priority_score']:g}")

print(f"attack tactics covered : {len(tactics)}")
print("queue_assessment.json written")
PY
