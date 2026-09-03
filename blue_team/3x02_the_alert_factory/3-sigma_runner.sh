#!/bin/bash
set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
RULE="${1:-}"
shift || true

EVIDENCE="$HANDOFF_DIR/data/normalized_events.json"
MODE="normal"
WINDOW=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        --dry-run)
            MODE="dry"
            shift
            ;;
        --count-only)
            MODE="count"
            shift
            ;;
        --window)
            WINDOW="$2"
            shift 2
            ;;
        *)
            EVIDENCE="$1"
            shift
            ;;
    esac
done

python3 - "$RULE" "$EVIDENCE" "$MODE" "$WINDOW" <<'PY'
import json
import re
import sys
import time
import yaml
from datetime import datetime

rule_file, evidence_file, mode, window = sys.argv[1:5]

try:
    with open(rule_file, encoding="utf-8") as f:
        rule = yaml.safe_load(f)
except Exception as e:
    print(e)
    sys.exit(1)

if mode == "dry":
    print("VALID")
    sys.exit(0)

detection = rule.get("detection", {})
condition = detection.get("condition", "")
timeframe = rule.get("timeframe", detection.get("timeframe", ""))
selections = {
    k: v for k, v in detection.items()
    if k not in ("condition", "timeframe") and isinstance(v, dict)
}

def parse_time(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None

start = end = None
if window:
    start_text, end_text = window.split(",", 1)
    start = parse_time(start_text)
    end = parse_time(end_text)

def field_value(event, field):
    if field in event:
        return event.get(field)

    data = event.get("event_data", {})
    if isinstance(data, dict) and field in data:
        return data.get(field)

    return None

def selection_matches(event, selection):
    for field, wanted in selection.items():
        value = field_value(event, field)

        if isinstance(wanted, list):
            if str(value) not in [str(x) for x in wanted]:
                return False
        elif str(value) != str(wanted):
            return False

    return True

events = []

with open(evidence_file, encoding="utf-8") as f:
    for line_number, line in enumerate(f, 1):
        if not line.strip():
            continue

        event = json.loads(line)
        timestamp = parse_time(event.get("timestamp"))

        if start and (timestamp is None or timestamp < start):
            continue
        if end and (timestamp is None or timestamp > end):
            continue

        event["_event_ref"] = line_number
        events.append(event)

started = time.perf_counter()

matched = []

aggregation = re.search(
    r"count\(\)\s+by\s+(\w+)\s*>\s*(\d+)",
    condition
)

if aggregation:
    group_field = aggregation.group(1)
    threshold = int(aggregation.group(2))

    seconds = 120
    tf = re.search(r"(\d+)s", str(timeframe))
    if tf:
        seconds = int(tf.group(1))

    selection = next(iter(selections.values()), {})
    groups = {}

    for event in events:
        if not selection_matches(event, selection):
            continue

        key = field_value(event, group_field)
        timestamp = parse_time(event.get("timestamp"))

        if key is None or timestamp is None:
            continue

        groups.setdefault(str(key), []).append((timestamp, event))

    seen = set()

    for items in groups.values():
        items.sort(key=lambda x: x[0])

        for i in range(len(items)):
            window_events = []

            for j in range(i, len(items)):
                delta = (items[j][0] - items[i][0]).total_seconds()
                if delta > seconds:
                    break
                window_events.append(items[j][1])

            if len(window_events) > threshold:
                for event in window_events:
                    ref = event["_event_ref"]
                    if ref not in seen:
                        seen.add(ref)
                        matched.append(event)
else:
    for event in events:
        results = {
            name: selection_matches(event, selection)
            for name, selection in selections.items()
        }

        if " and " in condition:
            names = [x.strip() for x in condition.split(" and ")]
            ok = all(results.get(name, False) for name in names)
        else:
            ok = results.get(condition.strip(), False)

        if ok:
            matched.append(event)

elapsed = round((time.perf_counter() - started) * 1000, 3)

if mode == "count":
    print(len(matched))
    sys.exit(0)

result = {
    "rule_id": rule.get("id"),
    "rule_title": rule.get("title"),
    "level": rule.get("level"),
    "evidence_path": evidence_file,
    "match_count": len(matched),
    "matches": [
        {
            "timestamp": event.get("timestamp"),
            "hostname": event.get("hostname"),
            "event_ref": event["_event_ref"]
        }
        for event in matched
    ],
    "execution_time_ms": elapsed
}

print(json.dumps(result, indent=2))
PY
