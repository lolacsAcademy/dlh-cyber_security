#!/bin/bash
set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"

RULE="${1:-}"
shift || true

EVIDENCE="$HANDOFF_DIR/data/normalized_events.json"
MODE="normal"
WINDOW=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        --dry-run) MODE="dry"; shift ;;
        --count-only) MODE="count"; shift ;;
        --window) WINDOW="$2"; shift 2 ;;
        *) EVIDENCE="$1"; shift ;;
    esac
done

python3 - "$RULE" "$EVIDENCE" "$MODE" "$WINDOW" "$BASELINE_PKG" <<'PY'
import json
import sys
import time
import glob
import re
import yaml
from datetime import datetime

rule_file, evidence_file, mode, window, baseline_pkg = sys.argv[1:]

try:
    with open(rule_file, encoding="utf-8") as f:
        rule = yaml.safe_load(f)
except Exception as e:
    print(e)
    sys.exit(1)

if mode == "dry":
    print("VALID")
    sys.exit(0)

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

baseline_seen = set()
baseline_file = baseline_pkg + "/baselines/baseline_process.json"

try:
    with open(baseline_file, encoding="utf-8") as f:
        baseline = json.load(f)

    items = baseline if isinstance(baseline, list) else []
    if isinstance(baseline, dict):
        for key in ("processes", "baseline", "entries"):
            if isinstance(baseline.get(key), list):
                items = baseline[key]
                break

    for item in items:
        if isinstance(item, dict):
            host = item.get("hostname") or item.get("host")
            proc = item.get("process_name") or item.get("process")
            if host and proc:
                baseline_seen.add(
                    (str(host).lower(), str(proc).lower())
                )
except (FileNotFoundError, json.JSONDecodeError):
    pass

def get_value(event, field):
    if field == "hour_of_day":
        ts = parse_time(event.get("timestamp"))
        return ts.hour if ts else None

    if field == "baseline_seen":
        host = event.get("hostname")
        proc = event.get("process_name")
        if not host or not proc:
            return False
        return (str(host).lower(), str(proc).lower()) in baseline_seen

    if field in event:
        return event[field]

    data = event.get("event_data", {})
    if isinstance(data, dict):
        if field in data:
            return data[field]

        aliases = {
            "process_name": "Image",
            "parent_process_name": "ParentImage",
            "LogonType": "LogonType"
        }

        if field in aliases:
            return data.get(aliases[field])

    return None

def value_matches(value, wanted, modifier):
    if isinstance(wanted, list):
        return any(value_matches(value, x, modifier) for x in wanted)

    if modifier == "endswith":
        return str(value or "").lower().endswith(str(wanted).lower())

    if modifier == "startswith":
        return str(value or "").lower().startswith(str(wanted).lower())

    if modifier == "contains":
        return str(wanted).lower() in str(value or "").lower()

    if isinstance(wanted, bool):
        return value is wanted

    return str(value) == str(wanted)

def selection_matches(event, selection):
    for raw_field, wanted in selection.items():
        parts = raw_field.split("|", 1)
        field = parts[0]
        modifier = parts[1] if len(parts) == 2 else ""

        if not value_matches(
            get_value(event, field),
            wanted,
            modifier
        ):
            return False

    return True

events = []

with open(evidence_file, encoding="utf-8") as f:
    for line_number, line in enumerate(f, 1):
        if not line.strip():
            continue

        event = json.loads(line)
        ts = parse_time(event.get("timestamp"))

        if start and (ts is None or ts < start):
            continue
        if end and (ts is None or ts > end):
            continue

        event["_event_ref"] = line_number
        events.append(event)

detection = rule.get("detection", {})
condition = str(detection.get("condition", ""))

selections = {
    name: value
    for name, value in detection.items()
    if name not in ("condition", "timeframe")
    and isinstance(value, dict)
}

def condition_matches(event):
    text = condition.strip()

    aggregation = re.search(
        r"(.+?)\s*\|\s*count\(\)\s+by\s+(\w+)\s*>\s*(\d+)",
        text
    )

    if aggregation:
        return False

    if " and not " in text:
        left, right = text.split(" and not ", 1)
        return (
            condition_matches_named(event, left.strip())
            and not condition_matches_named(event, right.strip())
        )

    if " and " in text:
        names = [x.strip() for x in text.split(" and ")]
        return all(condition_matches_named(event, x) for x in names)

    if " or " in text:
        names = [x.strip() for x in text.split(" or ")]
        return any(condition_matches_named(event, x) for x in names)

    return condition_matches_named(event, text)

def condition_matches_named(event, name):
    return selection_matches(event, selections.get(name, {}))

matched = []

for event in events:
    if condition_matches(event):
        matched.append(event)

aggregation = re.search(
    r"count\(\)\s+by\s+(\w+)\s*>\s*(\d+)",
    condition
)

if aggregation:
    group_field = aggregation.group(1)
    threshold = int(aggregation.group(2))

    timeframe = str(
        rule.get("timeframe", detection.get("timeframe", "120s"))
    )

    tf = re.search(r"(\d+)s", timeframe)
    seconds = int(tf.group(1)) if tf else 120

    groups = {}

    for event in events:
        if not condition_matches_named(
            event,
            condition.split("|", 1)[0].strip()
        ):
            continue

        key = get_value(event, group_field)
        ts = parse_time(event.get("timestamp"))

        if key is not None and ts is not None:
            groups.setdefault(str(key), []).append((ts, event))

    matched = []
    seen = set()

    for group in groups.values():
        group.sort(key=lambda x: x[0])

        for i in range(len(group)):
            window_events = []

            for j in range(i, len(group)):
                delta = (
                    group[j][0] - group[i][0]
                ).total_seconds()

                if delta <= seconds:
                    window_events.append(group[j][1])
                else:
                    break

            if len(window_events) > threshold:
                for event in window_events:
                    ref = event["_event_ref"]
                    if ref not in seen:
                        seen.add(ref)
                        matched.append(event)

elapsed = round((time.perf_counter() - time.perf_counter()) * 1000, 3)

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
