#!/bin/bash
set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"

EVENTS="$HANDOFF_DIR/data/normalized_events.json"
ASSETS="$HANDOFF_DIR/context/asset_inventory.json"
PRIORITIES="rule_prioritization.json"
BASELINE="$BASELINE_PKG/baselines/baseline_summary.json"

START=$(jq -r '.evaluation_window.start' "$BASELINE")
END=$(jq -r '.evaluation_window.end' "$BASELINE")

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

RULES=()
for rule in rules/sigma/*.yml; do
    [ -e "$rule" ] || continue
    name=$(basename "$rule")

    if [ -f "rules/sigma/tuned/$name" ]; then
        RULES+=("rules/sigma/tuned/$name")
    else
        RULES+=("$rule")
    fi
done

: > "$TMP/matches.jsonl"

for rule in "${RULES[@]}"; do
    ./3-sigma_runner.sh "$rule" \
        --window "$START,$END" >> "$TMP/matches.jsonl"
done

python3 - "$TMP/matches.jsonl" "$EVENTS" "$ASSETS" \
"$PRIORITIES" alert_queue.json alert_queue_schema.json \
"${RULES[@]}" <<'PY'
import datetime
import hashlib
import json
import sys
import uuid
import yaml

matches_file, events_file, assets_file = sys.argv[1:4]
priorities_file, output, schema_file = sys.argv[4:7]
rule_files = sys.argv[7:]

rules = {}
for path in rule_files:
    with open(path, encoding="utf-8") as f:
        rule = yaml.safe_load(f)
    rules[rule["id"]] = rule

with open(priorities_file, encoding="utf-8") as f:
    priorities = json.load(f)

priority_map = {
    item["rule_id"]: item["priority_score"]
    for item in priorities
}

with open(assets_file, encoding="utf-8") as f:
    asset_data = json.load(f)

asset_map = {}
for asset in asset_data.get("assets", []):
    hostname = asset.get("hostname")
    if hostname:
        asset_map[hostname] = asset

matches = []
with open(matches_file, encoding="utf-8") as f:
    for line in f:
        try:
            match = json.loads(line)
        except json.JSONDecodeError:
            continue

        if match.get("event_ref") is not None:
            matches.append(match)

raw_matches = len(matches)

refs = {}
for match in matches:
    ref = str(match["event_ref"])
    refs.setdefault(ref, []).append(match)

needed = set(refs)
events = {}

with open(events_file, encoding="utf-8") as f:
    for number, raw in enumerate(f, 1):
        ref = str(number)

        if ref in needed:
            try:
                events[ref] = (
                    json.loads(raw),
                    raw.rstrip("\n")
                )
            except json.JSONDecodeError:
                pass

        if len(events) == len(needed):
            break

generated_at = datetime.datetime.now(
    datetime.timezone.utc
).strftime("%Y-%m-%dT%H:%M:%SZ")

alerts = []

for ref, match_list in refs.items():
    if ref not in events:
        continue

    event, raw = events[ref]

    for match in match_list:
        rule_id = match.get("rule_id")
        rule = rules.get(rule_id)

        if not rule:
            continue

        hostname = (
            event.get("hostname")
            or event.get("host")
            or ""
        )

        techniques = []
        for tag in rule.get("tags", []):
            tag = str(tag).lower()
            if tag.startswith("attack.t"):
                techniques.append(
                    tag.replace("attack.", "").upper()
                )

        alerts.append({
            "alert_id": str(uuid.uuid5(
                uuid.NAMESPACE_URL,
                rule_id + ref
            )),
            "generated_at": generated_at,
            "rule_id": rule_id,
            "rule_title": rule.get("title", ""),
            "rule_level": rule.get("level", ""),
            "priority_score": priority_map.get(rule_id, 0),
            "event_ref": ref,
            "event_summary": {
                "timestamp": event.get("timestamp"),
                "hostname": hostname,
                "user": event.get("user"),
                "src_ip": event.get("src_ip"),
                "dst_ip": event.get("dst_ip"),
                "process_name": event.get("process_name"),
                "canonical_label": event.get("canonical_label"),
                "event_category": event.get("event_category")
            },
            "asset_context": asset_map.get(hostname, {}),
            "attack_techniques": sorted(set(techniques)),
            "status": "new",
            "evidence_hash": hashlib.sha256(
                raw.encode("utf-8")
            ).hexdigest()
        })

def parse_time(value):
    if not value:
        return datetime.datetime.min.replace(
            tzinfo=datetime.timezone.utc
        )

    return datetime.datetime.fromisoformat(
        value.replace("Z", "+00:00")
    )

alerts.sort(
    key=lambda x: parse_time(
        x["event_summary"]["timestamp"]
    )
)

deduped = []
last_seen = {}

for alert in alerts:
    key = (
        alert["rule_id"],
        alert["event_summary"]["hostname"],
        alert["event_summary"]["user"]
    )

    current = parse_time(
        alert["event_summary"]["timestamp"]
    )
    previous = last_seen.get(key)

    if previous is not None and (
        current - previous
    ).total_seconds() <= 60:
        continue

    deduped.append(alert)
    last_seen[key] = current

deduped.sort(
    key=lambda x: (
        -float(x["priority_score"]),
        parse_time(x["event_summary"]["timestamp"])
    )
)

with open(output, "w", encoding="utf-8") as f:
    json.dump(deduped, f, indent=2)
    f.write("\n")

schema = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "MedDefense Alert Queue",
    "type": "array",
    "items": {
        "type": "object",
        "required": [
            "alert_id",
            "generated_at",
            "rule_id",
            "rule_title",
            "rule_level",
            "priority_score",
            "event_ref",
            "event_summary",
            "asset_context",
            "attack_techniques",
            "status",
            "evidence_hash"
        ],
        "properties": {
            "alert_id": {
                "type": "string",
                "format": "uuid"
            },
            "generated_at": {
                "type": "string",
                "format": "date-time"
            },
            "rule_id": {"type": "string"},
            "rule_title": {"type": "string"},
            "rule_level": {"type": "string"},
            "priority_score": {"type": "number"},
            "event_ref": {"type": "string"},
            "event_summary": {
                "type": "object"
            },
            "asset_context": {
                "type": "object"
            },
            "attack_techniques": {
                "type": "array",
                "items": {"type": "string"}
            },
            "status": {
                "type": "string",
                "const": "new"
            },
            "evidence_hash": {
                "type": "string",
                "pattern": "^[a-f0-9]{64}$"
            }
        }
    }
}

with open(schema_file, "w", encoding="utf-8") as f:
    json.dump(schema, f, indent=2)
    f.write("\n")

print(f"rules executed            : {len(rule_files)}")
print(f"raw matches               : {raw_matches}")
print(f"after deduplication       : {len(deduped)}")
print("top 5 alerts")

for number, alert in enumerate(deduped[:5], 1):
    print(
        f'{number:2d}  '
        f'{alert["priority_score"]:5.1f}  '
        f'{alert["rule_level"]:8s}  '
        f'{alert["rule_title"][:30]:30s}  '
        f'{alert["event_summary"]["hostname"]}'
    )

print(
    f"alert_queue.json        : {len(deduped)} alerts"
)
print("alert_queue_schema.json : written")
PY
