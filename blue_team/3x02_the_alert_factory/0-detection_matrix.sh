#!/bin/bash
set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"

EVENTS="$HANDOFF_DIR/data/enriched_events.json"
SCHEMA="$HANDOFF_DIR/schema/event_schema.json"
BASELINE="$BASELINE_PKG/baselines/baseline_summary.json"

python3 - "$EVENTS" "$SCHEMA" "$BASELINE" <<'PY'
import json
import sys
from collections import Counter, defaultdict

events_file, schema_file, baseline_file = sys.argv[1:4]

# Required Task 0 inputs
with open(schema_file, encoding="utf-8") as f:
    json.load(f)
with open(baseline_file, encoding="utf-8") as f:
    json.load(f)

counts = Counter()
present = defaultdict(Counter)
values = defaultdict(lambda: defaultdict(set))

with open(events_file, encoding="utf-8") as f:
    for line in f:
        if not line.strip():
            continue
        event = json.loads(line)
        source = event.get("source_type", "unknown")
        counts[source] += 1

        for field, value in event.items():
            if value is not None:
                present[source][field] += 1
                if isinstance(value, (str, int, float, bool)):
                    values[source][field].add(str(value))

matrix = []

for source in sorted(counts):
    total = counts[source]

    stable = sorted(
        field for field, count in present[source].items()
        if count / total >= 0.95
    )

    high = sorted(
        field for field, vals in values[source].items()
        if len(vals) > 0.5 * total
    )

    if source in ("windows_json", "linux_text"):
        types = ["signature", "anomaly", "behavioral", "correlation"]
    elif source == "suricata_alert":
        types = ["signature", "correlation"]
    elif source == "firewall":
        types = ["anomaly", "correlation"]
    elif source == "pcap_flow":
        types = ["anomaly", "behavioral"]
    else:
        types = ["anomaly"]

    rationale = {
        t: {
            "signature": "stable event fields",
            "anomaly": "baseline supports deviation detection",
            "behavioral": "events support activity patterns",
            "correlation": "events can be linked across records",
        }[t]
        for t in types
    }

    tactics = {
        "windows_json": ["TA0002", "TA0003", "TA0004", "TA0005"],
        "linux_text": ["TA0002", "TA0003", "TA0004", "TA0005"],
        "suricata_alert": ["TA0011"],
        "firewall": ["TA0011"],
        "pcap_flow": ["TA0011"],
    }.get(source, [])

    matrix.append({
        "source_type": source,
        "record_count": total,
        "stable_fields": stable,
        "high_cardinality_fields": high,
        "supported_detection_types": types,
        "rationale": rationale,
        "recommended_attack_tactics": tactics
    })

with open("detection_matrix.json", "w", encoding="utf-8") as f:
    json.dump(matrix, f, indent=2)
    f.write("\n")

for item in matrix:
    types = " ".join(item["supported_detection_types"])
    print(f'{item["source_type"]:<16} {len(item["supported_detection_types"])} types  [{types}]')

print(f"{len(matrix)} source types analyzed")
print("detection_matrix.json written")
PY
