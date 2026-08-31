#!/bin/bash

AUTH="anomalies_auth.json"
PROCESS="anomalies_process.json"
NETWORK="anomalies_network.json"
OUTPUT="correlated_anomalies.json"
WINDOW="${CORRELATION_WINDOW:-300}"

python3 - "$AUTH" "$PROCESS" "$NETWORK" "$OUTPUT" "$WINDOW" <<'PY'
import json
import sys
import hashlib
from datetime import datetime

auth_file, process_file, network_file, output, window = sys.argv[1:6]
window = int(window)

def load_file(name):
    try:
        with open(name, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return []

items = []

for source, filename in [
    ("auth", auth_file),
    ("process", process_file),
    ("network", network_file)
]:
    for index, event in enumerate(load_file(filename)):
        event["_source"] = source
        event["_ref"] = source + ":" + str(index)
        items.append(event)

items.sort(key=lambda x: x["timestamp"])
used = set()
findings = []

for i, first in enumerate(items):
    if i in used:
        continue

    host = first.get("host")
    if not host:
        continue

    first_time = datetime.fromisoformat(
        first["timestamp"].replace("Z", "+00:00")
    )

    group = []

    for j in range(i, len(items)):
        event = items[j]

        if event.get("host") != host:
            continue

        event_time = datetime.fromisoformat(
            event["timestamp"].replace("Z", "+00:00")
        )

        seconds = (event_time - first_time).total_seconds()

        if 0 <= seconds <= window:
            group.append((j, event))

    sources = sorted({e["_source"] for _, e in group})

    if len(group) >= 2 and len(sources) >= 2:
        types = sorted({e["anomaly_type"] for _, e in group})
        times = [e["timestamp"] for _, e in group]

        raw_id = host + "|" + min(times) + "|" + "|".join(types)
        correlation_id = hashlib.sha256(
            raw_id.encode()
        ).hexdigest()[:12]

        # Score: 1 per source + 1 per distinct anomaly type.
        # Criticality multiplier defaults to 1 because no asset
        # criticality field exists in the available baseline.
        criticality_multiplier = 1
        score = (len(sources) + len(types)) * criticality_multiplier

        findings.append({
            "correlation_id": correlation_id,
            "host": host,
            "window_start": min(times),
            "window_end": max(times),
            "sources_involved": sources,
            "anomaly_types": types,
            "member_refs": [e["_ref"] for _, e in group],
            "score": score
        })

        for j, _ in group:
            used.add(j)

with open(output, "w", encoding="utf-8") as f:
    json.dump(findings, f, indent=2)

max_score = max((x["score"] for x in findings), default=0)

print("single-source anomalies  :", len(items))
print("correlated findings      :", len(findings))
print("multi-host findings      : 0")
print("max score                :", max_score)
print("correlated_anomalies.json written")
PY
