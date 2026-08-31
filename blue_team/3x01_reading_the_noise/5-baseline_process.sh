#!/bin/bash

INPUT="labeled_events.json"
OUTPUT="baseline_process.json"
DAYS="${BASELINE_DAYS:-7}"

python3 - "$INPUT" "$OUTPUT" "$DAYS" <<'PY'
import json
import sys
from datetime import datetime, timedelta
from collections import defaultdict, Counter

inp, out, days = sys.argv[1], sys.argv[2], int(sys.argv[3])

processes = defaultdict(dict)
global_counts = Counter()
process_hosts = defaultdict(set)
pairs = defaultdict(set)

start = None
end = None

with open(inp, encoding="utf-8") as f:
    for line in f:
        e = json.loads(line)
        dt = datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00"))

        if start is None:
            start = dt
            end = start + timedelta(days=days)

        if not start <= dt < end:
            continue

        if e.get("canonical_label") != "process_start":
            continue

        host = e.get("hostname") or "unknown"
        process = e.get("process_name")

        if not process:
            continue

        user = e.get("user")
        timestamp = e["timestamp"]

        if process not in processes[host]:
            processes[host][process] = {
                "process_name": process,
                "execution_count": 0,
                "first_seen": timestamp,
                "last_seen": timestamp,
                "users": set()
            }

        item = processes[host][process]
        item["execution_count"] += 1
        item["last_seen"] = timestamp

        if user:
            item["users"].add(user)

        global_counts[process] += 1
        process_hosts[process].add(host)

        data = e.get("event_data") or {}
        parent = (
            data.get("ParentImage")
            or data.get("parent_process_name")
            or data.get("parent_process")
        )

        if parent:
            pairs[host].add((parent, process))

per_host = {}

for host, items in sorted(processes.items()):
    per_host[host] = []
    for process in sorted(items):
        item = items[process]
        item["users"] = sorted(item["users"])
        per_host[host].append(item)

global_top = [
    {"process_name": name, "execution_count": count}
    for name, count in global_counts.most_common(50)
]

rare = [
    {
        "process_name": name,
        "execution_count": global_counts[name],
        "hosts": sorted(process_hosts[name])
    }
    for name in sorted(global_counts)
    if len(process_hosts[name]) == 1 or global_counts[name] < 5
]

parent_child = {
    host: [
        {"parent": parent, "child": child}
        for parent, child in sorted(values)
    ]
    for host, values in sorted(pairs.items())
}

result = {
    "window": {
        "start": start.isoformat().replace("+00:00", "Z"),
        "end": end.isoformat().replace("+00:00", "Z")
    },
    "per_host": per_host,
    "global_top": global_top,
    "rare_processes": rare,
    "parent_child_pairs": parent_child
}

with open(out, "w", encoding="utf-8") as f:
    json.dump(result, f, indent=2)

pair_count = sum(len(x) for x in pairs.values())

print("baseline window :", result["window"]["start"], "->", result["window"]["end"])
print("processes indexed by host:", len(per_host))

if global_top:
    top = global_top[0]
    print("global top process    :", top["process_name"],
          "(" + str(top["execution_count"]) + " executions)")
else:
    print("global top process    : none (0 executions)")

print("rare processes        :", len(rare))
print("parent->child pairs   :", pair_count)
print("baseline_process.json written")
PY
