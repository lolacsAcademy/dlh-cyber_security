#!/bin/bash

SUMMARY="baseline_summary.json"
EVENTS="labeled_events.json"
OUTPUT="anomalies_process.json"

# Severity rubric:
# unknown process = medium
# unknown parent-child = medium
# rare process spike = high
# high-risk process = high

python3 - "$SUMMARY" "$EVENTS" "$OUTPUT" <<'PY'
import json
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import PureWindowsPath, PurePosixPath

summary_file, events_file, output = sys.argv[1:4]

WATCHLIST = {
    "powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe",
    "nc", "nmap", "wget", "curl", "python3", "bash"
}

with open(summary_file, encoding="utf-8") as f:
    summary = json.load(f)

process = summary["process"]
start_text = summary["evaluation_window"]["start"]
end_text = summary["evaluation_window"]["end"]

start = datetime.fromisoformat(start_text.replace("Z", "+00:00"))
end = datetime.fromisoformat(end_text.replace("Z", "+00:00"))

known_processes = defaultdict(set)
for host, items in process["per_host"].items():
    for item in items:
        known_processes[host].add(item["process_name"])

known_pairs = defaultdict(set)
for host, items in process.get("parent_child_pairs", {}).items():
    for item in items:
        known_pairs[host].add((item["parent"], item["child"]))

rare_names = {
    item["process_name"]
    for item in process.get("rare_processes", [])
    if item["execution_count"] < 5
}

def basename(name):
    if not name:
        return ""
    if "\\" in name:
        return PureWindowsPath(name).name.lower()
    return PurePosixPath(name).name.lower()

events = []
spikes = defaultdict(list)

with open(events_file, encoding="utf-8") as f:
    for line in f:
        e = json.loads(line)
        dt = datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00"))

        if not start <= dt < end:
            continue
        if e.get("canonical_label") != "process_start":
            continue

        events.append(e)

        process_name = e.get("process_name")
        host = e.get("hostname") or "unknown"

        if process_name in rare_names:
            spikes[(host, process_name)].append(e)

anomalies = []

def add(e, anomaly_type, severity, parent=None):
    anomalies.append({
        "timestamp": e["timestamp"],
        "host": e.get("hostname"),
        "user": e.get("user"),
        "process_name": e.get("process_name"),
        "parent_process_name": parent,
        "anomaly_type": anomaly_type,
        "severity": severity,
        "event_refs": [e.get("event_id")]
    })

for e in events:
    host = e.get("hostname") or "unknown"
    child = e.get("process_name")

    data = e.get("event_data") or {}
    parent = (
        data.get("ParentImage")
        or data.get("parent_process_name")
        or data.get("parent_process")
    )

    if child not in known_processes[host]:
        add(e, "unknown_process_for_host", "medium", parent)

    if parent and (parent, child) not in known_pairs[host]:
        add(e, "unknown_parent_child", "medium", parent)

    if basename(child) in WATCHLIST and child not in known_processes[host]:
        add(e, "high_risk_process", "high", parent)

for (host, process_name), items in spikes.items():
    if len(items) > 10:
        data = items[0].get("event_data") or {}
        parent = (
            data.get("ParentImage")
            or data.get("parent_process_name")
            or data.get("parent_process")
        )
        add(items[0], "rare_process_spike", "high", parent)

anomalies.sort(key=lambda x: x["timestamp"])

with open(output, "w", encoding="utf-8") as f:
    json.dump(anomalies, f, indent=2)

counts = defaultdict(int)
for item in anomalies:
    counts[item["anomaly_type"]] += 1

print("evaluation window :", start_text, "->", end_text)
print("unknown_process_for_host :", counts["unknown_process_for_host"])
print("unknown_parent_child     :", counts["unknown_parent_child"])
print("rare_process_spike       :", counts["rare_process_spike"])
print("high_risk_process        :", counts["high_risk_process"])
print("total anomalies          :", len(anomalies))
print("anomalies_process.json written")
PY
