#!/bin/bash

OUTPUT="baseline_validation.json"
LIMIT="${SELF_CHECK_THRESHOLD:-5}"

python3 - "$OUTPUT" "$LIMIT" <<'PY'
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import PureWindowsPath, PurePosixPath

output = sys.argv[1]
limit = int(sys.argv[2])

with open("baseline_summary.json", encoding="utf-8") as f:
    summary = json.load(f)

auth = summary["auth"]
process = summary["process"]
known_accounts = set(auth["known_accounts"])

known_processes = defaultdict(set)
for host, items in process["per_host"].items():
    for item in items:
        known_processes[host].add(item["process_name"])

known_pairs = defaultdict(set)
for host, items in process.get("parent_child_pairs", {}).items():
    for item in items:
        known_pairs[host].add((item["parent"], item["child"]))

watchlist = {
    "powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe",
    "nc", "nmap", "wget", "curl", "python3", "bash"
}

base_start = datetime.fromisoformat(
    summary["baseline_window"]["start"].replace("Z", "+00:00"))
base_end = datetime.fromisoformat(
    summary["baseline_window"]["end"].replace("Z", "+00:00"))
live_start = datetime.fromisoformat(
    summary["evaluation_window"]["start"].replace("Z", "+00:00"))
live_end = datetime.fromisoformat(
    summary["evaluation_window"]["end"].replace("Z", "+00:00"))

self_auth = []
self_process = []
live_auth = []
live_process = []

def basename(name):
    if not name:
        return ""
    if "\\" in name:
        return PureWindowsPath(name).name.lower()
    return PurePosixPath(name).name.lower()

def check_event(e, auth_out, process_out):
    label = e.get("canonical_label")
    host = e.get("hostname") or "unknown"
    user = e.get("user")

    if user and user not in known_accounts:
        auth_out.append({"anomaly_type": "unknown_account"})

    if label != "process_start":
        return

    child = e.get("process_name")
    data = e.get("event_data") or {}
    parent = (
        data.get("ParentImage")
        or data.get("parent_process_name")
        or data.get("parent_process")
    )

    if child and child not in known_processes[host]:
        process_out.append(
            {"anomaly_type": "unknown_process_for_host"})

    if parent and (parent, child) not in known_pairs[host]:
        process_out.append(
            {"anomaly_type": "unknown_parent_child"})

    if basename(child) in watchlist and child not in known_processes[host]:
        process_out.append(
            {"anomaly_type": "high_risk_process"})

with open("labeled_events.json", encoding="utf-8") as f:
    for line in f:
        e = json.loads(line)
        dt = datetime.fromisoformat(
            e["timestamp"].replace("Z", "+00:00"))

        if base_start <= dt < base_end:
            check_event(e, self_auth, self_process)
        elif live_start <= dt < live_end:
            check_event(e, live_auth, live_process)

checks = {
    "self_check_auth.json": self_auth,
    "self_check_process.json": self_process,
    "self_check_network.json": [],
    "live_check_auth.json": live_auth,
    "live_check_process.json": live_process,
    "live_check_network.json": []
}

for name, data in checks.items():
    with open(name, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

self_items = self_auth + self_process
live_items = live_auth + live_process

def breakdown(items):
    return dict(sorted(Counter(
        x["anomaly_type"] for x in items
    ).items()))

self_total = len(self_items)
live_total = len(live_items)
ratio = live_total / max(self_total, 1)

verdict = "pass" if self_total <= limit and ratio >= 3.0 else "fail"

result = {
    "acceptable_self_check_threshold": limit,
    "self_check_total": self_total,
    "live_check_total": live_total,
    "signal_to_noise_ratio": ratio,
    "self_check_breakdown": breakdown(self_items),
    "live_check_breakdown": breakdown(live_items),
    "verdict": verdict
}

with open(output, "w", encoding="utf-8") as f:
    json.dump(result, f, indent=2)

print("self-check anomalies (baseline window):", self_total)
print("live-check anomalies (evaluation win ):", live_total)
print("signal-to-noise ratio                : %.2f" % ratio)
print("verdict                              :", verdict)
print("baseline_validation.json written")

sys.exit(0 if verdict == "pass" else 1)
PY
