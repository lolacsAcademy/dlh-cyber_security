#!/bin/bash

SUMMARY="baseline_summary.json"
EVENTS="labeled_events.json"
OUTPUT="anomalies_auth.json"

python3 - "$SUMMARY" "$EVENTS" "$OUTPUT" <<'PY'
import json
import sys
from datetime import datetime
from collections import defaultdict

summary_file, events_file, output = sys.argv[1:4]

with open(summary_file, encoding="utf-8") as f:
    summary = json.load(f)

auth = summary["auth"]
known = set(auth["known_accounts"])
per_host = auth["per_host"]

start_text = summary["evaluation_window"]["start"]
end_text = summary["evaluation_window"]["end"]

start = datetime.fromisoformat(start_text.replace("Z", "+00:00"))
end = datetime.fromisoformat(end_text.replace("Z", "+00:00"))

multiplier = summary["thresholds"]["failure_rate_multiplier"]["value"]
baseline_max = auth["max_failures_1h_window"]
threshold = baseline_max * multiplier

baseline_start = datetime.fromisoformat(
    summary["baseline_window"]["start"].replace("Z", "+00:00")
)
baseline_end = datetime.fromisoformat(
    summary["baseline_window"]["end"].replace("Z", "+00:00")
)

baseline_hours = defaultdict(set)
failures = defaultdict(list)
privilege = defaultdict(list)
eval_events = []

with open(events_file, encoding="utf-8") as f:
    for line in f:
        e = json.loads(line)
        dt = datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00"))
        label = e.get("canonical_label")
        user = e.get("user")

        if baseline_start <= dt < baseline_end:
            if label == "login_success" and user:
                baseline_hours[user].add("business" if 6 <= dt.hour < 18 else "off")

        if start <= dt < end:
            eval_events.append(e)

anomalies = []

def add(e, kind, baseline, observed, severity):
    anomalies.append({
        "timestamp": e["timestamp"],
        "host": e.get("hostname"),
        "user": e.get("user"),
        "src_ip": e.get("src_ip"),
        "anomaly_type": kind,
        "baseline_value": baseline,
        "observed_value": observed,
        "severity": severity,
        "event_refs": [e.get("event_id")]
    })

for e in eval_events:
    dt = datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00"))
    label = e.get("canonical_label")
    user = e.get("user")
    host = e.get("hostname") or "unknown"

    if user and user not in known:
        add(e, "unknown_account", "known_accounts", user, "high")

    if label == "login_failure" and e.get("src_ip"):
        hour = dt.strftime("%Y-%m-%dT%H")
        failures[(e["src_ip"], hour)].append(e)

    if label == "login_success" and user and (dt.hour < 6 or dt.hour >= 18):
        if baseline_hours.get(user) == {"business"}:
            add(e, "offhours_login",
                "business-hours-only", "off-hours login", "medium")

    if label == "privilege_escalation":
        privilege[host].append(e)

for events in failures.values():
    if len(events) > threshold:
        add(events[0], "failure_rate_burst",
            threshold, len(events), "high")

for host, events in privilege.items():
    baseline_count = per_host.get(host, {}).get("privilege_escalation", 0)
    if baseline_count == 0 and len(events) > 0:
        add(events[0], "privilege_escalation_surge",
            0, len(events), "high")

anomalies.sort(key=lambda x: x["timestamp"])

with open(output, "w", encoding="utf-8") as f:
    json.dump(anomalies, f, indent=2)

counts = defaultdict(int)
for item in anomalies:
    counts[item["anomaly_type"]] += 1

print("evaluation window  :", start_text, "->", end_text)
print("unknown_account           :", counts["unknown_account"])
print("failure_rate_burst        :", counts["failure_rate_burst"])
print("offhours_login            :", counts["offhours_login"])
print("privilege_escalation_surge:", counts["privilege_escalation_surge"])
print("total anomalies           :", len(anomalies))
print("anomalies_auth.json written")
PY
