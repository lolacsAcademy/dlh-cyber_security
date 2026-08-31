#!/bin/bash

INPUT="labeled_events.json"
OUTPUT="baseline_auth.json"
DAYS="${BASELINE_DAYS:-7}"

python3 - "$INPUT" "$OUTPUT" "$DAYS" <<'PY'
import json
import sys
from datetime import datetime, timedelta
from collections import defaultdict

inp, out, days = sys.argv[1], sys.argv[2], int(sys.argv[3])

labels = [
    "login_success", "login_failure", "logout",
    "account_lockout", "privilege_escalation"
]
auth_labels = set(labels)

hosts = defaultdict(lambda: {x: 0 for x in labels})
users = defaultdict(lambda: {"login_success": 0, "login_failure": 0})
business = [0, 0]
offhours = [0, 0]
failures = defaultdict(int)

start = None
end = None

with open(inp, encoding="utf-8") as f:
    for line in f:
        e = json.loads(line)
        dt = datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00"))

        if start is None:
            start = dt
            end = start + timedelta(days=days)

        if dt < start or dt >= end:
            continue

        label = e.get("canonical_label")
        if label not in auth_labels:
            continue

        host = e.get("hostname") or "unknown"
        user = e.get("user")

        hosts[host][label] += 1

        if user:
            users[user]
            if label in ("login_success", "login_failure"):
                users[user][label] += 1

        if label in ("login_success", "login_failure"):
            target = business if 6 <= dt.hour < 18 else offhours
            target[0 if label == "login_success" else 1] += 1

        if label == "login_failure" and e.get("src_ip"):
            hour = dt.strftime("%Y-%m-%dT%H")
            failures[(e["src_ip"], hour)] += 1

hours = days * 12

result = {
    "window": {
        "start": start.isoformat().replace("+00:00", "Z"),
        "end": end.isoformat().replace("+00:00", "Z")
    },
    "per_host": dict(hosts),
    "per_user": [
        {"user": u, **counts} for u, counts in sorted(users.items())
    ],
    "known_accounts": sorted(users),
    "business_hours_avg": {
        "success": business[0] / hours,
        "failure": business[1] / hours
    },
    "offhours_avg": {
        "success": offhours[0] / hours,
        "failure": offhours[1] / hours
    },
    "max_failures_1h_window": max(failures.values(), default=0)
}

with open(out, "w", encoding="utf-8") as f:
    json.dump(result, f, indent=2)

print("baseline window :", result["window"]["start"], "->", result["window"]["end"])
print("hosts           :", len(hosts))
print("known accounts  :", len(users))
print("business hours  : %.2f success/h  |  %.2f failure/h" %
      (result["business_hours_avg"]["success"],
       result["business_hours_avg"]["failure"]))
print("off hours       : %.2f success/h  |  %.2f failure/h" %
      (result["offhours_avg"]["success"],
       result["offhours_avg"]["failure"]))
print("max 1h src_ip failures :", result["max_failures_1h_window"])
print("baseline_auth.json written")
PY
