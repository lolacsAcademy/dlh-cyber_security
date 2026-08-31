#!/bin/bash

AUTH="baseline_auth.json"
PROCESS="baseline_process.json"
OUTPUT="baseline_summary.json"

python3 - "$AUTH" "$PROCESS" "$OUTPUT" <<'PY'
import json
import sys
from datetime import datetime, timezone, timedelta

auth_file, process_file, output = sys.argv[1:4]

with open(auth_file, encoding="utf-8") as f:
    auth = json.load(f)

with open(process_file, encoding="utf-8") as f:
    process = json.load(f)

start_text = auth["window"]["start"]
end_text = auth["window"]["end"]

start = datetime.fromisoformat(start_text.replace("Z", "+00:00"))
end = datetime.fromisoformat(end_text.replace("Z", "+00:00"))

duration_days = (end - start).total_seconds() / 86400

evaluation_start = end
evaluation_end = evaluation_start + timedelta(hours=24)

hosts = sorted(
    set(auth.get("per_host", {}).keys())
    | set(process.get("per_host", {}).keys())
)

result = {
    "version": "1.0",
    "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "baseline_window": {
        "start": start_text,
        "end": end_text,
        "duration_days": duration_days
    },
    "evaluation_window": {
        "start": evaluation_start.isoformat().replace("+00:00", "Z"),
        "end": evaluation_end.isoformat().replace("+00:00", "Z"),
        "duration_hours": 24
    },
    "host_inventory": hosts,
    "auth": auth,
    "process": process,
    "network": {},
    "file": {},
    "temporal": {},
    "thresholds": {
        "failure_rate_multiplier": {
            "value": 3,
            "comment": "Three times the authentication baseline rate flags a significant deviation."
        },
        "unknown_process_penalty": {
            "value": 5,
            "comment": "Unseen per-host processes receive a higher anomaly weight."
        },
        "unknown_port_penalty": {
            "value": 4,
            "comment": "Reserved for network anomalies; network baseline task is not present."
        }
    }
}

with open(output, "w", encoding="utf-8") as f:
    json.dump(result, f, indent=2)

print("version           : 1.0")
print("baseline window   :", start_text, "->", end_text,
      "(" + str(int(duration_days)) + " days)")
print("evaluation window :",
      result["evaluation_window"]["start"], "->",
      result["evaluation_window"]["end"], "(24h)")
print("hosts             :", len(hosts))
print("sections included : auth, process, network, file, temporal, thresholds")
print("baseline_summary.json written")
PY
