#!/bin/bash

set -euo pipefail

PACK="$HOME/evidence_pack_primary"
OUT="windows_events.json"
TMP=$(mktemp)

trap 'rm -f "$TMP"' EXIT

python3 - "$PACK" "$TMP" <<'PY'
import json
import sys
from pathlib import Path
from datetime import datetime, timezone

pack = Path(sys.argv[1])
out = Path(sys.argv[2])

required = [
    "timestamp_raw", "hostname", "event_id", "channel",
    "provider", "raw_message", "event_data", "source_origin"
]

records = []
counts = {}

def read_evidence(path):
    count = 0

    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            if not line.strip():
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                raise ValueError(f"{path.name}:{line_no}: invalid JSON")

            if not isinstance(record, dict):
                raise ValueError(f"{path.name}:{line_no}: not an object")

            for field in required[:-1]:
                if field not in record:
                    raise ValueError(
                        f"{path.name}:{line_no}: missing {field}"
                    )

            record["source_origin"] = "evidence_pack"
            records.append(record)
            count += 1

    return count

for name in ("security.json", "sysmon.json", "powershell.json"):
    path = pack / "windows" / name

    if not path.is_file():
        raise FileNotFoundError(f"missing {path}")

    counts[name] = read_evidence(path)

student = pack / "student_telemetry" / "windows_events.json"

if not student.is_file():
    raise FileNotFoundError(f"missing {student}")

student_count = 0

with student.open("r", encoding="utf-8") as f:
    for line_no, line in enumerate(f, 1):
        if not line.strip():
            continue

        try:
            original = json.loads(line)
        except json.JSONDecodeError:
            raise ValueError(
                f"student telemetry:{line_no}: invalid JSON"
            )

        if not isinstance(original, dict):
            raise ValueError(
                f"student telemetry:{line_no}: not an object"
            )

        record = dict(original)

        record["timestamp_raw"] = record.get(
            "timestamp_raw", record.get("timestamp")
        )

        record["provider"] = record.get(
            "provider", record.get("source_type", "unknown")
        )

        record["channel"] = record.get(
            "channel", record.get("event_category", "unknown")
        )

        record["raw_message"] = record.get(
            "raw_message", record.get("command_line", "")
        )

        record["event_data"] = record.get(
            "event_data",
            {
                k: v for k, v in original.items()
                if k not in {
                    "timestamp", "hostname", "source_type",
                    "event_category", "event_id", "raw_message"
                }
            }
        )

        if not record.get("hostname"):
            raise ValueError(
                f"student telemetry:{line_no}: missing hostname"
            )

        if "event_id" not in record:
            raise ValueError(
                f"student telemetry:{line_no}: missing event_id"
            )

        record["source_origin"] = "student_telemetry"

        records.append(record)
        student_count += 1

counts["student telemetry"] = student_count

def sort_key(record):
    value = record.get("timestamp_raw")

    if not value:
        return datetime.max.replace(tzinfo=timezone.utc)

    try:
        text = str(value).replace("Z", "+00:00")
        dt = datetime.fromisoformat(text)

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        return dt.astimezone(timezone.utc)

    except ValueError:
        return datetime.max.replace(tzinfo=timezone.utc)

records.sort(key=sort_key)

with out.open("w", encoding="utf-8") as f:
    for record in records:
        f.write(json.dumps(record, separators=(",", ":")) + "\n")

for name in ("security.json", "sysmon.json", "powershell.json"):
    print(f"reading {name:<18} ... {counts[name]} records")

print(
    f"appending student telemetry ... "
    f"{counts['student telemetry']} records"
)

print(f"windows_events.json: {len(records)} records")
PY
