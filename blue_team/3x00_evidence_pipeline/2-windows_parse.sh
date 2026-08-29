#!/bin/bash

set -euo pipefail

PACK="$HOME/evidence_pack_primary"
OUT="windows_events.json"
TMP="${OUT}.tmp"

trap 'rm -f "$TMP"' EXIT

python3 - "$PACK" "$TMP" <<'PY'
import json
import sys
from pathlib import Path
from datetime import datetime, timezone

pack = Path(sys.argv[1])
out = Path(sys.argv[2])

required = (
    "timestamp_raw",
    "hostname",
    "event_id",
    "channel",
    "provider",
    "raw_message",
    "event_data",
    "source_origin",
)

records = []
counts = {}


def parse_time(value):
    if not value:
        return None

    text = str(value).strip()

    if text.endswith("Z"):
        text = text[:-1] + "+00:00"

    if len(text) >= 5 and (
        text[-5] in "+-" and text[-2:].isdigit()
    ):
        text = text[:-2] + ":" + text[-2:]

    try:
        dt = datetime.fromisoformat(text)

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        return dt.astimezone(timezone.utc)
    except ValueError:
        return None


def read_evidence(path):
    count = 0

    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            if not line.strip():
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError as e:
                raise ValueError(
                    f"{path.name}:{line_no}: invalid JSON"
                ) from e

            if not isinstance(record, dict):
                raise ValueError(
                    f"{path.name}:{line_no}: record is not an object"
                )

            for field in required:
                if field not in record:
                    raise ValueError(
                        f"{path.name}:{line_no}: missing {field}"
                    )

            if record["source_origin"] != "evidence_pack":
                raise ValueError(
                    f"{path.name}:{line_no}: "
                    "source_origin must be evidence_pack"
                )

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
        except json.JSONDecodeError as e:
            raise ValueError(
                f"student telemetry:{line_no}: invalid JSON"
            ) from e

        if not isinstance(original, dict):
            raise ValueError(
                f"student telemetry:{line_no}: record is not an object"
            )

        record = dict(original)

        record["timestamp_raw"] = record.get(
            "timestamp_raw",
            record.get("timestamp")
        )

        record["provider"] = record.get(
            "provider",
            record.get("source_type", "unknown")
        )

        record["channel"] = record.get(
            "channel",
            record.get("event_category", "unknown")
        )

        record["raw_message"] = record.get(
            "raw_message",
            record.get("command_line", "")
        )

        record["event_data"] = record.get(
            "event_data",
            {
                key: value
                for key, value in original.items()
                if key not in {
                    "timestamp",
                    "timestamp_raw",
                    "hostname",
                    "source_type",
                    "event_category",
                    "event_id",
                    "raw_message",
                    "command_line",
                    "source_origin",
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

        for field in required:
            if field not in record:
                raise ValueError(
                    f"student telemetry:{line_no}: "
                    f"missing normalized field {field}"
                )

        records.append(record)
        student_count += 1


counts["student telemetry"] = student_count


# Stable deterministic ordering.
# Original order is preserved when timestamps are equal.
records.sort(
    key=lambda record: (
        parse_time(record.get("timestamp_raw"))
        is None,
        parse_time(record.get("timestamp_raw"))
        or datetime.max.replace(tzinfo=timezone.utc),
    )
)


with out.open("w", encoding="utf-8") as f:
    for record in records:
        f.write(
            json.dumps(
                record,
                separators=(",", ":"),
                ensure_ascii=False
            )
            + "\n"
        )


for name in ("security.json", "sysmon.json", "powershell.json"):
    print(
        f"reading {name:<18} ... "
        f"{counts[name]} records"
    )

print(
    f"appending student telemetry ... "
    f"{counts['student telemetry']} records"
)

print(
    f"windows_events.json: "
    f"{len(records)} records"
)
PY

mv "$TMP" "$OUT"
trap - EXIT
