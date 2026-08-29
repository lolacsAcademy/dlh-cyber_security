#!/bin/bash
set -euo pipefail

PACK="$HOME/evidence_pack_primary"
OUT="$(pwd)/linux_events.json"
TMP="$(mktemp)"

trap 'rm -f "$TMP"' EXIT

python3 - "$PACK" "$TMP" <<'PY'
import json
import re
import shlex
import sys
from pathlib import Path

pack = Path(sys.argv[1])
tmp = Path(sys.argv[2])
records = []

syslog_re = re.compile(
    r'^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.+)$'
)
program_re = re.compile(
    r'^([^\s\[]+)(?:\[(\d+)\])?:\s*(.*)$'
)
audit_type_re = re.compile(r'\btype=([A-Z_]+)')
audit_msg_re = re.compile(r'\bmsg=audit\(([^)]+)\)')


def key_values(text):
    result = {}

    try:
        tokens = shlex.split(text, posix=True)
    except ValueError:
        tokens = text.split()

    for token in tokens:
        if "=" in token:
            key, value = token.split("=", 1)
            if key and re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', key):
                result[key] = value

    return result


def syslog_record(line, filename, line_no):
    match = syslog_re.match(line)

    if match:
        timestamp, hostname, message = match.groups()
    else:
        timestamp = ""
        hostname = ""
        message = line

    program = ""
    pid = None

    program_match = program_re.match(message)

    if program_match:
        program, pid_text, message = program_match.groups()
        if pid_text:
            pid = int(pid_text)

    parsed = {
        "message": message,
        "key_values": key_values(message)
    }

    record = {
        "timestamp_raw": timestamp,
        "hostname": hostname,
        "program": program,
        "raw_message": line,
        "parsed_fields": parsed,
        "source_file": filename,
        "source_line": line_no,
        "source_origin": "evidence_pack"
    }

    if pid is not None:
        record["pid"] = pid

    return record


def audit_record(line, filename, line_no):
    fields = key_values(line)

    type_match = audit_type_re.search(line)
    msg_match = audit_msg_re.search(line)

    group_id = msg_match.group(1) if msg_match else ""

    record = {
        "timestamp_raw": group_id,
        "hostname": fields.get("hostname", ""),
        "audit_type": (
            type_match.group(1)
            if type_match
            else ""
        ),
        "raw_message": line,
        "parsed_fields": {
            "key_values": fields,
            "audit_group_id": group_id
        },
        "source_file": filename,
        "source_line": line_no,
        "source_origin": "evidence_pack"
    }

    if fields.get("pid", "").isdigit():
        record["pid"] = int(fields["pid"])

    return record


def parse_file(path, mixed=False):
    count = 0

    with path.open(
        "r",
        encoding="utf-8",
        errors="replace"
    ) as handle:

        for line_no, line in enumerate(handle, 1):
            line = line.rstrip("\n")

            if not line:
                continue

            if mixed and (
                audit_type_re.search(line)
                and audit_msg_re.search(line)
            ):
                record = audit_record(
                    line,
                    path.name,
                    line_no
                )
            elif path.name == "audit.log":
                record = audit_record(
                    line,
                    path.name,
                    line_no
                )
            else:
                record = syslog_record(
                    line,
                    path.name,
                    line_no
                )

            records.append(record)
            count += 1

    return count


for filename in ("auth.log", "audit.log", "syslog"):
    path = pack / "linux" / filename

    if not path.is_file():
        raise SystemExit(f"Error: missing {path}")

    count = parse_file(
        path,
        mixed=(filename == "syslog")
    )

    print(
        f"parsing {filename:<12} ... "
        f"{count} lines -> {count} records"
    )


student_path = (
    pack / "student_telemetry" / "linux_events.json"
)

if not student_path.is_file():
    raise SystemExit(
        f"Error: missing {student_path}"
    )

student_count = 0

with student_path.open(
    "r",
    encoding="utf-8",
    errors="replace"
) as handle:

    for line_no, line in enumerate(handle, 1):
        if not line.strip():
            continue

        original = json.loads(line)

        if not isinstance(original, dict):
            raise SystemExit(
                f"Error: invalid student record "
                f"at line {line_no}"
            )

        # Preserve the original telemetry object.
        record = dict(original)

        # Add common fields only when absent.
        if "timestamp_raw" not in record:
            record["timestamp_raw"] = original.get(
                "timestamp",
                ""
            )

        if "hostname" not in record:
            record["hostname"] = ""

        if "program" not in record:
            record["program"] = original.get(
                "source_type",
                ""
            )

        if "raw_message" not in record:
            record["raw_message"] = ""

        if "parsed_fields" not in record:
            record["parsed_fields"] = {}

        if not isinstance(
            record["parsed_fields"],
            dict
        ):
            record["parsed_fields"] = {
                "original_value":
                    record["parsed_fields"]
            }

        record["source_file"] = (
            "student_telemetry/linux_events.json"
        )
        record["source_line"] = line_no

        # Required student provenance tag.
        record["source_origin"] = (
            "student_telemetry"
        )

        records.append(record)
        student_count += 1


print(
    f"appending student telemetry ... "
    f"{student_count} records"
)

with tmp.open(
    "w",
    encoding="utf-8"
) as handle:

    for record in records:
        handle.write(
            json.dumps(
                record,
                separators=(",", ":"),
                ensure_ascii=False
            )
            + "\n"
        )

print("linux_events.json: written")
PY

mv "$TMP" "$OUT"
trap - EXIT
