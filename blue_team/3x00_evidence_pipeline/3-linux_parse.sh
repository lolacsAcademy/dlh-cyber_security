#!/bin/bash
set -euo pipefail

PACK="$HOME/evidence_pack_primary"
OUT="$(pwd)/linux_events.json"
TMP="$(mktemp)"

trap 'rm -f "$TMP"' EXIT

python3 - "$PACK" "$TMP" <<'PY'
import json
import re
import sys
from pathlib import Path

pack = Path(sys.argv[1])
tmp = Path(sys.argv[2])
records = []

syslog_re = re.compile(
    r'^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.+)$'
)
program_re = re.compile(r'^([^\s\[]+)(?:\[(\d+)\])?:\s*(.*)$')
audit_type_re = re.compile(r'type=([A-Z_]+)')
audit_msg_re = re.compile(r'msg=audit\(([^)]+)\)')
kv_re = re.compile(r'(\w+)=(".*?"|\S+)')

def parse_kv(text):
    return {k: v.strip('"') for k, v in kv_re.findall(text)}

def syslog_record(line, filename, line_no):
    m = syslog_re.match(line)

    if not m:
        return {
            "timestamp_raw": "",
            "hostname": "",
            "program": "",
            "raw_message": line,
            "parsed_fields": {"unparsed": True},
            "source_file": filename,
            "source_line": line_no,
            "source_origin": "evidence_pack"
        }

    timestamp, hostname, message = m.groups()
    pm = program_re.match(message)

    program = ""
    pid = None

    if pm:
        program, pid, message = pm.groups()

    parsed = parse_kv(message)

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

    if pid:
        record["pid"] = int(pid)

    if "user" in parsed:
        record["user"] = parsed["user"]

    return record

def audit_record(line, filename, line_no):
    parsed = parse_kv(line)
    tm = audit_msg_re.search(line)
    typ = audit_type_re.search(line)

    group_id = tm.group(1) if tm else ""

    record = {
        "timestamp_raw": group_id,
        "hostname": parsed.get("hostname", ""),
        "audit_type": typ.group(1) if typ else "",
        "raw_message": line,
        "parsed_fields": parsed,
        "source_file": filename,
        "source_line": line_no,
        "source_origin": "evidence_pack"
    }

    record["parsed_fields"]["audit_group_id"] = group_id

    if parsed.get("pid", "").isdigit():
        record["pid"] = int(parsed["pid"])

    if "uid" in parsed:
        record["user"] = parsed["uid"]

    return record

def parse_standard(path):
    count = 0

    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, 1):
            line = line.rstrip("\n")

            if not line:
                continue

            records.append(
                syslog_record(line, path.name, line_no)
            )
            count += 1

    return count

def parse_mixed_syslog(path):
    count = 0

    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, 1):
            line = line.rstrip("\n")

            if not line:
                continue

            if audit_type_re.search(line) and audit_msg_re.search(line):
                records.append(
                    audit_record(line, path.name, line_no)
                )
            else:
                records.append(
                    syslog_record(line, path.name, line_no)
                )

            count += 1

    return count

def parse_audit(path):
    lines = 0
    groups = []
    current = None

    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, 1):
            line = line.rstrip("\n")

            if not line:
                continue

            lines += 1
            record = audit_record(line, path.name, line_no)
            group = record["parsed_fields"]["audit_group_id"]

            if current is None:
                current = record
                continue

            current_group = current["parsed_fields"]["audit_group_id"]

            if group and group == current_group:
                current["raw_message"] += "\n" + line
                current["parsed_fields"].update(
                    record["parsed_fields"]
                )
            else:
                groups.append(current)
                current = record

        if current is not None:
            groups.append(current)

    records.extend(groups)
    return lines, len(groups)

for name in ("auth.log", "audit.log", "syslog"):
    path = pack / "linux" / name

    if not path.is_file():
        raise SystemExit(f"Error: missing {path}")

    if name == "audit.log":
        lines, count = parse_audit(path)
        print(
            f"parsing {name:<12} ... "
            f"{lines} lines -> {count} records"
        )
    elif name == "syslog":
        count = parse_mixed_syslog(path)
        print(
            f"parsing {name:<12} ... "
            f"{count} lines -> {count} records"
        )
    else:
        count = parse_standard(path)
        print(
            f"parsing {name:<12} ... "
            f"{count} lines -> {count} records"
        )

student = pack / "student_telemetry" / "linux_events.json"

if not student.is_file():
    raise SystemExit(f"Error: missing {student}")

student_count = 0

with student.open("r", encoding="utf-8", errors="replace") as f:
    for line_no, line in enumerate(f, 1):
        if not line.strip():
            continue

        record = json.loads(line)

        if not isinstance(record, dict):
            raise SystemExit(
                f"Error: invalid student record at line {line_no}"
            )

        record["timestamp_raw"] = record.get(
            "timestamp_raw",
            record.get("timestamp", "")
        )

        record["hostname"] = record.get("hostname", "")

        record["program"] = record.get(
            "program",
            record.get("source_type", "")
        )

        record["raw_message"] = record.get(
            "raw_message",
            ""
        )

        record["parsed_fields"] = record.get(
            "parsed_fields",
            {}
        )

        record["source_file"] = (
            "student_telemetry/linux_events.json"
        )
        record["source_line"] = line_no
        record["source_origin"] = "student_telemetry"

        records.append(record)
        student_count += 1

print(
    f"appending student telemetry ... "
    f"{student_count} records"
)

with tmp.open("w", encoding="utf-8") as f:
    for record in records:
        f.write(
            json.dumps(
                record,
                separators=(",", ":"),
                ensure_ascii=False
            ) + "\n"
        )
PY

mv "$TMP" "$OUT"
trap - EXIT
