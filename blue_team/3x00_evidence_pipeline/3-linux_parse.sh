#!/bin/bash
set -euo pipefail

PACK="$HOME/evidence_pack_primary"
OUT="linux_events.json"
TMP="${OUT}.tmp"
trap 'rm -f "$TMP"' EXIT

python3 - "$PACK" "$TMP" <<'PY'
import json, re, sys
from pathlib import Path

pack = Path(sys.argv[1])
out = Path(sys.argv[2])
records = []

syslog_re = re.compile(
    r'^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.+)$'
)
program_re = re.compile(r'^([^\s\[]+)(?:\[(\d+)\])?:\s*(.*)$')
audit_type_re = re.compile(r'type=([A-Z_]+)')
audit_msg_re = re.compile(r'msg=audit\(([^)]+)\)')
kv_re = re.compile(r'(\w+)=(".*?"|\S+)')

def kv(text):
    return {k: v.strip('"') for k, v in kv_re.findall(text)}

def syslog_record(line):
    m = syslog_re.match(line)
    if not m:
        return {
            "timestamp_raw": "",
            "hostname": "",
            "program": "",
            "raw_message": line,
            "parsed_fields": {"unparsed": True},
            "source_origin": "evidence_pack"
        }

    ts, host, message = m.groups()
    pm = program_re.match(message)
    program, pid, message = pm.groups() if pm else ("", None, message)

    r = {
        "timestamp_raw": ts,
        "hostname": host,
        "program": program,
        "raw_message": line,
        "parsed_fields": kv(message),
        "source_origin": "evidence_pack"
    }

    if pid:
        r["pid"] = int(pid)
    if "user" in r["parsed_fields"]:
        r["user"] = r["parsed_fields"]["user"]

    return r

def audit_record(line):
    fields = kv(line)
    tm = audit_msg_re.search(line)
    typ = audit_type_re.search(line)
    group = tm.group(1) if tm else ""

    r = {
        "timestamp_raw": group,
        "hostname": fields.get("hostname", ""),
        "audit_type": typ.group(1) if typ else "",
        "raw_message": line,
        "parsed_fields": fields,
        "source_origin": "evidence_pack"
    }

    r["parsed_fields"]["audit_group_id"] = group

    if fields.get("pid", "").isdigit():
        r["pid"] = int(fields["pid"])
    if "uid" in fields:
        r["user"] = fields["uid"]

    return r

def parse_file(path):
    count = 0
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            records.append(
                audit_record(line)
                if path.name == "audit.log"
                else syslog_record(line)
            )
            count += 1
    return count

for name in ("auth.log", "audit.log", "syslog"):
    path = pack / "linux" / name
    if not path.is_file():
        raise SystemExit(f"Error: missing {path}")
    count = parse_file(path)
    print(f"parsing {name:<12} ... {count} lines -> {count} records")

student = pack / "student_telemetry" / "linux_events.json"
if not student.is_file():
    raise SystemExit(f"Error: missing {student}")

student_count = 0

with student.open("r", encoding="utf-8", errors="replace") as f:
    for line in f:
        if not line.strip():
            continue

        r = json.loads(line)
        if not isinstance(r, dict):
            raise SystemExit("Error: invalid student telemetry record")

        r["timestamp_raw"] = r.get("timestamp_raw", r.get("timestamp", ""))
        r["hostname"] = r.get("hostname", "")
        r["raw_message"] = r.get("raw_message", "")
        r["parsed_fields"] = r.get("parsed_fields", {})
        r["program"] = r.get("program", r.get("source_type", ""))
        r["source_origin"] = "student_telemetry"

        records.append(r)
        student_count += 1

print(f"appending student telemetry ... {student_count} records")

with out.open("w", encoding="utf-8") as f:
    for r in records:
        f.write(json.dumps(r, separators=(",", ":")) + "\n")

print("linux_events.json: written")
PY

mv "$TMP" "$OUT"
trap - EXIT
