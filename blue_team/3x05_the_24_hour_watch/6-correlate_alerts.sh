#!/bin/bash
set -euo pipefail

LOG="$SHIFT_WORKSPACE/alerts/triage_log.jsonl"
OUT="$SHIFT_WORKSPACE/alerts/incidents.json"
SHIFT_START="$SHIFT_WORKSPACE/runtime/shift_start.json"

if [ ! -f "$LOG" ]; then
    echo "[group] missing triage_log.jsonl" >&2
    exit 1
fi

if [ ! -f "$SHIFT_START" ]; then
    echo "[group] missing shift_start.json" >&2
    exit 1
fi

mkdir -p "$SHIFT_WORKSPACE/alerts"

python3 - "$LOG" "$SHIFT_START" "$OUT" <<'PY'
import json
import sys
from datetime import datetime, timezone, timedelta

log_file, shift_file, out_file = sys.argv[1:]

with open(shift_file, encoding="utf-8") as f:
    shift_id = json.load(f).get("shift_id", "")

tp = []
with open(log_file, encoding="utf-8") as f:
    for line in f:
        if line.strip():
            record = json.loads(line)
            if record.get("classification") == "TP":
                record["host"] = str(record.get("host") or "").lower()
                tp.append(record)

print(f"[group] TP alerts: {len(tp)}")
print("[group] grouping by temporal proximity, shared user, IOC match")

def parse_time(record):
    value = (
        record.get("timestamp")
        or record.get("event_timestamp")
        or record.get("classified_at")
    )
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None

def temporal(a, b):
    if not a["host"] or a["host"] != b["host"]:
        return False
    ta, tb = parse_time(a), parse_time(b)
    return ta is not None and tb is not None and abs(ta - tb) <= timedelta(minutes=15)

def shared_user(a, b):
    return bool(a.get("user") and a.get("user") == b.get("user"))

def shared_ioc(a, b):
    return bool(set(a.get("matches_ioc", [])) & set(b.get("matches_ioc", [])))

remaining = list(range(len(tp)))
groups = []

def build_group(seed, matcher, rule):
    group = {seed}
    changed = True
    while changed:
        changed = False
        for i in list(remaining):
            if i in group:
                continue
            if any(matcher(tp[i], tp[j]) for j in group):
                group.add(i)
                changed = True
    for i in group:
        if i in remaining:
            remaining.remove(i)
    groups.append((sorted(group), rule))

for matcher, rule in [
    (temporal, "temporal"),
    (shared_user, "shared_user"),
    (shared_ioc, "ioc_match"),
]:
    for seed in list(remaining):
        matches = [i for i in remaining if i != seed and matcher(tp[seed], tp[i])]
        if matches and seed in remaining:
            build_group(seed, matcher, rule)

for i in list(remaining):
    remaining.remove(i)
    groups.append(([i], "residual"))

today = datetime.now(timezone.utc).strftime("%Y%m%d")
generated = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

incidents = []

for n, (indexes, rule) in enumerate(groups):
    records = [tp[i] for i in indexes]
    suffix = chr(ord("A") + n)
    incident_id = f"INC-{today}-{suffix}"

    hosts = sorted({r["host"] for r in records if r["host"]})
    users = sorted({r["user"] for r in records if r.get("user")})
    iocs = sorted({
        value
        for r in records
        for value in r.get("matches_ioc", [])
    })
    alert_ids = [str(r.get("alert_id", "")) for r in records]

    times = [parse_time(r) for r in records]
    times = [t for t in times if t is not None]

    severities = {str(r.get("severity", "")).lower() for r in records}

    if iocs:
        category = "c2"
        confidence = "high"
    elif users:
        category = "credential_abuse"
        confidence = "medium"
    else:
        category = "unknown"
        confidence = "medium" if "critical" in severities or "high" in severities else "low"

    incident = {
        "incident_id": incident_id,
        "host_list": hosts,
        "user_list": users,
        "ioc_list": iocs,
        "alert_ids": alert_ids,
        "first_seen": min(times).isoformat().replace("+00:00", "Z") if times else "",
        "last_seen": max(times).isoformat().replace("+00:00", "Z") if times else "",
        "grouping_rule": rule,
        "tentative_category": category,
        "confidence": confidence
    }

    incidents.append(incident)

    host = hosts[0] if hosts else "unknown"
    print(f"[group] {incident_id}: {len(records)} alerts  host={host}  rule={rule}")

output = {
    "shift_id": shift_id,
    "generated_at": generated,
    "incidents": incidents,
    "incident_count": len(incidents),
    "unmatched_tp_count": 0
}

with open(out_file, "w", encoding="utf-8") as f:
    json.dump(output, f, indent=2)
    f.write("\n")

print(f"[group] incident_count={len(incidents)}")
print("[group] incidents.json written")

if len(incidents) < 3:
    sys.exit(1)
PY
