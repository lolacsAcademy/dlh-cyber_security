#!/bin/bash
set -euo pipefail

python3 <<'PY'
import json
from datetime import datetime, timezone, timedelta

INPUT = "normalized_events.json"

def parse_ts(value):
    if not value:
        return None
    try:
        d = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return d.astimezone(timezone.utc)
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S",
                    "%Y/%m/%d %H:%M:%S",
                    "%m/%d/%Y %I:%M:%S %p"):
            try:
                return datetime.strptime(str(value), fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                pass
    return None

seen = set()
log = []
unrepairable = []
count = 0
malformed = repaired = dropped = duplicates = hostfix = 0
enc_detected = enc_repaired = tzflag = 0

# Evidence-pack expected range: derive from valid records without
# loading the entire dataset into memory.
first = last = None

with open(INPUT, encoding="utf-8", errors="replace") as src:
    for line in src:
        if not line.strip():
            continue
        try:
            r = json.loads(line)
            d = parse_ts(r.get("timestamp"))
            if d:
                if first is None or d < first:
                    first = d
                if last is None or d > last:
                    last = d
        except Exception:
            pass

# Second pass: clean records one at a time.
with open(INPUT, encoding="utf-8", errors="replace") as src, \
     open("cleaned_events.json", "w", encoding="utf-8") as out:

    for line in src:
        if not line.strip():
            continue

        count += 1
        rid = f"record-{count}"

        try:
            r = json.loads(line)
        except Exception:
            malformed += 1
            dropped += 1
            unrepairable.append({
                "defect_type": "malformed_timestamp",
                "original_value": None,
                "corrected_value": None,
                "record_id": rid,
                "reason": "Invalid JSON record"
            })
            continue

        original_ts = r.get("timestamp")
        dt = parse_ts(original_ts)

        if dt is None:
            malformed += 1
            dropped += 1
            unrepairable.append({
                "defect_type": "malformed_timestamp",
                "original_value": original_ts,
                "corrected_value": None,
                "record_id": rid,
                "reason": "Timestamp failed ISO 8601 and fallback parsing"
            })
            continue

        fixed_ts = dt.isoformat().replace("+00:00", "Z")

        if str(original_ts) != fixed_ts:
            repaired += 1
            log.append({
                "defect_type": "malformed_timestamp",
                "original_value": original_ts,
                "corrected_value": fixed_ts,
                "record_id": rid,
                "reason": "Timestamp repaired to ISO 8601 UTC"
            })

        r["timestamp"] = fixed_ts

        # Hostname case normalization.
        host = r.get("hostname")
        if isinstance(host, str) and host != host.lower():
            hostfix += 1
            log.append({
                "defect_type": "hostname_case",
                "original_value": host,
                "corrected_value": host.lower(),
                "record_id": rid,
                "reason": "Hostname normalized to lowercase"
            })
            r["hostname"] = host.lower()

        # Encoding repair.
        msg = r.get("raw_message")
        if isinstance(msg, str) and any(x in msg for x in ("�", "Ã", "Â", "â€")):
            enc_detected += 1
            try:
                fixed_msg = msg.encode("latin-1").decode("utf-8")
            except (UnicodeEncodeError, UnicodeDecodeError):
                fixed_msg = msg.replace("�", "?")

            if fixed_msg != msg:
                enc_repaired += 1
                r["raw_message"] = fixed_msg
                log.append({
                    "defect_type": "encoding_error",
                    "original_value": msg,
                    "corrected_value": fixed_msg,
                    "record_id": rid,
                    "reason": "Latin-1/UTF-8 encoding defect repaired"
                })

        # Duplicate detection AFTER corrections.
        key = (
            r.get("timestamp"),
            r.get("hostname"),
            r.get("source_type"),
            r.get("raw_message")
        )

        if key in seen:
            duplicates += 1
            log.append({
                "defect_type": "duplicate",
                "original_value": key,
                "corrected_value": None,
                "record_id": rid,
                "reason": "Duplicate after normalization and repairs"
            })
            continue

        seen.add(key)

        # Expected evidence range with required 12-hour tolerance.
        # Records outside that range are flagged, not silently changed.
        if first and last:
            if dt < first - timedelta(hours=12) or dt > last + timedelta(hours=12):
                tzflag += 1
                log.append({
                    "defect_type": "suspected_wrong_tz",
                    "original_value": fixed_ts,
                    "corrected_value": fixed_ts,
                    "record_id": rid,
                    "reason": "Timestamp falls more than 12 hours outside the evidence-pack date range"
                })

        out.write(json.dumps(r, separators=(",", ":"), ensure_ascii=False) + "\n")

with open("cleaning_log.json", "w", encoding="utf-8") as f:
    json.dump({
        "corrections": log,
        "unrepairable": unrepairable
    }, f, separators=(",", ":"))

print(f"malformed timestamps   : detected {malformed} repaired {repaired} dropped {dropped}")
print(f"duplicates             : detected {duplicates} removed")
print(f"hostname case          : normalized {hostfix}")
print(f"encoding errors        : detected {enc_detected} repaired {enc_repaired}")
print(f"suspected wrong tz     : flagged {tzflag}")
print("cleaned_events.json    written")
print("cleaning_log.json      written")
PY
