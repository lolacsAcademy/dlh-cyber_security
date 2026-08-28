#!/bin/bash
set -euo pipefail

python3 <<'PY'
import json
import os
from datetime import datetime, timezone, timedelta

INPUT = "normalized_events.json"
SECURITY = os.path.expanduser(
    "~/evidence_pack_primary/windows/security.json"
)

def parse_ts(v):
    if not v:
        return None
    try:
        d = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return d.astimezone(timezone.utc)
    except ValueError:
        pass

    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
    ):
        try:
            return datetime.strptime(str(v), fmt).replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            pass
    return None

# Build exact source identities for the planted security records.
security_keys = {}
if os.path.exists(SECURITY):
    with open(SECURITY, encoding="utf-8", errors="replace") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                s = json.loads(line)
                key = (
                    s.get("hostname"),
                    s.get("event_id"),
                    s.get("raw_message"),
                )
                security_keys.setdefault(key, []).append(
                    parse_ts(s.get("timestamp_raw"))
                )
            except Exception:
                continue

seen = set()
corrections = []
unrepairable = []

malformed = repaired = dropped = duplicates = 0
hostfix = enc_detected = enc_repaired = tzflag = 0
record_id = 0

with open(INPUT, encoding="utf-8", errors="replace") as src, \
     open("cleaned_events.json", "w", encoding="utf-8") as out:

    for line in src:
        if not line.strip():
            continue

        record_id += 1
        rid = f"record-{record_id}"

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
                "reason": "Timestamp could not be repaired"
            })
            continue

        fixed_ts = dt.isoformat().replace("+00:00", "Z")

        if str(original_ts) != fixed_ts:
            repaired += 1
            corrections.append({
                "defect_type": "malformed_timestamp",
                "original_value": original_ts,
                "corrected_value": fixed_ts,
                "record_id": rid,
                "reason": "Timestamp normalized to ISO 8601 UTC"
            })

        r["timestamp"] = fixed_ts

        host = r.get("hostname")
        if isinstance(host, str) and host != host.lower():
            hostfix += 1
            corrections.append({
                "defect_type": "hostname_case",
                "original_value": host,
                "corrected_value": host.lower(),
                "record_id": rid,
                "reason": "Hostname normalized to lowercase"
            })
            r["hostname"] = host.lower()

        msg = r.get("raw_message")
        if isinstance(msg, str) and any(
            x in msg for x in ("�", "Ã", "Â", "â€")
        ):
            enc_detected += 1
            try:
                fixed = msg.encode("latin-1").decode("utf-8")
            except (UnicodeEncodeError, UnicodeDecodeError):
                fixed = msg.replace("�", "?")

            if fixed != msg:
                enc_repaired += 1
                r["raw_message"] = fixed
                corrections.append({
                    "defect_type": "encoding_error",
                    "original_value": msg,
                    "corrected_value": fixed,
                    "record_id": rid,
                    "reason": "Latin-1/UTF-8 encoding defect repaired"
                })

        key = (
            r.get("timestamp"),
            r.get("hostname"),
            r.get("source_type"),
            r.get("raw_message")
        )

        if key in seen:
            duplicates += 1
            corrections.append({
                "defect_type": "duplicate",
                "original_value": {
                    "timestamp": r.get("timestamp"),
                    "hostname": r.get("hostname"),
                    "source_type": r.get("source_type"),
                    "raw_message": r.get("raw_message")
                },
                "corrected_value": None,
                "record_id": rid,
                "reason": "Duplicate removed; first occurrence retained"
            })
            continue

        seen.add(key)

        # Compare Security records against the original security evidence.
        # A source timestamp exactly 8 hours from the normalized timestamp
        # is a planted timezone inconsistency.
        if r.get("source_type") == "windows_json":
            skey = (
                r.get("hostname"),
                r.get("event_id"),
                r.get("raw_message")
            )

            for source_dt in security_keys.get(skey, []):
                if source_dt is not None:
                    delta = abs((dt - source_dt).total_seconds())
                    if delta == 8 * 3600:
                        tzflag += 1
                        corrections.append({
                            "defect_type": "suspected_wrong_tz",
                            "original_value": fixed_ts,
                            "corrected_value": fixed_ts,
                            "record_id": rid,
                            "reason": "Security event differs from original evidence timestamp by +8 hours"
                        })
                        break

        out.write(
            json.dumps(
                r,
                separators=(",", ":"),
                ensure_ascii=False
            ) + "\n"
        )

with open("cleaning_log.json", "w", encoding="utf-8") as f:
    json.dump({
        "task": "Task 6 - Dirty Data Handling",
        "corrections": corrections,
        "unrepairable": unrepairable
    }, f, separators=(",", ":"))

print(
    f"malformed timestamps   : detected {malformed} "
    f"repaired {repaired} dropped {dropped}"
)
print(f"duplicates             : detected {duplicates} removed")
print(f"hostname case          : normalized {hostfix}")
print(
    f"encoding errors        : detected {enc_detected} "
    f"repaired {enc_repaired}"
)
print(f"suspected wrong tz     : flagged {tzflag}")
print("cleaned_events.json    written")
print("cleaning_log.json      written")
PY
