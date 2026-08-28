#!/bin/bash
set -euo pipefail

python3 <<'PY'
import json
import hashlib
from datetime import datetime, timezone

seen = set()
log = []

def parse_time(value):
    if not value:
        return None

    text = str(value).replace("Z", "+00:00")

    try:
        d = datetime.fromisoformat(text)
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return d.astimezone(timezone.utc)
    except ValueError:
        pass

    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
        "%b %d %H:%M:%S"
    ):
        try:
            return datetime.strptime(
                str(value), fmt
            ).replace(tzinfo=timezone.utc)
        except ValueError:
            pass

    return None

with open("cleaned_events.json", "w", encoding="utf-8") as out:
    with open(
        "normalized_events.json",
        encoding="utf-8",
        errors="replace"
    ) as src:

        for number, line in enumerate(src, 1):
            if not line.strip():
                continue

            rid = f"record-{number}"

            try:
                r = json.loads(line)
            except Exception:
                log.append({
                    "defect_type": "malformed_timestamp",
                    "original_value": None,
                    "corrected_value": None,
                    "record_id": rid,
                    "reason": "Invalid JSON record"
                })
                continue

            original_ts = r.get("timestamp")
            dt = parse_time(original_ts)

            if dt is None:
                log.append({
                    "defect_type": "malformed_timestamp",
                    "original_value": original_ts,
                    "corrected_value": None,
                    "record_id": rid,
                    "reason": "Timestamp could not be repaired"
                })
                continue

            new_ts = dt.isoformat().replace("+00:00", "Z")

            if str(original_ts) != new_ts:
                log.append({
                    "defect_type": "malformed_timestamp",
                    "original_value": original_ts,
                    "corrected_value": new_ts,
                    "record_id": rid,
                    "reason": "Timestamp repaired to ISO 8601 UTC"
                })

            r["timestamp"] = new_ts

            key = json.dumps([
                r.get("timestamp"),
                r.get("hostname"),
                r.get("source_type"),
                r.get("raw_message")
            ], sort_keys=True)

            key = hashlib.sha256(key.encode()).hexdigest()

            if key in seen:
                log.append({
                    "defect_type": "duplicate",
                    "original_value": key,
                    "corrected_value": None,
                    "record_id": rid,
                    "reason": "Duplicate timestamp, hostname, source_type and raw_message"
                })
                continue

            seen.add(key)

            host = r.get("hostname")

            if isinstance(host, str):
                fixed_host = host.lower()

                if host != fixed_host:
                    log.append({
                        "defect_type": "hostname_case",
                        "original_value": host,
                        "corrected_value": fixed_host,
                        "record_id": rid,
                        "reason": "Hostname normalized to lowercase"
                    })
                    r["hostname"] = fixed_host

            message = r.get("raw_message")

            if isinstance(message, str):
                if any(x in message for x in ("�", "Ã", "Â", "â€")):
                    try:
                        fixed = message.encode(
                            "latin-1"
                        ).decode("utf-8")

                        if fixed != message:
                            log.append({
                                "defect_type": "encoding_error",
                                "original_value": message,
                                "corrected_value": fixed,
                                "record_id": rid,
                                "reason": "Latin-1/UTF-8 encoding repaired"
                            })
                            r["raw_message"] = fixed
                    except (UnicodeEncodeError, UnicodeDecodeError):
                        pass

            out.write(
                json.dumps(
                    r,
                    separators=(",", ":"),
                    ensure_ascii=False
                ) + "\n"
            )

with open("cleaning_log.json", "w", encoding="utf-8") as f:
    json.dump(log, f, separators=(",", ":"))

print("cleaned_events.json    written")
print("cleaning_log.json      written")
PY
