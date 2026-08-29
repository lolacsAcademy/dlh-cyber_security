#!/bin/bash

set -euo pipefail

PACK_ROOT="${1:-$HOME/evidence_pack_primary}"
OUT="source_inventory.json"

python3 - "$PACK_ROOT" "$OUT" <<'PY'
import csv
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

root = Path(sys.argv[1])
out_file = Path(sys.argv[2])

manifest = []


def sha256_file(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def normalize_time(value):
    if value is None:
        return None

    value = str(value).strip()
    if not value:
        return None

    # Unix epoch
    if re.fullmatch(r"\d+(?:\.\d+)?", value):
        try:
            return datetime.fromtimestamp(
                float(value), timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
        except (ValueError, OverflowError):
            return None

    # ISO 8601
    try:
        iso = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", value.replace("Z", "+00:00"))
        dt = datetime.fromisoformat(iso)

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        return dt.astimezone(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    except ValueError:
        pass

    # PCAP format: 03/20/2026 11:16:56 PM
    try:
        dt = datetime.strptime(value, "%m/%d/%Y %I:%M:%S %p")
        dt = dt.replace(tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None


def add_entry(path, source_type, count_key, count,
              first_time, last_time, parse_status):
    manifest.append({
        "path": str(path.relative_to(root)),
        "source_type": source_type,
        "size_bytes": path.stat().st_size,
        "sha256": sha256_file(path),
        count_key: count,
        "first_event_time": first_time,
        "last_event_time": last_time,
        "parse_status": parse_status
    })


def read_json_records(path):
    """
    Accept:
      - JSON array
      - single JSON object
      - NDJSON

    Bad NDJSON records are skipped and marked partial.
    Empty or completely malformed files do not crash.
    """
    if path.stat().st_size == 0:
        return [], "empty"

    records = []
    bad = 0

    with path.open("r", encoding="utf-8", errors="replace") as f:
        first_char = ""

        while True:
            c = f.read(1)
            if not c:
                return [], "empty"
            if not c.isspace():
                first_char = c
                break

        f.seek(0)

        # JSON array
        if first_char == "[":
            try:
                data = json.load(f)

                if not isinstance(data, list):
                    return [], "parse_error"

                for item in data:
                    if isinstance(item, dict):
                        records.append(item)
                    else:
                        bad += 1

                status = "partial" if bad else "ok"
                return records, status

            except (json.JSONDecodeError, OSError):
                return [], "parse_error"

        # Object or NDJSON: process line by line.
        for line in f:
            line = line.strip()

            if not line:
                continue

            try:
                item = json.loads(line)

                if isinstance(item, dict):
                    records.append(item)
                else:
                    bad += 1

            except json.JSONDecodeError:
                bad += 1

    if not records:
        return [], "parse_error" if bad else "empty"

    return records, "partial" if bad else "ok"


def json_file(path, source_type, time_field,
              start_field=None, end_field=None):
    records, status = read_json_records(path)

    times = []

    if start_field and end_field:
        starts = []
        ends = []

        for record in records:
            start = normalize_time(record.get(start_field))
            end = normalize_time(record.get(end_field))

            if start:
                starts.append(start)

            if end:
                ends.append(end)

        first_time = min(starts) if starts else None
        last_time = max(ends) if ends else None

    else:
        for record in records:
            timestamp = normalize_time(record.get(time_field))
            if timestamp:
                times.append(timestamp)

        first_time = min(times) if times else None
        last_time = max(times) if times else None

    add_entry(
        path,
        source_type,
        "record_count",
        len(records),
        first_time,
        last_time,
        status
    )


# Determine evidence year from audit.log.
pack_year = None
audit_path = root / "linux" / "audit.log"

if audit_path.is_file():
    audit_re = re.compile(r"audit\((\d+)(?:\.\d+)?:")
    earliest_epoch = None

    with audit_path.open(
        "r", encoding="utf-8", errors="replace"
    ) as f:
        for line in f:
            match = audit_re.search(line)

            if match:
                epoch = int(match.group(1))

                if earliest_epoch is None or epoch < earliest_epoch:
                    earliest_epoch = epoch

    if earliest_epoch is not None:
        pack_year = datetime.fromtimestamp(
            earliest_epoch, timezone.utc
        ).year


# Windows JSON
windows_dir = root / "windows"

if windows_dir.is_dir():
    for path in sorted(windows_dir.glob("*.json")):
        json_file(
            path,
            "windows_json",
            "timestamp_raw"
        )


# Linux text
linux_dir = root / "linux"

if linux_dir.is_dir():
    syslog_re = re.compile(
        r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    )
    audit_re = re.compile(r"audit\((\d+)(?:\.\d+)?:")
    
    for path in sorted(linux_dir.iterdir()):
        if not path.is_file():
            continue

        count = 0
        times = []
        bad_timestamps = 0

        with path.open(
            "r", encoding="utf-8", errors="replace"
        ) as f:
            for line in f:
                count += 1

                if path.name == "audit.log":
                    match = audit_re.search(line)

                    if match:
                        timestamp = normalize_time(match.group(1))

                        if timestamp:
                            times.append(timestamp)
                        else:
                            bad_timestamps += 1

                else:
                    match = syslog_re.match(line)

                    if match and pack_year is not None:
                        try:
                            dt = datetime.strptime(
                                f"{match.group(1)} {pack_year}",
                                "%b %d %H:%M:%S %Y"
                            ).replace(tzinfo=timezone.utc)

                            times.append(
                                dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                            )
                        except ValueError:
                            bad_timestamps += 1

        if count == 0:
            status = "empty"
        elif bad_timestamps:
            status = "partial"
        else:
            status = "ok"

        add_entry(
            path,
            "linux_text",
            "line_count",
            count,
            min(times) if times else None,
            max(times) if times else None,
            status
        )


# Network evidence
network_dir = root / "network"

if network_dir.is_dir():
    for path in sorted(network_dir.iterdir()):
        if not path.is_file():
            continue

        if path.suffix.lower() == ".csv":
            count = 0
            times = []
            bad = 0

            try:
                with path.open(
                    "r",
                    encoding="utf-8",
                    errors="replace",
                    newline=""
                ) as f:
                    reader = csv.DictReader(f)

                    for row in reader:
                        count += 1
                        timestamp = normalize_time(
                            row.get("timestamp")
                        )

                        if timestamp:
                            times.append(timestamp)
                        else:
                            bad += 1

                if count == 0:
                    status = "empty"
                elif bad:
                    status = "partial"
                else:
                    status = "ok"

            except (csv.Error, OSError):
                count = 0
                times = []
                status = "parse_error"

            add_entry(
                path,
                "network_csv",
                "record_count",
                count,
                min(times) if times else None,
                max(times) if times else None,
                status
            )

        elif path.name == "pcap_summary.json":
            json_file(
                path,
                "network_json",
                None,
                "start_time",
                "end_time"
            )

        elif path.suffix.lower() == ".json":
            json_file(
                path,
                "network_json",
                "timestamp"
            )


# Deterministic output.
manifest.sort(key=lambda item: item["path"])

with out_file.open("w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2)
    f.write("\n")


# Human-readable summary.
total_files = 0
total_bytes = 0

for category in ("windows", "linux", "network"):
    entries = [
        item for item in manifest
        if item["path"].startswith(category + "/")
    ]

    file_count = len(entries)
    byte_count = sum(item["size_bytes"] for item in entries)

    total_files += file_count
    total_bytes += byte_count

    print(
        f"{category:<8}: {file_count} files  |  "
        f"{byte_count / 1048576:6.1f} MB"
    )

print(
    f"{'total':<8}: {total_files} files  |  "
    f"{total_bytes / 1048576:6.1f} MB"
)

print(f"manifest written to {out_file}")
PY
