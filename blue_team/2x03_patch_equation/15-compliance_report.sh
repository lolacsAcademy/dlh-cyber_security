#!/bin/bash
set -uo pipefail

OUT="patch_compliance.json"

INVENTORY="vulnerability_inventory.json"
CHANGE_LOG="patch_change_log.json"
HOLDS="hold_management.json"
PIPELINE="pipeline_run.json"
HISTORY_DIR="./history"

TARGET_SCORE="95.00"

for file in "$INVENTORY" "$CHANGE_LOG" "$HOLDS" "$PIPELINE"; do
    if [ ! -f "$file" ]; then
        echo "ERROR: required file missing: $file" >&2
        exit 1
    fi
done

if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 is required" >&2
    exit 1
fi

python3 - "$INVENTORY" "$CHANGE_LOG" "$HOLDS" "$PIPELINE" \
    "$HISTORY_DIR" "$OUT" "$TARGET_SCORE" <<'PY'
import glob
import json
import os
import platform
import re
import socket
import sys
from datetime import datetime, timezone

inventory_file = sys.argv[1]
change_log_file = sys.argv[2]
holds_file = sys.argv[3]
pipeline_file = sys.argv[4]
history_dir = sys.argv[5]
output_file = sys.argv[6]
target_score = float(sys.argv[7])

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: cannot read {path}: {exc}", file=sys.stderr)
        sys.exit(1)


def parse_time(value):
    if not value:
        return None

    text = str(value).strip()

    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        pass

    formats = (
        "%Y-%m-%d",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
    )

    for fmt in formats:
        try:
            dt = datetime.strptime(text, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue

    return None


def iso_or_none(value):
    dt = parse_time(value)
    if dt is None:
        return None

    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def find_timestamp(obj):
    if not isinstance(obj, dict):
        return None

    for key in (
        "first_seen",
        "detected_at",
        "discovered_at",
        "timestamp",
        "generated_at",
        "started_at",
        "date",
        "time",
    ):
        if obj.get(key):
            return iso_or_none(obj[key])

    return None


def find_value(obj, keys):
    if not isinstance(obj, dict):
        return None

    for key in keys:
        if key in obj and obj[key] not in (None, ""):
            return obj[key]

    return None


def extract_cves(node, inherited=None):
    """
    Recursively find CVE records in differing inventory schemas.
    """
    inherited = inherited or {}
    found = []

    if isinstance(node, dict):
        context = dict(inherited)

        package = find_value(
            node,
            ("package", "package_name", "name", "pkg")
        )
        severity = find_value(
            node,
            ("severity", "cvss_severity", "priority")
        )

        if package:
            context["package"] = str(package)

        if severity:
            context["severity"] = str(severity).lower()

        timestamp = find_timestamp(node)
        if timestamp:
            context["first_seen"] = timestamp

        for key in ("id", "cve", "cve_id", "CVE"):
            value = node.get(key)

            if isinstance(value, str) and CVE_RE.match(value):
                record = dict(context)
                record["id"] = value.upper()
                found.append(record)

        for key, value in node.items():
            if isinstance(key, str) and CVE_RE.match(key):
                record = dict(context)
                record["id"] = key.upper()

                if isinstance(value, dict):
                    pkg = find_value(
                        value,
                        ("package", "package_name", "name", "pkg")
                    )
                    sev = find_value(
                        value,
                        ("severity", "cvss_severity", "priority")
                    )

                    if pkg:
                        record["package"] = str(pkg)

                    if sev:
                        record["severity"] = str(sev).lower()

                    ts = find_timestamp(value)
                    if ts:
                        record["first_seen"] = ts

                found.append(record)

            found.extend(extract_cves(value, context))

    elif isinstance(node, list):
        for item in node:
            found.extend(extract_cves(item, inherited))

    elif isinstance(node, str):
        if CVE_RE.match(node):
            record = dict(inherited)
            record["id"] = node.upper()
            found.append(record)

    return found


def records_for_cve(node, cve_id):
    results = []

    def walk(value):
        if isinstance(value, dict):
            text_values = [
                str(v).upper()
                for v in value.values()
                if isinstance(v, str)
            ]

            if cve_id.upper() in text_values or cve_id in value:
                results.append(value)

            for key, child in value.items():
                if str(key).upper() == cve_id.upper():
                    if isinstance(child, dict):
                        copy = dict(child)
                        copy.setdefault("id", cve_id)
                        results.append(copy)

                walk(child)

        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(node)
    return results


current_inventory = load_json(inventory_file)
change_log = load_json(change_log_file)
holds = load_json(holds_file)
pipeline = load_json(pipeline_file)

inventory_files = []

if os.path.isdir(history_dir):
    inventory_files.extend(
        sorted(
            glob.glob(
                os.path.join(
                    history_dir,
                    "*vulnerability_inventory*.json"
                )
            )
        )
    )

inventory_files.append(inventory_file)

all_records = {}
current_ids = set()

for path in inventory_files:
    data = load_json(path)

    generated = None
    if isinstance(data, dict):
        generated = find_value(
            data,
            (
                "generated_at",
                "timestamp",
                "created_at",
                "started_at",
            ),
        )
        generated = iso_or_none(generated)

    for record in extract_cves(data):
        cve_id = record["id"]

        if path == inventory_file:
            current_ids.add(cve_id)

        existing = all_records.setdefault(
            cve_id,
            {
                "id": cve_id,
                "package": None,
                "severity": "unknown",
                "first_seen": None,
            },
        )

        if record.get("package"):
            existing["package"] = record["package"]

        if record.get("severity"):
            existing["severity"] = record["severity"].lower()

        candidate_seen = record.get("first_seen") or generated

        if candidate_seen:
            candidate_dt = parse_time(candidate_seen)
            existing_dt = parse_time(existing.get("first_seen"))

            if existing_dt is None or (
                candidate_dt is not None and
                candidate_dt < existing_dt
            ):
                existing["first_seen"] = iso_or_none(candidate_seen)


def held_information(cve_id):
    matches = records_for_cve(holds, cve_id)

    for item in matches:
        state = str(
            find_value(
                item,
                ("state", "status", "decision", "action")
            ) or ""
        ).lower()

        held_flag = item.get("held")

        if (
            held_flag is True
            or "hold" in state
            or "held" in state
        ):
            reason = find_value(
                item,
                (
                    "justification",
                    "reason",
                    "rationale",
                    "comment",
                ),
            )

            return True, (
                str(reason)
                if reason
                else "package/CVE held by hold management"
            )

    return False, None


def resolution_information(cve_id):
    matches = records_for_cve(change_log, cve_id)

    for item in matches:
        state = str(
            find_value(
                item,
                (
                    "state",
                    "status",
                    "result",
                    "action",
                    "decision",
                ),
            ) or ""
        ).lower()

        resolved = (
            item.get("resolved") is True
            or "resolved" in state
            or "patched" in state
            or "fixed" in state
            or "installed" in state
        )

        if resolved:
            resolved_at = find_value(
                item,
                (
                    "resolved_at",
                    "patched_at",
                    "installed_at",
                    "timestamp",
                    "date",
                    "time",
                ),
            )

            return True, iso_or_none(resolved_at)

    return False, None


def first_seen_from_change_log(cve_id):
    matches = records_for_cve(change_log, cve_id)
    earliest = None

    for item in matches:
        value = find_value(
            item,
            (
                "first_seen",
                "detected_at",
                "discovered_at",
                "timestamp",
                "date",
                "time",
            ),
        )

        dt = parse_time(value)

        if dt is not None and (
            earliest is None or dt < earliest
        ):
            earliest = dt

    if earliest:
        return earliest.astimezone(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )

    return None


pipeline_status = ""

if isinstance(pipeline, dict):
    pipeline_status = str(
        pipeline.get("pipeline_status", "")
    ).lower()

generated_at = datetime.now(timezone.utc)
generated_iso = generated_at.strftime("%Y-%m-%dT%H:%M:%SZ")

cves = []

for cve_id in sorted(all_records):
    record = all_records[cve_id]

    held, hold_reason = held_information(cve_id)
    resolved, resolved_at = resolution_information(cve_id)

    first_seen = (
        record.get("first_seen")
        or first_seen_from_change_log(cve_id)
    )

    if resolved and cve_id not in current_ids:
        state = "resolved"
        justification = "resolved by patching"

    elif held:
        state = "deferred_held"
        justification = hold_reason

    elif cve_id in current_ids and pipeline_status == "deferred":
        state = "deferred_window"
        justification = "deferred until next maintenance window"

    elif cve_id in current_ids:
        state = "open"
        justification = "currently present on host"

    elif resolved:
        state = "resolved"
        justification = "resolved by patching"

    else:
        state = "resolved"
        justification = "no longer present in current inventory"

    if state != "resolved":
        resolved_at = None

    cves.append(
        {
            "id": cve_id,
            "package": record.get("package"),
            "severity": record.get("severity", "unknown"),
            "state": state,
            "first_seen": first_seen,
            "resolved_at": resolved_at,
            "justification": justification,
        }
    )


state_counts = {
    "resolved": 0,
    "open": 0,
    "deferred_held": 0,
    "deferred_window": 0,
}

for item in cves:
    state_counts[item["state"]] += 1


critical_high = [
    item for item in cves
    if item["severity"].lower() in ("critical", "high")
]

total_critical_high = len(critical_high)

resolved_critical_high = sum(
    1
    for item in critical_high
    if item["state"] == "resolved"
)

if total_critical_high == 0:
    score = 100.00
else:
    score = round(
        (
            resolved_critical_high
            / total_critical_high
        ) * 100,
        2,
    )


overdue_count = 0

for item in cves:
    if (
        item["state"] == "open"
        and item["severity"].lower() in ("critical", "high")
    ):
        first_seen_dt = parse_time(item.get("first_seen"))

        if first_seen_dt is not None:
            age_seconds = (
                generated_at - first_seen_dt
            ).total_seconds()

            if age_seconds > (7 * 24 * 60 * 60):
                overdue_count += 1


hostname = None
kernel = None

if isinstance(pipeline, dict):
    hostname = pipeline.get("hostname")
    kernel = pipeline.get("kernel")

if not hostname:
    hostname = socket.gethostname()

if not kernel:
    kernel = platform.release()


report = {
    "generated_at": generated_iso,
    "hostname": hostname,
    "kernel": kernel,
    "summary": {
        "resolved": state_counts["resolved"],
        "open": state_counts["open"],
        "deferred_held": state_counts["deferred_held"],
        "deferred_window": state_counts["deferred_window"],
        "resolved_critical_high": resolved_critical_high,
        "total_critical_high": total_critical_high,
        "score": f"{score:.2f}",
        "target_score": f"{target_score:.2f}",
        "overdue": overdue_count,
    },
    "cves": cves,
}


tmp_file = output_file + ".tmp"

with open(tmp_file, "w", encoding="utf-8") as handle:
    json.dump(
        report,
        handle,
        indent=2,
        sort_keys=False,
    )
    handle.write("\n")

# Avoid rewriting unchanged JSON with different content.
if os.path.exists(output_file):
    try:
        with open(output_file, "r", encoding="utf-8") as handle:
            previous = json.load(handle)

        comparison_old = dict(previous)
        comparison_new = dict(report)

        # generated_at is naturally different between executions.
        comparison_old.pop("generated_at", None)
        comparison_new.pop("generated_at", None)

        if comparison_old == comparison_new:
            os.remove(tmp_file)
        else:
            os.replace(tmp_file, output_file)
    except (OSError, json.JSONDecodeError):
        os.replace(tmp_file, output_file)
else:
    os.replace(tmp_file, output_file)


print(f"Report saved to: {output_file}")
print(f"Compliance score: {score:.2f}%")
print(f"Target score: {target_score:.2f}%")
print(f"Overdue critical/high CVEs: {overdue_count}")

if score >= target_score:
    sys.exit(0)

sys.exit(1)
PY

exit $?
