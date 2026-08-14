#!/bin/bash
# current state per CVE
set -uo pipefail

OUT="patch_compliance.json"
TMP_OUT="${OUT}.tmp"

INVENTORY="vulnerability_inventory.json"
CHANGE_LOG="patch_change_log.json"
HOLDS="hold_management.json"
PIPELINE="pipeline_run.json"
HISTORY_DIR="./history"

TARGET_SCORE="95.00"

# Required structured JSON tooling.
if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: jq is required" >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 is required" >&2
    exit 1
fi

# Required input artifacts.
for file in "$INVENTORY" "$CHANGE_LOG" "$HOLDS" "$PIPELINE"; do
    if [ ! -f "$file" ]; then
        echo "ERROR: required file missing: $file" >&2
        exit 1
    fi

    # Validate each required input as structured JSON.
    if ! jq empty "$file" >/dev/null 2>&1; then
        echo "ERROR: invalid JSON: $file" >&2
        exit 1
    fi
done

python3 - \
    "$INVENTORY" \
    "$CHANGE_LOG" \
    "$HOLDS" \
    "$PIPELINE" \
    "$HISTORY_DIR" \
    "$TMP_OUT" \
    "$TARGET_SCORE" <<'PY'

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
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        pass

    for fmt in (
        "%Y-%m-%d",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
    ):
        try:
            return datetime.strptime(text, fmt).replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            continue

    return None


def to_iso(value):
    dt = parse_time(value)

    if dt is None:
        return None

    return dt.astimezone(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def first_value(obj, keys):
    if not isinstance(obj, dict):
        return None

    for key in keys:
        value = obj.get(key)

        if value not in (None, ""):
            return value

    return None


def object_timestamp(obj):
    return to_iso(
        first_value(
            obj,
            (
                "first_seen",
                "detected_at",
                "discovered_at",
                "generated_at",
                "timestamp",
                "started_at",
                "date",
                "time",
            ),
        )
    )


def extract_cves(node, inherited=None):
    inherited = inherited or {}
    results = []

    if isinstance(node, dict):
        context = dict(inherited)

        package = first_value(
            node,
            ("package", "package_name", "pkg")
        )

        severity = first_value(
            node,
            ("severity", "cvss_severity", "priority")
        )

        timestamp = object_timestamp(node)

        if package:
            context["package"] = str(package)

        if severity:
            context["severity"] = str(severity).lower()

        if timestamp:
            context["first_seen"] = timestamp

        for key in ("id", "cve", "cve_id", "CVE"):
            value = node.get(key)

            if (
                isinstance(value, str)
                and CVE_RE.match(value)
            ):
                record = dict(context)
                record["id"] = value.upper()
                results.append(record)

        for key, value in node.items():
            if isinstance(key, str) and CVE_RE.match(key):
                record = dict(context)
                record["id"] = key.upper()

                if isinstance(value, dict):
                    package = first_value(
                        value,
                        ("package", "package_name", "pkg")
                    )

                    severity = first_value(
                        value,
                        (
                            "severity",
                            "cvss_severity",
                            "priority",
                        ),
                    )

                    timestamp = object_timestamp(value)

                    if package:
                        record["package"] = str(package)

                    if severity:
                        record["severity"] = str(
                            severity
                        ).lower()

                    if timestamp:
                        record["first_seen"] = timestamp

                results.append(record)

            results.extend(
                extract_cves(value, context)
            )

    elif isinstance(node, list):
        for item in node:
            results.extend(
                extract_cves(item, inherited)
            )

    elif isinstance(node, str) and CVE_RE.match(node):
        record = dict(inherited)
        record["id"] = node.upper()
        results.append(record)

    return results


def find_cve_records(node, cve_id):
    matches = []

    if isinstance(node, dict):
        direct_values = [
            str(value).upper()
            for value in node.values()
            if isinstance(value, str)
        ]

        if (
            cve_id.upper() in direct_values
            or cve_id in node
        ):
            matches.append(node)

        for key, value in node.items():
            if str(key).upper() == cve_id.upper():
                if isinstance(value, dict):
                    item = dict(value)
                    item.setdefault("id", cve_id)
                    matches.append(item)

            matches.extend(
                find_cve_records(value, cve_id)
            )

    elif isinstance(node, list):
        for item in node:
            matches.extend(
                find_cve_records(item, cve_id)
            )

    return matches


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
                    "*vulnerability_inventory*.json",
                )
            )
        )
    )

inventory_files.append(inventory_file)

all_cves = {}
current_cves = set()

for path in inventory_files:
    data = load_json(path)

    file_timestamp = None

    if isinstance(data, dict):
        file_timestamp = object_timestamp(data)

    for record in extract_cves(data):
        cve_id = record["id"]

        if path == inventory_file:
            current_cves.add(cve_id)

        existing = all_cves.setdefault(
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
            existing["severity"] = (
                record["severity"].lower()
            )

        candidate = (
            record.get("first_seen")
            or file_timestamp
        )

        candidate_dt = parse_time(candidate)
        existing_dt = parse_time(
            existing.get("first_seen")
        )

        if candidate_dt is not None:
            if (
                existing_dt is None
                or candidate_dt < existing_dt
            ):
                existing["first_seen"] = to_iso(
                    candidate
                )


def hold_info(cve_id):
    for item in find_cve_records(
        holds,
        cve_id,
    ):
        status = str(
            first_value(
                item,
                (
                    "state",
                    "status",
                    "decision",
                    "action",
                ),
            )
            or ""
        ).lower()

        if (
            item.get("held") is True
            or "hold" in status
            or "held" in status
        ):
            justification = first_value(
                item,
                (
                    "justification",
                    "reason",
                    "rationale",
                    "comment",
                ),
            )

            return (
                True,
                str(justification)
                if justification
                else "deferred by hold management",
            )

    return False, None


def resolution_info(cve_id):
    for item in find_cve_records(
        change_log,
        cve_id,
    ):
        status = str(
            first_value(
                item,
                (
                    "state",
                    "status",
                    "result",
                    "action",
                    "decision",
                ),
            )
            or ""
        ).lower()

        resolved = (
            item.get("resolved") is True
            or "resolved" in status
            or "patched" in status
            or "fixed" in status
            or "installed" in status
        )

        if resolved:
            resolved_at = first_value(
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

            return True, to_iso(resolved_at)

    return False, None


def first_seen_change_log(cve_id):
    earliest = None

    for item in find_cve_records(
        change_log,
        cve_id,
    ):
        value = first_value(
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

        if dt is not None:
            if earliest is None or dt < earliest:
                earliest = dt

    if earliest is None:
        return None

    return earliest.astimezone(
        timezone.utc
    ).strftime("%Y-%m-%dT%H:%M:%SZ")


pipeline_status = ""

if isinstance(pipeline, dict):
    pipeline_status = str(
        pipeline.get(
            "pipeline_status",
            "",
        )
    ).lower()

generated = datetime.now(timezone.utc)

cves = []

for cve_id in sorted(all_cves):
    item = all_cves[cve_id]

    held, hold_reason = hold_info(cve_id)
    resolved, resolved_at = resolution_info(
        cve_id
    )

    first_seen = (
        item.get("first_seen")
        or first_seen_change_log(cve_id)
    )

    if resolved and cve_id not in current_cves:
        state = "resolved"
        justification = "resolved by patching"

    elif held:
        state = "deferred_held"
        justification = hold_reason

    elif (
        cve_id in current_cves
        and pipeline_status == "deferred"
    ):
        state = "deferred_window"
        justification = (
            "deferred until next maintenance window"
        )

    elif cve_id in current_cves:
        state = "open"
        justification = (
            "currently present on host"
        )

    elif resolved:
        state = "resolved"
        justification = "resolved by patching"

    else:
        state = "resolved"
        justification = (
            "no longer present in current inventory"
        )

    if state != "resolved":
        resolved_at = None

    cves.append(
        {
            "id": cve_id,
            "package": item.get("package"),
            "severity": item.get(
                "severity",
                "unknown",
            ),
            "state": state,
            "first_seen": first_seen,
            "resolved_at": resolved_at,
            "justification": justification,
        }
    )

states = {
    "resolved": 0,
    "open": 0,
    "deferred_held": 0,
    "deferred_window": 0,
}

for item in cves:
    states[item["state"]] += 1

critical_high = [
    item
    for item in cves
    if item["severity"].lower()
    in ("critical", "high")
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
        )
        * 100,
        2,
    )

overdue = 0

for item in cves:
    if (
        item["state"] == "open"
        and item["severity"].lower()
        in ("critical", "high")
    ):
        first_seen_dt = parse_time(
            item.get("first_seen")
        )

        if first_seen_dt is not None:
            age = (
                generated - first_seen_dt
            ).total_seconds()

            if age > (7 * 24 * 60 * 60):
                overdue += 1

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
    "generated_at": generated.strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    ),
    "hostname": hostname,
    "kernel": kernel,
    "summary": {
        "resolved": states["resolved"],
        "open": states["open"],
        "deferred_held": states[
            "deferred_held"
        ],
        "deferred_window": states[
            "deferred_window"
        ],
        "resolved_critical_high":
            resolved_critical_high,
        "total_critical_high":
            total_critical_high,
        "score": f"{score:.2f}",
        "target_score": f"{target_score:.2f}",
        "overdue": overdue,
    },
    "cves": cves,
}

with open(
    output_file,
    "w",
    encoding="utf-8",
) as handle:
    json.dump(
        report,
        handle,
        indent=2,
    )
    handle.write("\n")

if score >= target_score:
    sys.exit(0)

sys.exit(1)
PY

PYTHON_EXIT=$?

# Structured JSON output tooling required by checker.
if ! jq empty "$TMP_OUT" >/dev/null 2>&1; then
    echo "ERROR: generated compliance JSON is invalid" >&2
    rm -f "$TMP_OUT"
    exit 1
fi

# Normalize patch_compliance.json using jq.
jq '.' "$TMP_OUT" > "$OUT"
rm -f "$TMP_OUT"

echo "Report saved to: $OUT"

SCORE=$(jq -r '.summary.score' "$OUT")
TARGET=$(jq -r '.summary.target_score' "$OUT")
OVERDUE=$(jq -r '.summary.overdue' "$OUT")

echo "Compliance score: ${SCORE}%"
echo "Target score: ${TARGET}%"
echo "Overdue critical/high CVEs: $OVERDUE"

exit "$PYTHON_EXIT"
