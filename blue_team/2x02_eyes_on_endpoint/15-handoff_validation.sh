#!/bin/bash
set -euo pipefail

HANDOFF_DIR="telemetry_handoff"

WINDOWS_FILE="$HANDOFF_DIR/windows_events.json"
LINUX_FILE="$HANDOFF_DIR/linux_events.json"
GROUND_FILE="$HANDOFF_DIR/attack_ground_truth.json"

WINDOWS_MATRIX="windows_detection_matrix.json"
LINUX_MATRIX="linux_detection_matrix.json"

OUT="handoff_validation.json"
TMP_DIR=$(mktemp -d)
TMP_OUT="$TMP_DIR/handoff_validation.json"

trap 'rm -rf "$TMP_DIR"' EXIT

PASS_COUNT=0
FAIL_COUNT=0
TOTAL_CHECKS=14
CHECKS='[]'

echo "[*] Validating telemetry_handoff/ ..."

# ------------------------------------------------------------
# Required tools
# ------------------------------------------------------------
for cmd in jq python3 stat; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: required command not found: $cmd" >&2
        exit 1
    fi
done

add_check() {
    local name="$1"
    local status="$2"
    local detail="$3"
    local entry

    entry=$(jq -n \
        --arg name "$name" \
        --arg status "$status" \
        --arg detail "$detail" \
        '{
            check: $name,
            status: $status,
            detail: $detail
        }')

    CHECKS=$(printf '%s\n' "$CHECKS" |
        jq --argjson entry "$entry" '. + [$entry]')

    if [ "$status" = "PASS" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo "[PASS] $detail"
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo "[FAIL] $detail"
    fi
}

file_size() {
    local file="$1"
    local bytes

    bytes=$(stat -c %s "$file" 2>/dev/null || echo 0)

    if [ "$bytes" -ge 1048576 ]; then
        awk -v b="$bytes" \
            'BEGIN {printf "%.1f MB", b/1048576}'
    elif [ "$bytes" -ge 1024 ]; then
        awk -v b="$bytes" \
            'BEGIN {printf "%.1f KB", b/1024}'
    else
        printf '%s bytes' "$bytes"
    fi
}

event_count() {
    jq '
        if type == "array" then
            length
        elif (.events? | type) == "array" then
            .events | length
        elif (.records? | type) == "array" then
            .records | length
        elif (.data? | type) == "array" then
            .data | length
        else
            0
        end
    ' "$1"
}

ground_count() {
    jq '
        if type == "array" then
            length
        elif (.actions? | type) == "array" then
            .actions | length
        elif (.ground_truth? | type) == "array" then
            .ground_truth | length
        elif (.windows? | type) == "array" and (.linux? | type) == "array" then
            (.windows + .linux) | length
        elif (.simulated_actions? | type) == "array" then
            .simulated_actions | length
        elif (.events? | type) == "array" then
            .events | length
        elif (.records? | type) == "array" then
            .records | length
        else
            0
        end
    ' "$1"
}

# ============================================================
# 1-3. FILE EXISTENCE
# ============================================================
echo "=== File Existence ==="

for file in \
    "$WINDOWS_FILE" \
    "$LINUX_FILE" \
    "$GROUND_FILE"
do
    name=$(basename "$file")

    if [ -s "$file" ]; then
        add_check \
            "file_exists_$name" \
            "PASS" \
            "$name exists ($(file_size "$file"))"
    else
        add_check \
            "file_exists_$name" \
            "FAIL" \
            "$name missing or empty"
    fi
done

# Stop safely if the required files do not exist.
if [ "$FAIL_COUNT" -gt 0 ]; then
    jq -n \
        --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
        --arg verdict "FAIL" \
        --argjson passed "$PASS_COUNT" \
        --argjson failed "$FAIL_COUNT" \
        --argjson total "$TOTAL_CHECKS" \
        --argjson checks "$CHECKS" \
        '{
            generated_at: $generated_at,
            verdict: $verdict,
            passed_checks: $passed,
            failed_checks: $failed,
            total_checks: $total,
            checks: $checks
        }' > "$OUT"

    echo "VERDICT: FAIL"
    echo "Report saved to: $OUT"
    exit 1
fi

# ============================================================
# 4-6. JSON VALIDITY
# ============================================================
echo "=== JSON Validity ==="

for file in \
    "$WINDOWS_FILE" \
    "$LINUX_FILE" \
    "$GROUND_FILE"
do
    name=$(basename "$file")

    if jq empty "$file" >/dev/null 2>&1; then
        if [ "$file" = "$GROUND_FILE" ]; then
            count=$(ground_count "$file")
        else
            count=$(event_count "$file")
        fi

        add_check \
            "json_valid_$name" \
            "PASS" \
            "$name: valid JSON, $count objects"
    else
        add_check \
            "json_valid_$name" \
            "FAIL" \
            "$name: invalid JSON"
    fi
done

# ============================================================
# 7. REQUIRED FIELDS
# ============================================================
echo "=== Required Fields ==="

WINDOWS_MISSING=$(jq '
    def events:
        if type == "array" then .
        elif (.events? | type) == "array" then .events
        elif (.records? | type) == "array" then .records
        elif (.data? | type) == "array" then .data
        else []
        end;

    events
    | [
        .[]
        | select(
            (.timestamp? == null) or
            (.hostname? == null) or
            (.source_type? == null) or
            (.event_category? == null)
        )
    ]
    | length
' "$WINDOWS_FILE")

LINUX_MISSING=$(jq '
    def events:
        if type == "array" then .
        elif (.events? | type) == "array" then .events
        elif (.records? | type) == "array" then .records
        elif (.data? | type) == "array" then .data
        else []
        end;

    events
    | [
        .[]
        | select(
            (.timestamp? == null) or
            (.hostname? == null) or
            (.source_type? == null) or
            (.event_category? == null)
        )
    ]
    | length
' "$LINUX_FILE")

if [ "$WINDOWS_MISSING" -eq 0 ] &&
    [ "$LINUX_MISSING" -eq 0 ]; then

    add_check \
        "required_fields" \
        "PASS" \
        "All events have timestamp, hostname, source_type, event_category"
else
    add_check \
        "required_fields" \
        "FAIL" \
        "Missing required fields: Windows=$WINDOWS_MISSING Linux=$LINUX_MISSING"
fi

# ============================================================
# 8-10. MINIMUM COUNTS
# ============================================================
echo "=== Minimum Event Counts ==="

WINDOWS_COUNT=$(event_count "$WINDOWS_FILE")
LINUX_COUNT=$(event_count "$LINUX_FILE")
GROUND_COUNT=$(ground_count "$GROUND_FILE")

if [ "$WINDOWS_COUNT" -ge 1000 ]; then
    add_check \
        "minimum_windows_events" \
        "PASS" \
        "Windows: $WINDOWS_COUNT >= 1000"
else
    add_check \
        "minimum_windows_events" \
        "FAIL" \
        "Windows: $WINDOWS_COUNT < 1000"
fi

if [ "$LINUX_COUNT" -ge 500 ]; then
    add_check \
        "minimum_linux_events" \
        "PASS" \
        "Linux: $LINUX_COUNT >= 500"
else
    add_check \
        "minimum_linux_events" \
        "FAIL" \
        "Linux: $LINUX_COUNT < 500"
fi

if [ "$GROUND_COUNT" -ge 10 ]; then
    add_check \
        "minimum_ground_truth_actions" \
        "PASS" \
        "Ground truth: $GROUND_COUNT >= 10"
else
    add_check \
        "minimum_ground_truth_actions" \
        "FAIL" \
        "Ground truth: $GROUND_COUNT < 10"
fi

# ============================================================
# 11-13. TIMESTAMP VALIDATION + ALIGNMENT
#
# One Python process handles ALL timestamps quickly.
# ============================================================
echo "=== Timestamp Consistency ==="

TIMESTAMP_RESULT="$TMP_DIR/timestamps.json"

python3 - \
    "$WINDOWS_FILE" \
    "$LINUX_FILE" \
    "$TIMESTAMP_RESULT" <<'PY'
import json
import re
import sys
from datetime import datetime, timezone

windows_file = sys.argv[1]
linux_file = sys.argv[2]
output_file = sys.argv[3]

ISO_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T"
    r"\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?"
    r"(?:Z|[+-]\d{2}:\d{2})$"
)


def load(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def events(data):
    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        for key in ("events", "records", "data"):
            value = data.get(key)

            if isinstance(value, list):
                return value

    return []


def parse_timestamp(value):
    if not isinstance(value, str):
        return None

    if not ISO_RE.match(value):
        return None

    try:
        dt = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )

        if dt.tzinfo is None:
            return None

        return dt.astimezone(timezone.utc)

    except ValueError:
        return None


def analyse(items):
    invalid = 0
    future = 0
    timestamps = []

    now = datetime.now(timezone.utc)

    for item in items:
        value = item.get("timestamp")

        dt = parse_timestamp(value)

        if dt is None:
            invalid += 1
            continue

        if dt > now:
            future += 1

        timestamps.append(dt)

    if timestamps:
        minimum = min(timestamps)
        maximum = max(timestamps)

        return {
            "invalid": invalid,
            "future": future,
            "min": minimum.isoformat().replace(
                "+00:00",
                "Z",
            ),
            "max": maximum.isoformat().replace(
                "+00:00",
                "Z",
            ),
            "min_epoch": int(minimum.timestamp()),
            "max_epoch": int(maximum.timestamp()),
        }

    return {
        "invalid": invalid,
        "future": future,
        "min": None,
        "max": None,
        "min_epoch": None,
        "max_epoch": None,
    }


windows = analyse(events(load(windows_file)))
linux = analyse(events(load(linux_file)))

combined_invalid = (
    windows["invalid"] +
    linux["invalid"]
)

combined_future = (
    windows["future"] +
    linux["future"]
)

valid_ranges = (
    windows["min_epoch"] is not None and
    windows["max_epoch"] is not None and
    linux["min_epoch"] is not None and
    linux["max_epoch"] is not None
)

overlap_seconds = 0

if valid_ranges:
    start = max(
        windows["min_epoch"],
        linux["min_epoch"],
    )

    end = min(
        windows["max_epoch"],
        linux["max_epoch"],
    )

    if start <= end:
        overlap_seconds = end - start

result = {
    "windows": windows,
    "linux": linux,
    "invalid_total": combined_invalid,
    "future_total": combined_future,
    "overlap_seconds": overlap_seconds,
}

with open(
    output_file,
    "w",
    encoding="utf-8",
) as handle:
    json.dump(result, handle)
    handle.write("\n")
PY

INVALID_TIMESTAMPS=$(jq -r '.invalid_total' "$TIMESTAMP_RESULT")
FUTURE_TIMESTAMPS=$(jq -r '.future_total' "$TIMESTAMP_RESULT")

WIN_MIN=$(jq -r '.windows.min // empty' "$TIMESTAMP_RESULT")
WIN_MAX=$(jq -r '.windows.max // empty' "$TIMESTAMP_RESULT")
LINUX_MIN=$(jq -r '.linux.min // empty' "$TIMESTAMP_RESULT")
LINUX_MAX=$(jq -r '.linux.max // empty' "$TIMESTAMP_RESULT")

if [ "$INVALID_TIMESTAMPS" -eq 0 ] &&
    [ -n "$WIN_MIN" ] &&
    [ -n "$LINUX_MIN" ]; then

    RANGE_MIN=$(printf '%s\n%s\n' "$WIN_MIN" "$LINUX_MIN" |
        sort |
        head -1)

    RANGE_MAX=$(printf '%s\n%s\n' "$WIN_MAX" "$LINUX_MAX" |
        sort |
        tail -1)

    add_check \
        "valid_iso8601_timestamps" \
        "PASS" \
        "All timestamps valid ISO 8601; range: $RANGE_MIN to $RANGE_MAX"
else
    add_check \
        "valid_iso8601_timestamps" \
        "FAIL" \
        "$INVALID_TIMESTAMPS invalid ISO 8601 timestamps found"
fi

# ============================================================
# 12. NO FUTURE TIMESTAMPS
# ============================================================

if [ "$FUTURE_TIMESTAMPS" -eq 0 ]; then
    add_check \
        "no_future_timestamps" \
        "PASS" \
        "No future timestamps"
else
    add_check \
        "no_future_timestamps" \
        "FAIL" \
        "$FUTURE_TIMESTAMPS future timestamps found"
fi

# ============================================================
# 13. CROSS-PLATFORM ALIGNMENT
# ============================================================
echo "=== Cross-Platform Alignment ==="

OVERLAP_SECONDS=$(jq -r '.overlap_seconds' "$TIMESTAMP_RESULT")

if [ "$OVERLAP_SECONDS" -gt 0 ]; then
    OVERLAP_HOURS=$(awk \
        -v seconds="$OVERLAP_SECONDS" \
        'BEGIN {printf "%.1f", seconds/3600}')

    add_check \
        "cross_platform_alignment" \
        "PASS" \
        "Windows and Linux time ranges overlap (${OVERLAP_HOURS} hours shared)"
else
    add_check \
        "cross_platform_alignment" \
        "FAIL" \
        "Windows and Linux timestamp ranges do not overlap"
fi

# ============================================================
# 14. GROUND TRUTH COMPLETENESS
# ============================================================
echo "=== Ground Truth Completeness ==="

if [ ! -s "$WINDOWS_MATRIX" ] ||
    [ ! -s "$LINUX_MATRIX" ]; then

    add_check \
        "ground_truth_completeness" \
        "FAIL" \
        "Detection matrix file missing"

elif ! jq empty "$WINDOWS_MATRIX" >/dev/null 2>&1 ||
    ! jq empty "$LINUX_MATRIX" >/dev/null 2>&1; then

    add_check \
        "ground_truth_completeness" \
        "FAIL" \
        "Detection matrix contains invalid JSON"

else
    MATCHED_ACTIONS=$(jq -n \
        --slurpfile truth "$GROUND_FILE" \
        --slurpfile windows "$WINDOWS_MATRIX" \
        --slurpfile linux "$LINUX_MATRIX" '
        def truth_array:
            if type == "array" then .
            elif (.actions? | type) == "array" then .actions
            elif (.ground_truth? | type) == "array"
                then .ground_truth
            elif (.windows? | type) == "array" and (.linux? | type) == "array"
                then (.windows + .linux)
            elif (.simulated_actions? | type) == "array"
                then .simulated_actions
            elif (.events? | type) == "array" then .events
            elif (.records? | type) == "array" then .records
            else []
            end;

        def id:
            (
                .action_number //
                .action_id //
                .action //
                .test_id //
                .id //
                .name //
                .test //
                empty
            ) | tostring;

        ($truth[0] | truth_array) as $actions |

        (
            [
                $windows[0] |
                .. |
                objects |
                select(
                    has("action_number") or
                    has("action_id") or
                    has("action") or
                    has("test_id") or
                    has("id")
                )
            ]
            +
            [
                $linux[0] |
                .. |
                objects |
                select(
                    has("action_number") or
                    has("action_id") or
                    has("action") or
                    has("test_id") or
                    has("id")
                )
            ]
        ) as $matrix |

        [
            $actions[] |
            id as $action_id |
            select(
                any(
                    $matrix[];
                    (id == $action_id)
                )
            )
        ]
        | length
    ')

    if [ "$GROUND_COUNT" -gt 0 ] &&
        [ "$MATCHED_ACTIONS" -eq "$GROUND_COUNT" ]; then

        add_check \
            "ground_truth_completeness" \
            "PASS" \
            "$MATCHED_ACTIONS/$GROUND_COUNT actions have detection matrix entries"
    else
        add_check \
            "ground_truth_completeness" \
            "FAIL" \
            "$MATCHED_ACTIONS/$GROUND_COUNT actions have detection matrix entries"
    fi
fi

# ============================================================
# FINAL VERDICT
# ============================================================

if [ "$FAIL_COUNT" -eq 0 ]; then
    VERDICT="PASS"
else
    VERDICT="FAIL"
fi

jq -n \
    --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg verdict "$VERDICT" \
    --argjson passed "$PASS_COUNT" \
    --argjson failed "$FAIL_COUNT" \
    --argjson total "$TOTAL_CHECKS" \
    --argjson windows "$WINDOWS_COUNT" \
    --argjson linux "$LINUX_COUNT" \
    --argjson ground_truth "$GROUND_COUNT" \
    --argjson checks "$CHECKS" \
    '{
        generated_at: $generated_at,
        verdict: $verdict,
        passed_checks: $passed,
        failed_checks: $failed,
        total_checks: $total,
        event_counts: {
            windows: $windows,
            linux: $linux,
            ground_truth: $ground_truth
        },
        checks: $checks
    }' > "$TMP_OUT"

jq '.' "$TMP_OUT" > "$OUT"

echo "VERDICT: $VERDICT ($PASS_COUNT/$TOTAL_CHECKS checks)"

if [ "$VERDICT" = "PASS" ]; then
    echo "Handoff package is ready for Module 3."
else
    echo "Handoff package is NOT ready for Module 3."
fi

echo "Report saved to: $OUT"

if [ "$VERDICT" = "PASS" ]; then
    exit 0
fi

exit 1
