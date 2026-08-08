#!/bin/bash
# name: 8-linux_telemetry_quality.sh
# purpose: Assess Linux telemetry quality
# author: analyst

set -e
set -u
set -o pipefail

INPUT="linux_events_export.json"
OUTPUT="linux_telemetry_quality.json"

echo "[*] Analyzing $INPUT..."

if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: jq is required."
    exit 1
fi

if [ ! -r "$INPUT" ]; then
    echo "ERROR: $INPUT not found or not readable."
    exit 1
fi

if ! jq -e 'type == "array"' "$INPUT" >/dev/null 2>&1; then
    echo "ERROR: $INPUT is not a valid JSON array."
    exit 1
fi

TOTAL=$(jq 'length' "$INPUT")

if [ "$TOTAL" -eq 0 ]; then
    cat > "$OUTPUT" <<EOF
{
  "input_file": "$INPUT",
  "total_events": 0,
  "event_distribution": {
    "by_event_category": [],
    "by_source_type": []
  },
  "time_coverage": {
    "events_per_hour": [],
    "hours_with_events": 0,
    "hours_without_events": 0
  },
  "gap_detection": {
    "gaps_over_30_minutes": [],
    "any_gap_over_30_minutes": false
  },
  "field_completeness": {
    "timestamp": 0,
    "hostname": 0,
    "source_type": 0,
    "event_category": 0,
    "command_line_execve": 0,
    "source_ip_user_ssh": 0,
    "path_operation_key_auditd_file": 0
  },
  "quality_score": 0,
  "assessment": "poor"
}
EOF

    echo "Total events: 0"
    echo "Quality score: 0% (poor)"
    echo "Report saved to: $OUTPUT"
    exit 0
fi

echo "Total events: $TOTAL"

# ------------------------------------------------------------
# Event distribution
# ------------------------------------------------------------

CATEGORY_JSON=$(jq '
    group_by(.event_category // .eventcategory // "unknown")
    | map({
        event_category: (.[0].event_category // .[0].eventcategory // "unknown"),
        count: length,
        percentage: ((length * 10000 / ($total // 1) | floor) / 100)
    })
' --argjson total "$TOTAL" "$INPUT")

SOURCE_JSON=$(jq '
    group_by(.source_type // .sourcetype // "unknown")
    | map({
        source_type: (.[0].source_type // .[0].sourcetype // "unknown"),
        count: length,
        percentage: ((length * 10000 / ($total // 1) | floor) / 100)
    })
' --argjson total "$TOTAL" "$INPUT")

# ------------------------------------------------------------
# Timestamp and field completeness
# ------------------------------------------------------------

TIMESTAMP_COMPLETE=$(jq '
    [ .[] | select(
        (.timestamp // "") != "" and
        (.timestamp | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"))
    ) ] | length
' "$INPUT")

HOSTNAME_COMPLETE=$(jq '
    [ .[] | select((.hostname // "") != "") ] | length
' "$INPUT")

SOURCE_TYPE_COMPLETE=$(jq '
    [ .[] | select((.source_type // .sourcetype // "") != "") ] | length
' "$INPUT")

EVENT_CATEGORY_COMPLETE=$(jq '
    [ .[] | select((.event_category // .eventcategory // "") != "") ] | length
' "$INPUT")

TIMESTAMP_PCT=$(awk -v c="$TIMESTAMP_COMPLETE" -v t="$TOTAL" 'BEGIN {printf "%.1f", (c/t)*100}')
HOSTNAME_PCT=$(awk -v c="$HOSTNAME_COMPLETE" -v t="$TOTAL" 'BEGIN {printf "%.1f", (c/t)*100}')
SOURCE_TYPE_PCT=$(awk -v c="$SOURCE_TYPE_COMPLETE" -v t="$TOTAL" 'BEGIN {printf "%.1f", (c/t)*100}')
EVENT_CATEGORY_PCT=$(awk -v c="$EVENT_CATEGORY_COMPLETE" -v t="$TOTAL" 'BEGIN {printf "%.1f", (c/t)*100}')

# ------------------------------------------------------------
# Execve command line completeness
# ------------------------------------------------------------

EXECVE_TOTAL=$(jq '
    [ .[] | select(
        ((.event_category // .eventcategory) == "execve")
    ) ] | length
' "$INPUT")

EXECVE_COMMAND_COMPLETE=$(jq '
    [ .[] | select(
        ((.event_category // .eventcategory) == "execve")
        and (
            ((.command_line // "") | tostring | length) > 0
            or
            ((.message // "") | test("command_line=|argc=|a0="))
        )
    ) ] | length
' "$INPUT")

if [ "$EXECVE_TOTAL" -gt 0 ]; then
    EXECVE_COMMAND_PCT=$(awk -v c="$EXECVE_COMMAND_COMPLETE" -v t="$EXECVE_TOTAL" 'BEGIN {printf "%.1f", (c/t)*100}')
else
    EXECVE_COMMAND_PCT=100.0
fi

# ------------------------------------------------------------
# SSH source IP / user completeness
# ------------------------------------------------------------

SSH_TOTAL=$(jq '
    [ .[] | select(
        ((.event_category // .eventcategory) == "ssh")
    ) ] | length
' "$INPUT")

SSH_SOURCE_COMPLETE=$(jq '
    [ .[] | select(
        ((.event_category // .eventcategory) == "ssh")
        and (
            (
                ((.source_ip // "") | tostring | length) > 0
                or
                ((.source_user // "") | tostring | length) > 0
            )
            or
            ((.message // "") | test("from [0-9]{1,3}(\\.[0-9]{1,3}){3}|for [^ ]+"))
        )
    ) ] | length
' "$INPUT")

if [ "$SSH_TOTAL" -gt 0 ]; then
    SSH_SOURCE_PCT=$(awk -v c="$SSH_SOURCE_COMPLETE" -v t="$SSH_TOTAL" 'BEGIN {printf "%.1f", (c/t)*100}')
else
    SSH_SOURCE_PCT=100.0
fi

# ------------------------------------------------------------
# Auditd file path / operation / key completeness
# ------------------------------------------------------------

FILE_TOTAL=$(jq '
    [ .[] | select(
        ((.event_category // .eventcategory) == "file_access")
    ) ] | length
' "$INPUT")

FILE_COMPLETE=$(jq '
    [ .[] | select(
        ((.event_category // .eventcategory) == "file_access")
        and (
            ((.path // "") | tostring | length) > 0
            or ((.operation // "") | tostring | length) > 0
            or ((.key // "") | tostring | length) > 0
            or ((.message // "") | test("name=|nametype=|key=|operation="))
        )
    ) ] | length
' "$INPUT")

if [ "$FILE_TOTAL" -gt 0 ]; then
    FILE_PCT=$(awk -v c="$FILE_COMPLETE" -v t="$FILE_TOTAL" 'BEGIN {printf "%.1f", (c/t)*100}')
else
    FILE_PCT=100.0
fi

echo "execve command_line completeness: $EXECVE_COMMAND_PCT%"
echo "SSH source_ip/user completeness: $SSH_SOURCE_PCT%"
echo "auditd file path completeness: $FILE_PCT%"

# ------------------------------------------------------------
# Time coverage
# ------------------------------------------------------------

jq -r '
    .[]
    | select(.timestamp != null)
    | .timestamp
' "$INPUT" |
while IFS= read -r ts; do
    date -u -d "$ts" +%s 2>/dev/null || true
done |
sort -n > /tmp/linux_telemetry_timestamps.txt

FIRST_TS=$(head -n 1 /tmp/linux_telemetry_timestamps.txt || true)
LAST_TS=$(tail -n 1 /tmp/linux_telemetry_timestamps.txt || true)

HOURS_WITH_EVENTS=$(jq '
    [
        .[]
        | select(.timestamp != null)
        | (.timestamp | fromdateiso8601)
        | strftime("%Y-%m-%dT%H:00:00Z")
    ]
    | unique
    | length
' "$INPUT")

if [ -n "$FIRST_TS" ] && [ -n "$LAST_TS" ]; then
    FIRST_HOUR=$((FIRST_TS / 3600))
    LAST_HOUR=$((LAST_TS / 3600))
    HOURS_IN_RANGE=$((LAST_HOUR - FIRST_HOUR + 1))
    HOURS_WITHOUT_EVENTS=$((HOURS_IN_RANGE - HOURS_WITH_EVENTS))
else
    HOURS_IN_RANGE=0
    HOURS_WITHOUT_EVENTS=0
fi

echo "Hours with events: $HOURS_WITH_EVENTS/$HOURS_IN_RANGE"

EVENTS_PER_HOUR=$(jq '
    [
        .[]
        | select(.timestamp != null)
        | {
            hour: (.timestamp | fromdateiso8601 | strftime("%Y-%m-%dT%H:00:00Z"))
        }
    ]
    | group_by(.hour)
    | map({
        hour: .[0].hour,
        count: length
    })
' "$INPUT")

# ------------------------------------------------------------
# Gap detection: periods longer than 30 minutes
# ------------------------------------------------------------

GAPS_JSON="[]"

if [ -s /tmp/linux_telemetry_timestamps.txt ]; then
    GAPS_JSON=$(
        awk '
        NR == 1 {
            previous = $1
            next
        }

        {
            gap = $1 - previous

            if (gap > 1800) {
                printf "%s|%s\n", previous, $1
            }

            previous = $1
        }
        ' /tmp/linux_telemetry_timestamps.txt |
        while IFS='|' read -r START END; do
            [ -z "$START" ] && continue

            START_ISO=$(date -u -d "@$START" +"%Y-%m-%dT%H:%M:%SZ")
            END_ISO=$(date -u -d "@$END" +"%Y-%m-%dT%H:%M:%SZ")
            GAP_MINUTES=$(awk -v s="$START" -v e="$END" 'BEGIN {printf "%.1f", (e-s)/60}')

            jq -n \
                --arg start "$START_ISO" \
                --arg end "$END_ISO" \
                --argjson minutes "$GAP_MINUTES" \
                '{
                    start: $start,
                    end: $end,
                    minutes: $minutes
                }'
        done |
        jq -s '.'
    )
fi

if [ "$GAPS_JSON" = "[]" ]; then
    ANY_GAP=false
    echo "No gaps detected"
else
    ANY_GAP=true
    echo "Gap(s) over 30 minutes detected"
fi

# ------------------------------------------------------------
# Quality score
#
# Field completeness = 50%
# Time coverage      = 20%
# Gap detection      = 20%
# Distribution       = 10%
# ------------------------------------------------------------

FIELD_SCORE=$(awk \
    -v t="$TIMESTAMP_PCT" \
    -v h="$HOSTNAME_PCT" \
    -v s="$SOURCE_TYPE_PCT" \
    -v e="$EVENT_CATEGORY_PCT" \
    -v c="$EXECVE_COMMAND_PCT" \
    -v ssh="$SSH_SOURCE_PCT" \
    -v f="$FILE_PCT" \
    'BEGIN {
        print (t+h+s+e+c+ssh+f)/7
    }')

if [ "$HOURS_IN_RANGE" -gt 0 ]; then
    TIME_SCORE=$(awk -v w="$HOURS_WITH_EVENTS" -v t="$HOURS_IN_RANGE" \
        'BEGIN {print (w/t)*100}')
else
    TIME_SCORE=0
fi

if [ "$ANY_GAP" = true ]; then
    GAP_SCORE=0
else
    GAP_SCORE=100
fi

if [ "$TOTAL" -gt 0 ]; then
    DISTRIBUTION_SCORE=100
else
    DISTRIBUTION_SCORE=0
fi

QUALITY_SCORE=$(awk \
    -v f="$FIELD_SCORE" \
    -v t="$TIME_SCORE" \
    -v g="$GAP_SCORE" \
    -v d="$DISTRIBUTION_SCORE" \
    'BEGIN {
        printf "%.1f", (f*0.50)+(t*0.20)+(g*0.20)+(d*0.10)
    }')

if awk -v s="$QUALITY_SCORE" 'BEGIN {exit !(s >= 80)}'; then
    ASSESSMENT="good"
elif awk -v s="$QUALITY_SCORE" 'BEGIN {exit !(s >= 60)}'; then
    ASSESSMENT="acceptable"
else
    ASSESSMENT="poor"
fi

echo "Quality score: $QUALITY_SCORE% ($ASSESSMENT)"

# ------------------------------------------------------------
# Build final JSON report
# ------------------------------------------------------------

jq -n \
    --arg input "$INPUT" \
    --argjson total "$TOTAL" \
    --argjson categories "$CATEGORY_JSON" \
    --argjson sources "$SOURCE_JSON" \
    --argjson hourly "$EVENTS_PER_HOUR" \
    --argjson hours_with "$HOURS_WITH_EVENTS" \
    --argjson hours_without "$HOURS_WITHOUT_EVENTS" \
    --argjson gaps "$GAPS_JSON" \
    --argjson any_gap "$ANY_GAP" \
    --argjson timestamp "$TIMESTAMP_PCT" \
    --argjson hostname "$HOSTNAME_PCT" \
    --argjson source_type "$SOURCE_TYPE_PCT" \
    --argjson event_category "$EVENT_CATEGORY_PCT" \
    --argjson command_line "$EXECVE_COMMAND_PCT" \
    --argjson ssh_source "$SSH_SOURCE_PCT" \
    --argjson file_fields "$FILE_PCT" \
    --argjson score "$QUALITY_SCORE" \
    --arg assessment "$ASSESSMENT" \
    '{
        input_file: $input,
        total_events: $total,

        event_distribution: {
            by_event_category: $categories,
            by_source_type: $sources
        },

        time_coverage: {
            events_per_hour: $hourly,
            hours_with_events: $hours_with,
            hours_without_events: $hours_without
        },

        gap_detection: {
            gaps_over_30_minutes: $gaps,
            any_gap_over_30_minutes: $any_gap
        },

        field_completeness: {
            timestamp: $timestamp,
            hostname: $hostname,
            source_type: $source_type,
            event_category: $event_category,
            command_line_execve: $command_line,
            source_ip_user_ssh: $ssh_source,
            path_operation_key_auditd_file: $file_fields
        },

        quality_score: $score,
        assessment: $assessment
    }' > "$OUTPUT"

rm -f /tmp/linux_telemetry_timestamps.txt

echo "Report saved to: $OUTPUT"
