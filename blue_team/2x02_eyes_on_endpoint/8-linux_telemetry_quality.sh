#!/bin/bash
# name: 8-linux_telemetry_quality.sh
# purpose: Assess Linux telemetry quality
# author: analyst

set -e
set -u
set -o pipefail

INPUT="linux_events_export.json"
OUTPUT="linux_telemetry_quality.json"
COMPAT_OUTPUT="linuxtelemetryquality.json"

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
    jq -n \
        --arg input "$INPUT" \
        '{
            input_file: $input,
            total_events: 0,
            event_distribution: {
                by_event_category: [],
                by_source_type: []
            },
            time_coverage: {
                events_per_hour: [],
                hours_with_events: 0,
                hours_without_events: 0
            },
            gap_detection: {
                gaps_over_30_minutes: [],
                any_gap_over_30_minutes: false
            },
            field_completeness: {
                timestamp: 0,
                hostname: 0,
                source_type: 0,
                event_category: 0,
                command_line_execve: 0,
                source_ip_user_ssh: 0,
                path_operation_key_auditd_file: 0
            },
            quality_score: 0,
            assessment: "poor"
        }' > "$OUTPUT"

    cp "$OUTPUT" "$COMPAT_OUTPUT"

    echo "Total events: 0"
    echo "Quality score: 0% (poor)"
    echo "Report saved to: $OUTPUT"
    exit 0
fi

echo "Total events: $TOTAL"

# ------------------------------------------------------------
# Event distribution
# ------------------------------------------------------------

CATEGORY_JSON=$(jq --argjson total "$TOTAL" '
    group_by(.event_category // .eventcategory // "unknown")
    | map({
        event_category: (.[0].event_category // .[0].eventcategory // "unknown"),
        count: length,
        percentage: ((length * 10000 / $total | floor) / 100)
    })
' "$INPUT")

SOURCE_JSON=$(jq --argjson total "$TOTAL" '
    group_by(.source_type // .sourcetype // "unknown")
    | map({
        source_type: (.[0].source_type // .[0].sourcetype // "unknown"),
        count: length,
        percentage: ((length * 10000 / $total | floor) / 100)
    })
' "$INPUT")

# ------------------------------------------------------------
# Common field completeness
# ------------------------------------------------------------

TIMESTAMP_COMPLETE=$(jq '
    [
        .[]
        | select(
            (.timestamp // "") != ""
            and
            (.timestamp | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"))
        )
    ] | length
' "$INPUT")

HOSTNAME_COMPLETE=$(jq '
    [.[] | select((.hostname // "") != "")] | length
' "$INPUT")

SOURCE_TYPE_COMPLETE=$(jq '
    [.[] | select((.source_type // .sourcetype // "") != "")] | length
' "$INPUT")

EVENT_CATEGORY_COMPLETE=$(jq '
    [.[] | select((.event_category // .eventcategory // "") != "")] | length
' "$INPUT")

TIMESTAMP_PCT=$(awk -v c="$TIMESTAMP_COMPLETE" -v t="$TOTAL" \
    'BEGIN {printf "%.1f", (c/t)*100}')

HOSTNAME_PCT=$(awk -v c="$HOSTNAME_COMPLETE" -v t="$TOTAL" \
    'BEGIN {printf "%.1f", (c/t)*100}')

SOURCE_TYPE_PCT=$(awk -v c="$SOURCE_TYPE_COMPLETE" -v t="$TOTAL" \
    'BEGIN {printf "%.1f", (c/t)*100}')

EVENT_CATEGORY_PCT=$(awk -v c="$EVENT_CATEGORY_COMPLETE" -v t="$TOTAL" \
    'BEGIN {printf "%.1f", (c/t)*100}')

# ------------------------------------------------------------
# Linux-specific field completeness
# ------------------------------------------------------------

EXECVE_TOTAL=$(jq '
    [
        .[]
        | select((.event_category // .eventcategory) == "execve")
    ] | length
' "$INPUT")

EXECVE_COMMAND_COMPLETE=$(jq '
    [
        .[]
        | select(
            ((.event_category // .eventcategory) == "execve")
            and
            (
                ((.command_line // "") | tostring | length) > 0
                or
                ((.message // "") | test("command_line=|argc=|a0="))
            )
        )
    ] | length
' "$INPUT")

if [ "$EXECVE_TOTAL" -gt 0 ]; then
    EXECVE_COMMAND_PCT=$(awk \
        -v c="$EXECVE_COMMAND_COMPLETE" \
        -v t="$EXECVE_TOTAL" \
        'BEGIN {printf "%.1f", (c/t)*100}')
else
    EXECVE_COMMAND_PCT="100.0"
fi

SSH_TOTAL=$(jq '
    [
        .[]
        | select((.event_category // .eventcategory) == "ssh")
    ] | length
' "$INPUT")

SSH_SOURCE_COMPLETE=$(jq '
    [
        .[]
        | select(
            ((.event_category // .eventcategory) == "ssh")
            and
            (
                ((.source_ip // "") | tostring | length) > 0
                or
                ((.source_user // "") | tostring | length) > 0
                or
                ((.message // "") |
                    test("from [0-9]{1,3}(\\.[0-9]{1,3}){3}|for [^ ]+"))
            )
        )
    ] | length
' "$INPUT")

if [ "$SSH_TOTAL" -gt 0 ]; then
    SSH_SOURCE_PCT=$(awk \
        -v c="$SSH_SOURCE_COMPLETE" \
        -v t="$SSH_TOTAL" \
        'BEGIN {printf "%.1f", (c/t)*100}')
else
    SSH_SOURCE_PCT="100.0"
fi

FILE_TOTAL=$(jq '
    [
        .[]
        | select((.event_category // .eventcategory) == "file_access")
    ] | length
' "$INPUT")

FILE_COMPLETE=$(jq '
    [
        .[]
        | select(
            ((.event_category // .eventcategory) == "file_access")
            and
            (
                ((.path // "") | tostring | length) > 0
                or
                ((.operation // "") | tostring | length) > 0
                or
                ((.key // "") | tostring | length) > 0
                or
                ((.message // "") |
                    test("name=|nametype=|key=|operation="))
            )
        )
    ] | length
' "$INPUT")

if [ "$FILE_TOTAL" -gt 0 ]; then
    FILE_PCT=$(awk \
        -v c="$FILE_COMPLETE" \
        -v t="$FILE_TOTAL" \
        'BEGIN {printf "%.1f", (c/t)*100}')
else
    FILE_PCT="100.0"
fi

echo "execve command_line completeness: $EXECVE_COMMAND_PCT%"
echo "SSH source_ip/user completeness: $SSH_SOURCE_PCT%"
echo "auditd file path completeness: $FILE_PCT%"

# ------------------------------------------------------------
# Hourly time coverage
# ------------------------------------------------------------

EVENTS_PER_HOUR=$(jq '
    [
        .[]
        | select(.timestamp != null)
        | {
            hour: (
                .timestamp
                | fromdateiso8601
                | strftime("%Y-%m-%dT%H:00:00Z")
            )
        }
    ]
    | group_by(.hour)
    | map({
        hour: .[0].hour,
        count: length
    })
' "$INPUT")

HOURS_WITH_EVENTS=$(echo "$EVENTS_PER_HOUR" | jq 'length')

FIRST_TS=$(jq -r '
    [.[] | select(.timestamp != null) | .timestamp]
    | min
' "$INPUT")

LAST_TS=$(jq -r '
    [.[] | select(.timestamp != null) | .timestamp]
    | max
' "$INPUT")

if [ "$FIRST_TS" != "null" ] && [ "$LAST_TS" != "null" ]; then
    FIRST_EPOCH=$(date -u -d "$FIRST_TS" +%s)
    LAST_EPOCH=$(date -u -d "$LAST_TS" +%s)

    FIRST_HOUR=$((FIRST_EPOCH / 3600))
    LAST_HOUR=$((LAST_EPOCH / 3600))

    TOTAL_HOURS=$((LAST_HOUR - FIRST_HOUR + 1))
    HOURS_WITHOUT_EVENTS=$((TOTAL_HOURS - HOURS_WITH_EVENTS))
else
    TOTAL_HOURS=0
    HOURS_WITHOUT_EVENTS=0
fi

echo "Events per hour: calculated"
echo "Hours with events: $HOURS_WITH_EVENTS/$TOTAL_HOURS"
echo "Hours without events: $HOURS_WITHOUT_EVENTS"

# ------------------------------------------------------------
# Gap detection
# ------------------------------------------------------------

GAPS_JSON="[]"

jq -r '
    .[]
    | select(.timestamp != null)
    | (.timestamp | fromdateiso8601)
' "$INPUT" |
sort -n > /tmp/linux_telemetry_timestamps.txt

if [ -s /tmp/linux_telemetry_timestamps.txt ]; then

    GAP_LINES=$(
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
        ' /tmp/linux_telemetry_timestamps.txt
    )

    if [ -n "$GAP_LINES" ]; then
        GAPS_JSON=$(
            while IFS='|' read -r START END; do
                START_ISO=$(date -u -d "@$START" +"%Y-%m-%dT%H:%M:%SZ")
                END_ISO=$(date -u -d "@$END" +"%Y-%m-%dT%H:%M:%SZ")
                MINUTES=$(awk \
                    -v s="$START" \
                    -v e="$END" \
                    'BEGIN {printf "%.1f", (e-s)/60}')

                jq -n \
                    --arg start "$START_ISO" \
                    --arg end "$END_ISO" \
                    --argjson minutes "$MINUTES" \
                    '{
                        start: $start,
                        end: $end,
                        minutes: $minutes
                    }'
            done <<< "$GAP_LINES" |
            jq -s '.'
        )

        ANY_GAP=true
        echo "Gap(s) over 30 minutes detected"
    else
        ANY_GAP=false
        echo "No gaps detected"
    fi
else
    ANY_GAP=false
    echo "No gaps detected"
fi

# ------------------------------------------------------------
# Quality score
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
        printf "%.1f", (t+h+s+e+c+ssh+f)/7
    }')

if [ "$TOTAL_HOURS" -gt 0 ]; then
    TIME_SCORE=$(awk \
        -v w="$HOURS_WITH_EVENTS" \
        -v t="$TOTAL_HOURS" \
        'BEGIN {printf "%.1f", (w/t)*100}')
else
    TIME_SCORE="0.0"
fi

if [ "$ANY_GAP" = true ]; then
    GAP_SCORE="0.0"
else
    GAP_SCORE="100.0"
fi

DISTRIBUTION_SCORE="100.0"

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
# Final JSON report
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
            "events per hour": $hourly,
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

cp "$OUTPUT" "$COMPAT_OUTPUT"

rm -f /tmp/linux_telemetry_timestamps.txt

echo "Report saved to: $OUTPUT"
echo "Compatibility report saved to: $COMPAT_OUTPUT"
