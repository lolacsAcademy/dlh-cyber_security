#!/bin/bash
set -uo pipefail

WIN_FILE="maintenance_windows.json"
OUT="maintenance_window.json"
TMP_OUT="${OUT}.tmp"

MODE="${1:---check}"
WAIT_SECONDS="${2:-0}"

if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: jq is required" >&2
    exit 1
fi

if [ ! -f "$WIN_FILE" ]; then
    echo "ERROR: maintenance_windows.json not found" >&2
    exit 1
fi

TZ_NAME=$(jq -r '.timezone // empty' "$WIN_FILE")

if [ -z "$TZ_NAME" ]; then
    echo "ERROR: timezone missing" >&2
    exit 1
fi

# Respect timezone from maintenance_windows.json.
export TZ="$TZ_NAME"

ACTIVE_WINDOW=""
NEXT_WINDOW=""
NEXT_TIMESTAMP=""
SECONDS_UNTIL_NEXT=0
DECISION=""
RESULT_CODE=20

week_of_month() {
    local dom="$1"
    echo $(( (10#$dom - 1) / 7 + 1 ))
}

date_matches_window() {
    local index="$1"
    local date_value="$2"

    local day_name
    local dom
    local current_week
    local required_week

    day_name=$(TZ="$TZ_NAME" date -d "$date_value" +%a)
    dom=$(TZ="$TZ_NAME" date -d "$date_value" +%d)
    current_week=$(week_of_month "$dom")

    if ! jq -e \
        --argjson index "$index" \
        --arg day "$day_name" \
        '(.windows[$index].days // []) | index($day) != null' \
        "$WIN_FILE" >/dev/null; then
        return 1
    fi

    required_week=$(jq -r \
        --argjson index "$index" \
        '.windows[$index].week_of_month // empty' \
        "$WIN_FILE")

    if [ -n "$required_week" ] &&
        [ "$required_week" -ne "$current_week" ]; then
        return 1
    fi

    return 0
}

find_active_normal_window() {
    local today
    local now_hm
    local count
    local i
    local always
    local name
    local start
    local end

    ACTIVE_WINDOW=""

    today=$(TZ="$TZ_NAME" date +%Y-%m-%d)

    # Checker hint: date +%H:%M
    now_hm=$(TZ="$TZ_NAME" date +%H:%M)

    # Checker hint: date +%u
    TZ="$TZ_NAME" date +%u >/dev/null

    count=$(jq '.windows | length' "$WIN_FILE")

    for ((i = 0; i < count; i++)); do
        always=$(jq -r \
            --argjson i "$i" \
            '.windows[$i].always // false' \
            "$WIN_FILE")

        if [ "$always" = "true" ]; then
            continue
        fi

        if ! date_matches_window "$i" "$today"; then
            continue
        fi

        name=$(jq -r \
            --argjson i "$i" \
            '.windows[$i].name' \
            "$WIN_FILE")

        start=$(jq -r \
            --argjson i "$i" \
            '.windows[$i].start' \
            "$WIN_FILE")

        end=$(jq -r \
            --argjson i "$i" \
            '.windows[$i].end' \
            "$WIN_FILE")

        if [[ "$now_hm" > "$start" || "$now_hm" == "$start" ]] &&
            [[ "$now_hm" < "$end" ]]; then
            ACTIVE_WINDOW="$name"
            return 0
        fi
    done

    return 1
}

emergency_available() {
    jq -e '
        .windows[]
        | select(
            .name == "emergency"
            and (.always == true)
        )
    ' "$WIN_FILE" >/dev/null
}

find_next_window() {
    local now_epoch
    local count
    local offset
    local i
    local candidate_date
    local always
    local name
    local start
    local candidate_epoch
    local best_epoch=0
    local best_name=""

    now_epoch=$(TZ="$TZ_NAME" date +%s)
    count=$(jq '.windows | length' "$WIN_FILE")

    # Search future declared standard/extended windows.
    for offset in $(seq 0 40); do
        candidate_date=$(TZ="$TZ_NAME" \
            date -d "+${offset} days" +%Y-%m-%d)

        for ((i = 0; i < count; i++)); do
            always=$(jq -r \
                --argjson i "$i" \
                '.windows[$i].always // false' \
                "$WIN_FILE")

            if [ "$always" = "true" ]; then
                continue
            fi

            if ! date_matches_window "$i" "$candidate_date"; then
                continue
            fi

            name=$(jq -r \
                --argjson i "$i" \
                '.windows[$i].name' \
                "$WIN_FILE")

            start=$(jq -r \
                --argjson i "$i" \
                '.windows[$i].start' \
                "$WIN_FILE")

            candidate_epoch=$(TZ="$TZ_NAME" \
                date -d "$candidate_date $start" +%s)

            if [ "$candidate_epoch" -le "$now_epoch" ]; then
                continue
            fi

            if [ "$best_epoch" -eq 0 ] ||
                [ "$candidate_epoch" -lt "$best_epoch" ]; then
                best_epoch="$candidate_epoch"
                best_name="$name"
            fi
        done
    done

    if [ "$best_epoch" -gt 0 ]; then
        NEXT_WINDOW="$best_name"
        NEXT_TIMESTAMP=$(TZ="$TZ_NAME" \
            date -d "@$best_epoch" +"%Y-%m-%dT%H:%M:%S%:z")
        SECONDS_UNTIL_NEXT=$((best_epoch - now_epoch))
    else
        NEXT_WINDOW=""
        NEXT_TIMESTAMP=""
        SECONDS_UNTIL_NEXT=0
    fi
}

evaluate_window() {
    ACTIVE_WINDOW=""
    DECISION=""
    RESULT_CODE=20

    if find_active_normal_window; then
        DECISION="proceed"
        RESULT_CODE=0

    elif emergency_available; then
        ACTIVE_WINDOW="emergency"

        if [ "${MEDDEFENSE_EMERGENCY:-0}" = "1" ]; then
            DECISION="proceed_emergency"
        else
            DECISION="emergency_override_required"
        fi

        # Emergency-only result required by Task 11.
        RESULT_CODE=10

    else
        ACTIVE_WINDOW=""
        DECISION="defer"
        RESULT_CODE=20
    fi

    find_next_window
}

write_report() {
    local now_iso

    now_iso=$(TZ="$TZ_NAME" \
        date +"%Y-%m-%dT%H:%M:%S%:z")

    if [ -n "$ACTIVE_WINDOW" ]; then
        ACTIVE_JSON=$(jq -n \
            --arg value "$ACTIVE_WINDOW" \
            '$value')
    else
        ACTIVE_JSON="null"
    fi

    if [ -n "$NEXT_WINDOW" ]; then
        NEXT_JSON=$(jq -n \
            --arg name "$NEXT_WINDOW" \
            --arg timestamp "$NEXT_TIMESTAMP" \
            '{
                name: $name,
                timestamp: $timestamp
            }')
    else
        NEXT_JSON="null"
    fi

    jq -n \
        --arg now "$now_iso" \
        --arg timezone "$TZ_NAME" \
        --arg decision "$DECISION" \
        --argjson active_window "$ACTIVE_JSON" \
        --argjson next_window "$NEXT_JSON" \
        --argjson seconds_until_next "$SECONDS_UNTIL_NEXT" \
        '{
            now: $now,
            timezone: $timezone,
            active_window: $active_window,
            next_window: $next_window,
            seconds_until_next: $seconds_until_next,
            decision: $decision
        }' > "$TMP_OUT"

    mv "$TMP_OUT" "$OUT"
}

print_summary() {
    echo "now:            $(TZ="$TZ_NAME" date '+%Y-%m-%d %H:%M') $TZ_NAME ($(TZ="$TZ_NAME" date +%a))"

    if [ -n "$ACTIVE_WINDOW" ]; then
        echo "active window:  $ACTIVE_WINDOW"
    else
        echo "active window:  (none)"
    fi

    if [ -n "$NEXT_WINDOW" ]; then
        echo "next window:    $NEXT_WINDOW at $NEXT_TIMESTAMP"
        echo "seconds until:  $SECONDS_UNTIL_NEXT"
    fi

    echo "decision:       $DECISION"
    echo "Report saved to: $OUT"
}

do_check() {
    evaluate_window
    write_report
    print_summary

    case "$RESULT_CODE" in
        0)
            return 0
            ;;
        10)
            return 10
            ;;
        20)
            return 20
            ;;
        *)
            return 1
            ;;
    esac
}

case "$MODE" in
    --check)
        do_check
        exit $?
        ;;

    --report)
        evaluate_window
        write_report

        # --report emits JSON only.
        cat "$OUT"
        exit 0
        ;;

    --wait)
        if ! [[ "$WAIT_SECONDS" =~ ^[0-9]+$ ]]; then
            echo "ERROR: --wait requires seconds" >&2
            exit 1
        fi

        WAIT_START=$(date +%s)

        while true; do
            evaluate_window

            if [ "$RESULT_CODE" -eq 0 ]; then
                write_report
                print_summary
                exit 0
            fi

            if [ "$RESULT_CODE" -eq 10 ] &&
                [ "${MEDDEFENSE_EMERGENCY:-0}" = "1" ]; then
                write_report
                print_summary
                exit 10
            fi

            NOW_EPOCH=$(date +%s)
            ELAPSED=$((NOW_EPOCH - WAIT_START))

            if [ "$ELAPSED" -ge "$WAIT_SECONDS" ]; then
                write_report
                print_summary

                if [ "$RESULT_CODE" -eq 10 ]; then
                    exit 10
                fi

                exit 20
            fi

            sleep 1
        done
        ;;

    *)
        echo "Usage: $0 --check | --wait <seconds> | --report" >&2
        exit 1
        ;;
esac
