#!/bin/bash
set -uo pipefail

WIN_FILE="maintenance_windows.json"
OUT="maintenance_window.json"

MODE="${1:---check}"
WAIT_SECONDS="${2:-0}"

TZ_NAME=$(jq -r '.timezone' "$WIN_FILE")

check_window() {
    local now_epoch now_day now_hm now_dom week_of_month
    now_epoch=$(TZ="$TZ_NAME" date +%s)
    now_day=$(TZ="$TZ_NAME" date -d "@$now_epoch" +%a)
    now_hm=$(TZ="$TZ_NAME" date -d "@$now_epoch" +%H:%M)
    now_dom=$(TZ="$TZ_NAME" date -d "@$now_epoch" +%d)
    week_of_month=$(( (10#$now_dom - 1) / 7 + 1 ))

    ACTIVE_NAME=""
    ACTIVE_TYPE="none"

    local win_count
    win_count=$(jq '.windows | length' "$WIN_FILE")
    local i=0
    while [ "$i" -lt "$win_count" ]; do
        local w always name days start end wom
        w=$(jq -c ".windows[$i]" "$WIN_FILE")
        always=$(echo "$w" | jq -r '.always // false')
        name=$(echo "$w" | jq -r '.name')

        if [ "$always" = "true" ]; then
            if [ "$ACTIVE_NAME" = "" ]; then
                ACTIVE_NAME="$name"
                ACTIVE_TYPE="emergency"
            fi
            i=$((i+1))
            continue
        fi

        days=$(echo "$w" | jq -r '.days[]' 2>/dev/null)
        start=$(echo "$w" | jq -r '.start')
        end=$(echo "$w" | jq -r '.end')
        wom=$(echo "$w" | jq -r '.week_of_month // empty')

        if echo "$days" | grep -qxF "$now_day"; then
            if [ -z "$wom" ] || [ "$wom" = "$week_of_month" ]; then
                if [[ "$now_hm" > "$start" || "$now_hm" == "$start" ]] && [[ "$now_hm" < "$end" ]]; then
                    ACTIVE_NAME="$name"
                    ACTIVE_TYPE="normal"
                fi
            fi
        fi
        i=$((i+1))
    done

    echo "$now_epoch|$now_day|$now_hm|$ACTIVE_NAME|$ACTIVE_TYPE"
}

# Find the next upcoming "standard" window (nearest future Saturday 02:00)
find_next_window() {
    local now_epoch="$1"
    local now_date now_dow target_dow days_ahead candidate_date candidate_epoch

    now_date=$(TZ="$TZ_NAME" date -d "@$now_epoch" +%Y-%m-%d)
    now_dow=$(TZ="$TZ_NAME" date -d "@$now_epoch" +%u)  # 1=Mon .. 7=Sun
    target_dow=6  # Saturday

    days_ahead=$(( (target_dow - now_dow + 7) % 7 ))
    candidate_date=$(TZ="$TZ_NAME" date -d "$now_date +$days_ahead days" +%Y-%m-%d)
    candidate_epoch=$(TZ="$TZ_NAME" date -d "$candidate_date 02:00" +%s)

    if [ "$candidate_epoch" -le "$now_epoch" ]; then
        candidate_date=$(TZ="$TZ_NAME" date -d "$now_date +$((days_ahead+7)) days" +%Y-%m-%d)
        candidate_epoch=$(TZ="$TZ_NAME" date -d "$candidate_date 02:00" +%s)
    fi

    echo "standard|$candidate_epoch"
}

RESULT=$(check_window)
NOW_EPOCH=$(echo "$RESULT" | cut -d'|' -f1)
NOW_DAY=$(echo "$RESULT" | cut -d'|' -f2)
ACTIVE_NAME=$(echo "$RESULT" | cut -d'|' -f4)
ACTIVE_TYPE=$(echo "$RESULT" | cut -d'|' -f5)

NOW_DISPLAY=$(TZ="$TZ_NAME" date -d "@$NOW_EPOCH" "+%Y-%m-%d %H:%M")

NEXT_RESULT=$(find_next_window "$NOW_EPOCH")
NEXT_NAME=$(echo "$NEXT_RESULT" | cut -d'|' -f1)
NEXT_EPOCH=$(echo "$NEXT_RESULT" | cut -d'|' -f2)
NEXT_ISO=$(TZ="$TZ_NAME" date -d "@$NEXT_EPOCH" "+%Y-%m-%dT%H:%M:%S")
SECONDS_UNTIL=$((NEXT_EPOCH - NOW_EPOCH))

DECISION="defer"
EXIT_CODE=20

if [ "$ACTIVE_TYPE" = "normal" ]; then
    DECISION="proceed"
    EXIT_CODE=0
elif [ "$ACTIVE_TYPE" = "emergency" ]; then
    if [ "${MEDDEFENSE_EMERGENCY:-0}" = "1" ]; then
        DECISION="proceed (emergency override)"
        EXIT_CODE=10
    else
        DECISION="defer (emergency window requires MEDDEFENSE_EMERGENCY=1)"
        EXIT_CODE=10
    fi
fi

if [ "$MODE" = "--wait" ]; then
    elapsed=0
    while [ "$EXIT_CODE" -eq 20 ] && [ "$elapsed" -lt "$WAIT_SECONDS" ]; do
        sleep 5
        elapsed=$((elapsed+5))
        RESULT=$(check_window)
        ACTIVE_TYPE=$(echo "$RESULT" | cut -d'|' -f5)
        if [ "$ACTIVE_TYPE" = "normal" ]; then
            DECISION="proceed"
            EXIT_CODE=0
        fi
    done
fi

ACTIVE_JSON="null"
[ -n "$ACTIVE_NAME" ] && ACTIVE_JSON="\"$ACTIVE_NAME\""

jq -n --arg now "$NOW_DISPLAY" --arg tz "$TZ_NAME" --argjson active "$ACTIVE_JSON" \
    --arg next_name "$NEXT_NAME" --arg next_iso "$NEXT_ISO" --argjson seconds "$SECONDS_UNTIL" \
    --arg decision "$DECISION" \
    '{now:$now, timezone:$tz, active_window:$active, next_window:{name:$next_name, at:$next_iso}, seconds_until_next:$seconds, decision:$decision}' > "$OUT"

if [ "$MODE" != "--report" ]; then
    echo "now:            $NOW_DISPLAY $TZ_NAME ($NOW_DAY)"
    if [ -n "$ACTIVE_NAME" ]; then
        echo "active window:  $ACTIVE_NAME"
    else
        echo "active window:  (none)"
        echo "next window:    $NEXT_NAME  at $NEXT_ISO"
        echo "seconds until:  $SECONDS_UNTIL"
    fi
    echo "decision:       $DECISION"
fi
echo "Report saved to: $OUT"

exit $EXIT_CODE
