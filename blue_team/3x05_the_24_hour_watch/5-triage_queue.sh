#!/bin/bash
set -euo pipefail

QUEUE="$SHIFT_WORKSPACE/alerts/alert_queue.json"
BRIEFING="$SHIFT_WORKSPACE/alerts/shift_briefing.json"
BASELINE="$SHIFT_WORKSPACE/enriched/baseline.json"
ASSETS="$ASSETS_DIR/assets.json"
LOG="$SHIFT_WORKSPACE/alerts/triage_log.jsonl"

for file in "$QUEUE" "$BRIEFING" "$BASELINE" "$ASSETS"; do
    if [ ! -f "$file" ]; then
        echo "[triage] missing required file: $file" >&2
        exit 1
    fi
done

ALERT_COUNT=$(jq 'length' "$QUEUE")
IOC_COUNT=$(jq '.ioc_count' "$BRIEFING")
TICKET_COUNT=$(jq '.active_change_tickets | length' "$BRIEFING")

echo "[triage] alert_queue: $ALERT_COUNT alerts"
echo "[triage] briefing loaded ($IOC_COUNT IOCs, $TICKET_COUNT change tickets)"
echo "[triage] invoking $TRIAGE_BIN"

CATALOG_DIR="$SHIFT_WORKSPACE" \
HANDOFF_DIR="$SHIFT_WORKSPACE" \
BASELINE_PKG="$SHIFT_WORKSPACE/enriched" \
ASSETS_DIR="$ASSETS_DIR" \
"$TRIAGE_BIN"

SOURCE="$HOME/bt/3x03/triage/work/triage_log.jsonl"

if [ ! -f "$SOURCE" ]; then
    echo "[triage] triage output not produced" >&2
    exit 1
fi

cp "$SOURCE" "$LOG"

echo "[triage] classifying $ALERT_COUNT alerts"

TP=$(jq -s '[.[] | select(.classification == "TP")] | length' "$LOG")
FP=$(jq -s '[.[] | select(.classification == "FP")] | length' "$LOG")
NOISE=$(jq -s '[.[] | select(.classification == "NOISE")] | length' "$LOG")
CLASSIFIED=$(jq -s 'length' "$LOG")
UNCLASSIFIED=$((ALERT_COUNT - CLASSIFIED))

echo "[triage] TP=$TP FP=$FP NOISE=$NOISE unclassified=$UNCLASSIFIED"

if [ "$UNCLASSIFIED" -ne 0 ]; then
    exit 1
fi

echo "[triage] triage_log.jsonl written"
