#!/bin/bash
set -euo pipefail

BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"
SUMMARY="$BASELINE_PKG/baselines/baseline_summary.json"
RULE_DIR="rules/sigma"
RUNNER="./3-sigma_runner.sh"
OUTPUT="fp_baseline.json"

START=$(jq -r '.baseline_window.start' "$SUMMARY")
END=$(jq -r '.baseline_window.end' "$SUMMARY")
DAYS=$(jq -r '.baseline_window.duration_days' "$SUMMARY")

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

RULE_COUNT=$(find "$RULE_DIR" -maxdepth 1 -name '*.yml' -type f | wc -l)

echo "evaluating $RULE_COUNT rules against baseline window ${START%%T*} -> ${END%%T*}"

for RULE in "$RULE_DIR"/*.yml; do
    RESULT=$("$RUNNER" "$RULE" --window "$START,$END")
    FP=$(printf '%s' "$RESULT" | jq '.match_count')
    ID=$(printf '%s' "$RESULT" | jq -r '.rule_id')
    TITLE=$(printf '%s' "$RESULT" | jq -r '.rule_title')
    LEVEL=$(printf '%s' "$RESULT" | jq -r '.level')

    RATE=$(awk -v fp="$FP" -v days="$DAYS" 'BEGIN {printf "%.2f", fp/days}')

    jq -n \
        --arg rule_id "$ID" \
        --arg rule_title "$TITLE" \
        --arg level "$LEVEL" \
        --argjson fp_count "$FP" \
        --arg window_start "$START" \
        --arg window_end "$END" \
        --argjson rate "$RATE" \
        '{
            rule_id: $rule_id,
            rule_title: $rule_title,
            level: $level,
            fp_count: $fp_count,
            baseline_window_start: $window_start,
            baseline_window_end: $window_end,
            fp_rate_per_day: $rate
        }' >> "$TMP"
done

jq -s '.' "$TMP" > "$OUTPUT"

jq -r 'sort_by(.fp_count) | reverse[] |
    "  \(.rule_title)  fp=\(.fp_count)" +
    (if .fp_count > 10 then "   [TUNE]" else "" end)' "$OUTPUT"

echo "fp_baseline.json written"
