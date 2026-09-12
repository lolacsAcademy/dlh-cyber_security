#!/bin/bash
set -euo pipefail

PIPELINE_RUN="$SHIFT_WORKSPACE/runtime/pipeline_run.json"
BASELINE_OUT="$SHIFT_WORKSPACE/enriched/baseline.json"
RUN_OUT="$SHIFT_WORKSPACE/runtime/baseline_run.json"

[ -s "$PIPELINE_RUN" ] || exit 1
[ "$(jq -r '.exit_status' "$PIPELINE_RUN")" = "0" ] || exit 1

echo "[baseline] pipeline check: OK"

if [ -s "$SHIFT_WORKSPACE/enriched/enriched_events.jsonl" ]; then
    INPUT="$SHIFT_WORKSPACE/enriched/enriched_events.jsonl"
else
    INPUT="$SHIFT_WORKSPACE/enriched/enriched_events.json"
fi

[ -s "$INPUT" ] || exit 1

STARTED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "[baseline] invoking $BASELINE_BIN"
echo "[baseline] input: $INPUT"
echo "[baseline] output: $BASELINE_OUT"

"$BASELINE_BIN" "$INPUT" "$BASELINE_OUT"

[ -s "$BASELINE_OUT" ] || exit 1

HOSTS_TOTAL=$(jq '.hosts | map(.host) | unique | length' "$BASELINE_OUT")
[ "$HOSTS_TOTAL" -gt 0 ] || exit 1

HOSTS_WITH_DEVIATIONS=$(jq '
  [.deviation_markers[].host] | unique | length
' "$BASELINE_OUT")

HOT_HOSTS=$(jq '
  [.deviation_markers]
  | flatten
  | group_by(.host)
  | map({
      host: .[0].host,
      score: (map(.deviation_score) | add)
    })
  | sort_by(-.score)
  | .[:5]
  | map(.host)
' "$BASELINE_OUT")

echo "[baseline] hosts processed: $HOSTS_TOTAL"
echo "[baseline] hosts with deviations: $HOSTS_WITH_DEVIATIONS"
echo "[baseline] hot hosts: $(echo "$HOT_HOSTS" | jq -r 'join(" ")')"

echo "$HOT_HOSTS" | jq -r '.[]' | while read -r host; do
    SCORE=$(jq --arg h "$host" '
      [.deviation_markers[]
       | select(.host == $h)
       | .deviation_score] | add
    ' "$BASELINE_OUT")
    echo "[baseline] $host score=$SCORE"
done

MARKERS_TOTAL=$(jq '.deviation_markers | length' "$BASELINE_OUT")
UNSEEN=$(jq '[.deviation_markers[] | select(.marker=="unseen_src_ip")] | length' "$BASELINE_OUT")
OFFHOURS=$(jq '[.deviation_markers[] | select(.marker=="off_hours_login")] | length' "$BASELINE_OUT")
NEW_SERVICE=$(jq '[.deviation_markers[] | select(.marker=="new_service")] | length' "$BASELINE_OUT")

echo "[baseline] markers: $MARKERS_TOTAL total (unseen_src_ip: $UNSEEN  off_hours: $OFFHOURS  new_service: $NEW_SERVICE)"

ENDED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
VERSION=$(jq -r '.baseline_version' "$BASELINE_OUT")

jq -n \
  --arg version "$VERSION" \
  --argjson total "$HOSTS_TOTAL" \
  --argjson deviations "$HOSTS_WITH_DEVIATIONS" \
  --argjson markers "$(jq '.deviation_markers' "$BASELINE_OUT")" \
  --argjson hot "$HOT_HOSTS" \
  --arg started "$STARTED_AT" \
  --arg ended "$ENDED_AT" \
'{
  baseline_version: $version,
  hosts_total: $total,
  hosts_with_deviations: $deviations,
  deviation_markers: $markers,
  hot_hosts: $hot,
  started_at: $started,
  ended_at: $ended,
  exit_status: 0
}' > "$RUN_OUT"

echo "[baseline] baseline_run.json written"
