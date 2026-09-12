#!/bin/bash
set -euo pipefail

PIPELINE_RUN="$SHIFT_WORKSPACE/runtime/pipeline_run.json"
ALERT_QUEUE="$SHIFT_WORKSPACE/alerts/alert_queue.json"
CATALOG_RUN="$SHIFT_WORKSPACE/runtime/catalog_run.json"

PROJECT="$HOME/dlh-cyber_security/blue_team/3x02_the_alert_factory"
RULE_DIR="$PROJECT/rules/sigma"

[ "$(jq -r '.exit_status' "$PIPELINE_RUN")" = "0" ] || exit 1
echo "[detect] pipeline check: OK"

RULES_TOTAL=$(find "$RULE_DIR" -maxdepth 1 -type f -name '*.yml' | wc -l)
echo "[detect] catalog loaded: $RULES_TOTAL rules"

INPUT="$SHIFT_WORKSPACE/enriched/enriched_events.json"
[ -s "$INPUT" ] || exit 1

mkdir -p "$SHIFT_WORKSPACE/alerts" "$SHIFT_WORKSPACE/runtime"

TMP=$(mktemp -d)
mkdir -p "$TMP/baselines"
ln -s "$HOME/bt/3x01/baseline/work/baseline_summary.json" "$TMP/baselines/baseline_summary.json"
ln -s "$HOME/bt/3x01/baseline/work/baseline_process.json" "$TMP/baselines/baseline_process.json"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/data" "$TMP/context"

jq -c '
  .canonical_label =
    if .event_id=="4624" then "login_success"
    elif .event_id=="4625" then "login_failure"
    elif .event_id=="4634" then "logout"
    elif .event_id=="4740" then "account_lockout"
    elif .event_id=="4672" then "privilege_escalation"
    elif .event_id=="1" then "process_start"
    elif .event_id=="23" then "process_stop"
    elif .event_category=="SYSCALL" then "child_process_spawn"
    elif .event_category=="PATH" then "file_read_sensitive"
    elif .event_id=="11" then "file_write_sensitive"
    elif .event_id=="4670" then "file_permission_change"
    elif .event_id=="3" then "network_connection_outbound"
    elif .event_id=="5156" then "network_connection_inbound"
    elif .event_category=="suricata" then "network_alert"
    elif .event_id=="5157" then "network_blocked"
    else "unlabeled" end
  | if .event_id=="4624" or .event_id=="4625" then
      .event_category="authentication"
    else . end
' "$INPUT" > "$TMP/data/normalized_events.json"

ln -s "$CAPSTONE_PACK/context/asset_inventory.json" \
  "$TMP/context/asset_inventory.json"

STARTED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "[detect] invoking detection runner"

(
  cd "$PROJECT"
  HANDOFF_DIR="$TMP" \
  BASELINE_PKG="$HOME/bt/3x01/baseline/work" \
  bash ./15-generate_alerts.sh
)

[ -s "$PROJECT/alert_queue.json" ] || exit 1
cp "$PROJECT/alert_queue.json" "$ALERT_QUEUE"

ALERTS_TOTAL=$(jq 'length' "$ALERT_QUEUE")
[ "$ALERTS_TOTAL" -gt 0 ] || exit 1

CRITICAL=$(jq '[.[] | select(.rule_level=="critical")] | length' "$ALERT_QUEUE")
HIGH=$(jq '[.[] | select(.rule_level=="high")] | length' "$ALERT_QUEUE")
MEDIUM=$(jq '[.[] | select(.rule_level=="medium")] | length' "$ALERT_QUEUE")
LOW=$(jq '[.[] | select(.rule_level=="low")] | length' "$ALERT_QUEUE")

BY_RULE=$(jq '
  group_by(.rule_id)
  | map({key: .[0].rule_id, value: length})
  | sort_by(-.value)
  | from_entries
' "$ALERT_QUEUE")

RULES_FIRED=$(jq 'length' <<< "$BY_RULE")
ENDED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "[detect] matched: $RULES_FIRED rules / $ALERTS_TOTAL alerts"
echo "[detect] severity critical=$CRITICAL high=$HIGH medium=$MEDIUM low=$LOW"
echo "[detect] top rules:"
jq -r 'to_entries[] | "  \(.key) : \(.value) alerts"' <<< "$BY_RULE"
echo "[detect] alert_queue.json written"

jq -n \
  --argjson rules "$RULES_TOTAL" \
  --argjson fired "$RULES_FIRED" \
  --argjson total "$ALERTS_TOTAL" \
  --argjson critical "$CRITICAL" \
  --argjson high "$HIGH" \
  --argjson medium "$MEDIUM" \
  --argjson low "$LOW" \
  --argjson by_rule "$BY_RULE" \
  --arg started "$STARTED_AT" \
  --arg ended "$ENDED_AT" \
  '{
    catalog_rules_total:$rules,
    catalog_rules_fired:$fired,
    alerts_total:$total,
    alerts_by_severity:{
      critical:$critical,
      high:$high,
      medium:$medium,
      low:$low
    },
    alerts_by_rule:$by_rule,
    started_at:$started,
    ended_at:$ended,
    exit_status:0
  }' > "$CATALOG_RUN"

echo "[detect] catalog_run.json written"
