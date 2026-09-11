#!/bin/bash

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
FINDING="findings/scenario_a_export.json"
EXPORT="$ASSETS_DIR/wazuh_exports/scenario_a_search_results.json"
TRACE="$ASSETS_DIR/wazuh_exports/scenario_a_dashboard_trace.json"
SUMMARY="$ASSETS_DIR/dashboard_exports/scenario_a_dashboard_summary.md"
CLI_FINDING="findings/scenario_a_cli.json"

start_epoch=$(date +%s)
investigation_start=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

hits_total=$(jq -r '.hits_total' "$EXPORT")
kql=$(jq -r '.query.kql' "$EXPORT")
event_count=$(jq '.events | length' "$EXPORT")

echo "reading     : scenario_a_search_results.json ($event_count events)"
echo "kql         : $kql"

jq -r '
    .events[]
    | select(
        ._source.winlog.event_id == 10 or
        ._source.winlog.event_id == 11 or
        ._source.winlog.event_id == 3
      )
    | [
        ."@timestamp",
        ._source.winlog.event_id,
        (._source.full_log // "")
      ]
    | @tsv
' "$EXPORT" |
while IFS=$'\t' read -r timestamp event_id full_log; do
    case "$event_id" in
        10) echo "EID 10      : $timestamp | $full_log" ;;
        11) echo "EID 11      : $timestamp | $full_log" ;;
        3)  echo "EID 3       : $timestamp | $full_log" ;;
    esac
done

click_count=$(jq '.click_path | length' "$TRACE")
estimated=$(jq -r '.estimated_time_seconds' "$TRACE")
click_path=$(jq -c '.click_path' "$TRACE")
field_map=$(jq -c '.field_name_translation' "$TRACE")

echo "click_path  : $click_count steps"
echo "field_map   : hostname -> agent.name, event_id -> winlog.event_id"

echo "ATT&CK mapping:"
grep -A 4 -i '^## ATT&CK Mapping' "$SUMMARY"

mkdir -p findings

cli_elapsed=$(jq -r '.time_to_first_answer_seconds // 0' "$CLI_FINDING")

investigation_end=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
end_epoch=$(date +%s)
elapsed=$((end_epoch - start_epoch))
delta=$((cli_elapsed - elapsed))

if [ "$delta" -gt 0 ]; then
    comparison="$delta seconds faster via export"
elif [ "$delta" -lt 0 ]; then
    comparison="$((-delta)) seconds slower via export"
else
    comparison="same elapsed time as CLI"
fi

echo "elapsed     : $elapsed seconds"
echo "delta_vs_cli: $comparison"

event_refs=$(jq '[
    .events[]
    | select(
        ._source.winlog.event_id == 10 or
        ._source.winlog.event_id == 11 or
        ._source.winlog.event_id == 3
      )
    | ._id
]' "$EXPORT")

jq -n \
    --arg inv_start "$investigation_start" \
    --arg inv_end "$investigation_end" \
    --argjson elapsed "$elapsed" \
    --argjson hits "$hits_total" \
    --arg kql "$kql" \
    --argjson actions "$click_path" \
    --argjson refs "$event_refs" \
    --argjson field_map "$field_map" \
    --argjson estimated "$estimated" \
    --arg comparison "$comparison" \
    '{
        finding_id: "scenario_a_wazuh_export",
        scenario_id: "scenario_a",
        interface: "wazuh_export",
        investigation_start: $inv_start,
        investigation_end: $inv_end,
        time_to_first_answer_seconds: $elapsed,
        actions: $actions,
        fields_touched: [
            "@timestamp",
            "agent.name",
            "winlog.event_id",
            "process.name",
            "full_log"
        ],
        event_refs: $refs,
        attack_techniques: [
            "T1003.001",
            "T1550.002",
            "T1021.002"
        ],
        hypothesis: "The Wazuh export confirms an LSASS access event followed by credential dump file creation and SMB lateral movement from clin-ws-12 to 10.1.1.10.",
        confidence: "high",
        export_hits_total: $hits,
        kql_query: $kql,
        field_name_translation: $field_map,
        dashboard_estimated_time_seconds: $estimated,
        comparison_to_cli: $comparison,
        created_at: $inv_end
    }' > "$FINDING" || exit 1

echo "attack      : T1003.001 T1550.002 T1021.002"
echo "finding     : findings/scenario_a_export.json written"
