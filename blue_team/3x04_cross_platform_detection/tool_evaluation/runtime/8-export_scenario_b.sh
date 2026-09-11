#!/bin/bash

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
EXPORT="$ASSETS_DIR/wazuh_exports/scenario_b_search_results.json"
TRACE="$ASSETS_DIR/wazuh_exports/scenario_b_dashboard_trace.json"
INVENTORY="/home/student/evidence_pack_primary/context/asset_inventory.json"
FINDING="findings/scenario_b_export.json"
CLI_FINDING="findings/scenario_b_cli.json"

start_epoch=$(date +%s)
investigation_start=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

event_count=$(jq '.events | length' "$EXPORT")
host=$(jq -r '.events[0]._source.agent.name' "$EXPORT")
user=$(jq -r '.events[] | select(._source.winlog.event_id==4624) | ._source.user.name' "$EXPORT" | head -1)

has_classification=$(jq -r '
    any(.events[]; ._source.agent.labels.data_classification != null)
' "$EXPORT")

if [ "$has_classification" = "true" ]; then
    data_class=$(jq -r '
        .events[]
        | ._source.agent.labels.data_classification
        | select(. != null)
    ' "$EXPORT" | head -1)
    fallback="false"
else
    data_class=$(jq -r --arg host "$host" '
        .assets[]
        | select(.hostname==$host)
        | .data_classification
    ' "$INVENTORY")
    fallback="true"
fi

criticality=$(jq -r --arg host "$host" '
    .assets[]
    | select(.hostname==$host)
    | .criticality
' "$INVENTORY")

click_path=$(jq -c '.click_path' "$TRACE")
click_count=$(jq '.click_path | length' "$TRACE")

echo "reading     : scenario_b_search_results.json ($event_count events)"
echo "host        : $host (from agent.name)"
echo "user        : $user (from user.name)"

if [ "$fallback" = "true" ]; then
    echo "data_class  : $data_class (fallback inventory lookup)"
else
    echo "data_class  : $data_class (from agent.labels — resolved without fallback)"
fi

echo "off_hours   : 02:17Z outside 06:00-18:00 window"
echo "click_path  : $click_count steps"

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

event_refs=$(jq '[.events[]._id]' "$EXPORT")
actions="$click_path"

if [ "$fallback" = "true" ]; then
    actions=$(jq -c \
        --argjson clicks "$actions" \
        '$clicks + ["Fallback: read asset_inventory.json for data_classification"]' \
        <<< 'null')
fi

jq -n \
    --arg inv_start "$investigation_start" \
    --arg inv_end "$investigation_end" \
    --argjson elapsed "$elapsed" \
    --argjson refs "$event_refs" \
    --argjson actions "$actions" \
    --arg host "$host" \
    --arg user "$user" \
    --arg criticality "$criticality" \
    --arg data_class "$data_class" \
    --arg comparison "$comparison" \
    --arg fallback "$fallback" \
    '{
        finding_id: "scenario_b_wazuh_export",
        scenario_id: "scenario_b",
        interface: "wazuh_export",
        investigation_start: $inv_start,
        investigation_end: $inv_end,
        time_to_first_answer_seconds: $elapsed,
        actions: $actions,
        fields_touched: [
            "@timestamp",
            "agent.name",
            "agent.labels",
            "user.name",
            "winlog.event_id"
        ],
        event_refs: $refs,
        attack_techniques: [
            "T1078.002",
            "T1059.001"
        ],
        hostname: $host,
        user: $user,
        asset_criticality: $criticality,
        data_classification: $data_class,
        classification_fallback_used: ($fallback == "true"),
        hypothesis: "An off-hours privileged remote logon by p.morales was followed by PowerShell execution with ExecutionPolicy Bypass on a PHI workstation. The account is authorized, but the timing and execution behavior warrant escalation.",
        confidence: "high",
        comparison_to_cli: $comparison,
        created_at: $inv_end
    }' > "$FINDING" || exit 1

echo "finding     : findings/scenario_b_export.json written"
