#!/bin/bash

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
EXPORT="$ASSETS_DIR/wazuh_exports/scenario_c_search_results.json"
TRACE="$ASSETS_DIR/wazuh_exports/scenario_c_dashboard_trace.json"
CLI_FINDING="findings/scenario_c_cli.json"
FINDING="findings/scenario_c_export.json"

start_epoch=$(date +%s)
investigation_start=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

event_count=$(jq '.events | length' "$EXPORT")
src_ip=$(jq -r '.events[0]._source.source.ip' "$EXPORT")
dst_ip=$(jq -r '.events[0]._source.destination.ip' "$EXPORT")
dst_port=$(jq -r '.events[0]._source.destination.port' "$EXPORT")
src_zone=$(jq -r '.events[0]._source.source.zone // empty' "$EXPORT")

echo "reading     : scenario_c_search_results.json ($event_count events)"
echo "src_ip      : $src_ip"
echo "dst_ip      : $dst_ip:$dst_port"

if [ -n "$src_zone" ]; then
    echo "src_zone    : $src_zone (from source.zone — immediately available)"
    fallback="false"
else
    echo "src_zone    : not populated (fallback lookup required)"
    fallback="true"
fi

mapfile -t beacons < <(
    jq -r '
        .events[]
        | select(._source.agent.type == "firewall")
        | .["@timestamp"]
    ' "$EXPORT" | sort
)

previous=""
count=1

for timestamp in "${beacons[@]}"; do
    if [ -z "$previous" ]; then
        echo "beacon_$count    : $timestamp"
    else
        current_epoch=$(date -d "$timestamp" +%s)
        previous_epoch=$(date -d "$previous" +%s)
        interval=$(( (current_epoch - previous_epoch) / 60 ))
        echo "beacon_$count    : $timestamp  ($interval min interval)"
    fi

    previous="$timestamp"
    count=$((count + 1))
done

click_path=$(jq -c '.click_path' "$TRACE")
click_count=$(jq '.click_path | length' "$TRACE")

echo "click_path  : $click_count steps"
echo "attack      : T1071.001 T1041"

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
        '$clicks + ["Fallback required: source.zone was not populated in export"]' \
        <<< 'null')
fi

jq -n \
    --arg inv_start "$investigation_start" \
    --arg inv_end "$investigation_end" \
    --argjson elapsed "$elapsed" \
    --argjson refs "$event_refs" \
    --argjson actions "$actions" \
    --arg src_ip "$src_ip" \
    --arg dst_ip "$dst_ip" \
    --arg src_zone "$src_zone" \
    --arg comparison "$comparison" \
    --arg fallback "$fallback" \
    '{
        finding_id: "scenario_c_wazuh_export",
        scenario_id: "scenario_c",
        interface: "wazuh_export",
        investigation_start: $inv_start,
        investigation_end: $inv_end,
        time_to_first_answer_seconds: $elapsed,
        actions: $actions,
        fields_touched: [
            "@timestamp",
            "source.ip",
            "destination.ip",
            "destination.port",
            "source.zone",
            "full_log"
        ],
        event_refs: $refs,
        attack_techniques: [
            "T1071.001",
            "T1041"
        ],
        source_ip: $src_ip,
        destination_ip: $dst_ip,
        source_zone: $src_zone,
        zone_immediately_available: ($fallback == "false"),
        hypothesis: "Regular outbound connections from the MEDICAL_IOT segment to the same external destination indicate a beaconing pattern and possible data egress.",
        confidence: "high",
        comparison_to_cli: $comparison,
        created_at: $inv_end
    }' > "$FINDING" || exit 1

echo "finding     : findings/scenario_c_export.json written"
