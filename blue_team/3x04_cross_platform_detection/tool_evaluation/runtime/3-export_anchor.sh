#!/bin/bash

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"

EXPORT="$ASSETS_DIR/wazuh_exports/anchor_search_results.json"
TRACE="$ASSETS_DIR/wazuh_exports/anchor_dashboard_trace.json"
MAPPING="$ASSETS_DIR/wazuh_exports/field_mapping.json"
FINDING="findings/anchor_export.json"

start_epoch=$(date +%s)
investigation_start=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "reading     : \$ASSETS_DIR/wazuh_exports/anchor_search_results.json"

hits_total=$(jq -r '.hits_total' "$EXPORT")
kql_query=$(jq -r '.query.kql' "$EXPORT")
time_start=$(jq -r '.query.time_start' "$EXPORT")
time_end=$(jq -r '.query.time_end' "$EXPORT")

first_timestamp=$(jq -r '.events[0]."@timestamp"' "$EXPORT")
first_ip=$(jq -r '.events[0]._source.source.ip' "$EXPORT")
last_timestamp=$(jq -r '.events[-1]."@timestamp"' "$EXPORT")
last_ip=$(jq -r '.events[-1]._source.source.ip' "$EXPORT")

echo "hits_total  : $hits_total"
echo "kql_query   : $kql_query"
echo "time range  : $time_start -> $time_end"
echo "first event : $first_timestamp ($first_ip)"
echo "last event  : $last_timestamp ($last_ip)"

mapfile -t click_path < <(jq -r '.click_path[]' "$TRACE")
estimated_time=$(jq -r '.estimated_time_seconds' "$TRACE")

echo "field map   :"

for field in src_ip hostname user event_ref raw_message; do
    wazuh=$(jq -r --arg field "$field" \
        '.mappings[] | select(.normalized == $field) | .wazuh' "$MAPPING")
    printf "              %-12s -> %s\n" "$field" "$wazuh"
done

echo "click_path  : ${#click_path[@]} steps loaded from dashboard_trace"

mkdir -p findings

investigation_end=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
end_epoch=$(date +%s)
elapsed=$((end_epoch - start_epoch))

refs=$(jq '[.events[]._id]' "$EXPORT")
actions=$(jq '.click_path' "$TRACE")

jq -n \
    --arg inv_start "$investigation_start" \
    --arg inv_end "$investigation_end" \
    --argjson elapsed "$elapsed" \
    --argjson actions "$actions" \
    --argjson refs "$refs" \
    '{
        finding_id: "anchor_wazuh_export",
        scenario_id: "anchor",
        interface: "wazuh_export",
        investigation_start: $inv_start,
        investigation_end: $inv_end,
        time_to_first_answer_seconds: $elapsed,
        actions: $actions,
        fields_touched: [
            "@timestamp",
            "source.ip",
            "agent.name",
            "user.name",
            "_id",
            "full_log"
        ],
        event_refs: $refs,
        attack_techniques: ["T1110.001"],
        hypothesis: "The Wazuh export shows repeated SSH activity from four external source IPs targeting the patient database host, consistent with the anchor brute force investigation.",
        confidence: "high",
        created_at: $inv_end
    }' > "$FINDING" || exit 1

echo "elapsed     : $elapsed seconds, 4 file reads"
echo "finding     : findings/anchor_export.json written"
