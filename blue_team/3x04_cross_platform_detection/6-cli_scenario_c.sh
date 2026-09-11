#!/bin/bash

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"

MANIFEST="$ASSETS_DIR/scenarios/scenario_c_medical_egress.json"
EXPORT="$ASSETS_DIR/wazuh_exports/scenario_c_search_results.json"
ZONES="/home/student/evidence_pack_primary/context/network_zones.json"
FINDING="findings/scenario_c_cli.json"

start_epoch=$(date +%s)
investigation_start=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

description=$(jq -r '.key_events[0].description' "$MANIFEST")
src_ip=$(printf '%s\n' "$description" | sed -n 's/.*(\([0-9.]*\)).*to \([0-9.]*\):443.*/\1/p')
dst_ip=$(printf '%s\n' "$description" | sed -n 's/.*(\([0-9.]*\)).*to \([0-9.]*\):443.*/\2/p')

echo "scenario    : scenario_c_medical_egress"
echo "src_ip      : $src_ip (MEDICAL_IOT zone)"
echo "dst_ip      : $dst_ip:443"

matched=$(jq '.events | length' "$EXPORT")
echo "matched     : $matched flows in Wazuh export"

beacon_count=0
previous_epoch=""

while IFS=$'\t' read -r timestamp bytes_out; do
    if [ "$bytes_out" != "n/a" ]; then
        beacon_count=$((beacon_count + 1))

        if [ -n "$previous_epoch" ]; then
            current_epoch=$(date -d "$timestamp" +%s)
            interval=$((current_epoch - previous_epoch))
            interval_min=$((interval / 60))
            echo "beacon_$beacon_count  : $timestamp  (interval: $interval_min min, bytes_out: $bytes_out)"
        else
            current_epoch=$(date -d "$timestamp" +%s)
            echo "beacon_$beacon_count  : $timestamp  (bytes_out: $bytes_out)"
        fi

        previous_epoch="$current_epoch"
    fi
done < <(
    jq -r '.events
        | sort_by(."@timestamp")[]
        | [."@timestamp", (._source.event_data.bytes_out // "n/a")]
        | @tsv' "$EXPORT"
)

zone=$(jq -r '.zones[] | select(.zone_id=="MEDICAL_IOT") | .zone_id' "$ZONES")
zone_notes=$(jq -r '.zones[] | select(.zone_id=="MEDICAL_IOT") | .notes' "$ZONES")

echo "zone        : $zone — $zone_notes"

ioc_file="$ASSETS_DIR/3x03_assets/ioc_context.json"
ioc_status="not available"

if [ -f "$ioc_file" ]; then
    ioc_status=$(jq -r --arg ip "$dst_ip" '
        .. | objects |
        select(
            (.ip? == $ip) or
            (.indicator? == $ip) or
            (.value? == $ip)
        ) | tostring
    ' "$ioc_file" | head -1)

    [ -z "$ioc_status" ] && ioc_status="destination not found"
fi

echo "ioc         : $ioc_status"
echo "attack      : T1071.001 T1041"

mkdir -p findings

investigation_end=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
end_epoch=$(date +%s)
elapsed=$((end_epoch - start_epoch))

refs=$(jq '[.events[]._id]' "$EXPORT")

jq -n \
    --arg inv_start "$investigation_start" \
    --arg inv_end "$investigation_end" \
    --argjson elapsed "$elapsed" \
    --argjson refs "$refs" \
    --arg zone "$zone" \
    --arg zone_notes "$zone_notes" \
    --arg ioc "$ioc_status" \
    '{
        finding_id: "scenario_c_cli",
        scenario_id: "scenario_c",
        interface: "cli",
        investigation_start: $inv_start,
        investigation_end: $inv_end,
        time_to_first_answer_seconds: $elapsed,
        actions: [
            "Read scenario C manifest",
            "Read matching Wazuh network export events",
            "Verified MEDICAL_IOT zone",
            "Checked optional IOC context",
            "Ordered beacon events chronologically and calculated intervals"
        ],
        fields_touched: [
            "@timestamp",
            "source.ip",
            "destination.ip",
            "destination.port",
            "event_data.bytes_out"
        ],
        event_refs: $refs,
        attack_techniques: [
            "T1071.001",
            "T1041"
        ],
        zone: $zone,
        zone_notes: $zone_notes,
        ioc_context: $ioc,
        hypothesis: "Repeated outbound HTTPS flows from a MEDICAL_IOT device to an external destination at regular intervals are consistent with a C2 beacon pattern and violate the zone outbound restriction.",
        confidence: "high",
        created_at: $inv_end
    }' > "$FINDING" || exit 1

echo "finding     : findings/scenario_c_cli.json written"
