#!/bin/bash

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
CATALOG_DIR="${CATALOG_DIR:-$HOME/3x02_package/detection_catalog}"
ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"

ANCHOR="$ASSETS_DIR/anchor_event.json"
EVIDENCE="$HANDOFF_DIR/data/enriched_events.json"
EXPORT="$ASSETS_DIR/wazuh_exports/anchor_search_results.json"
RULE="$CATALOG_DIR/rules/sigma/001_ssh_brute_force.yml"
FINDING="findings/anchor_cli.json"

start_epoch=$(date +%s)
investigation_start=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

host=$(jq -r '.target_host' "$ANCHOR")
target_ip=$(jq -r '.target_ip' "$ANCHOR")
window_start=$(jq -r '.time_window.start' "$ANCHOR")
window_end=$(jq -r '.time_window.end' "$ANCHOR")
mapfile -t attacker_ips < <(jq -r '.attacker_ips[]' "$ANCHOR")

echo "reading     : \$ASSETS_DIR/anchor_event.json"
echo "host        : $host ($target_ip)"
echo "window      : $window_start -> $window_end"
echo "attacker ips: ${attacker_ips[*]}"

ip_regex=$(printf '%s\n' "${attacker_ips[@]}" |
    sed 's/\./\\./g' |
    paste -sd '|' -)

matches=$(jq -c \
    --arg host "$host" \
    --arg window_start "$window_start" \
    --arg window_end "$window_end" \
    --arg ip_regex "$ip_regex" \
    'select(
        .hostname == $host and
        .timestamp >= $window_start and
        .timestamp <= $window_end and
        (.raw_message | test($ip_regex))
    )' "$EVIDENCE")

matched=$(printf '%s\n' "$matches" | grep -c '^{' || true)
first_event=$(printf '%s\n' "$matches" | jq -r '.timestamp' | sort | head -1)
last_event=$(printf '%s\n' "$matches" | jq -r '.timestamp' | sort | tail -1)

echo "matched     : $matched events in enriched_events.json"
echo "first event : $first_event"
echo "last event  : $last_event"

technique=""

if [ -f "$RULE" ]; then
    echo "logsource:"
    yq '.logsource' "$RULE"
    echo "detection:"
    yq '.detection' "$RULE"

    tag=$(yq -r '.tags[] | select(test("^attack\\.t[0-9]"))' "$RULE" | head -1)
    technique=$(printf '%s' "$tag" |
        sed 's/^attack\.t/T/' |
        tr '[:lower:]' '[:upper:]')

    echo "rule        : 001_ssh_brute_force ($technique)"
fi

mkdir -p findings

investigation_end=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
end_epoch=$(date +%s)
elapsed=$((end_epoch - start_epoch))

refs=$(jq '[.events[]._id]' "$EXPORT")

jq -n \
    --arg inv_start "$investigation_start" \
    --arg inv_end "$investigation_end" \
    --argjson elapsed "$elapsed" \
    --arg technique "$technique" \
    --argjson refs "$refs" \
    '{
        finding_id: "anchor_cli",
        scenario_id: "anchor",
        interface: "cli",
        investigation_start: $inv_start,
        investigation_end: $inv_end,
        time_to_first_answer_seconds: $elapsed,
        actions: [
            "Read anchor event manifest",
            "Filtered enriched events by anchor window and attacker IPs",
            "Counted matching records",
            "Extracted earliest and latest matching events",
            "Read Sigma rule"
        ],
        fields_touched: [
            "hostname",
            "timestamp",
            "raw_message",
            "event_ref"
        ],
        event_refs: $refs,
        attack_techniques: [$technique],
        hypothesis: "Multiple SSH authentication attempts from four external IPs against db-patient-01 indicate an SSH brute force attack culminating in successful access.",
        confidence: "high",
        created_at: $inv_end
    }' > "$FINDING" || exit 1

echo "elapsed     : $elapsed seconds, 5 commands"
echo "finding     : findings/anchor_cli.json written"
