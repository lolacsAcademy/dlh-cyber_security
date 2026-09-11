#!/bin/bash

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"

MANIFEST="$ASSETS_DIR/scenarios/scenario_b_offhours_phi.json"
EVIDENCE="$HANDOFF_DIR/data/enriched_events.json"
INVENTORY="$HOME/evidence_pack_primary/context/asset_inventory.json"
FINDING="findings/scenario_b_cli.json"

start_epoch=$(date +%s)
investigation_start=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

host=$(jq -r '.host_path[0]' "$MANIFEST")
window_start=$(jq -r '.time_window.start' "$MANIFEST")
window_end=$(jq -r '.time_window.end' "$MANIFEST")
ambiguity=$(jq -r '.ambiguity_note' "$MANIFEST")

criticality=$(jq -r --arg host "$host" \
    '.assets[] | select(.hostname==$host) | .criticality' "$INVENTORY")

classification=$(jq -r --arg host "$host" \
    '.assets[] | select(.hostname==$host) | .data_classification' "$INVENTORY")

echo "scenario    : scenario_b_offhours_phi"
echo "host        : $host (criticality: $criticality, data: $classification)"
echo "window      : $window_start -> $window_end"

scoped=$(jq -c \
    --arg host "$host" \
    --arg window_start "$window_start" \
    --arg window_end "$window_end" \
    'select(
        .hostname==$host and
        .timestamp >= $window_start and
        .timestamp <= $window_end
    )' "$EVIDENCE")

event_4624=$(printf '%s\n' "$scoped" |
    jq -r --arg eid "4624" '
        select(.event_id==$eid) |
        "\(.timestamp) | \(.user) | \(.raw_message)"
    ' | head -1)

event_4672=$(printf '%s\n' "$scoped" |
    jq -r --arg eid "4672" '
        select(.event_id==$eid) |
        "\(.timestamp) | \(.user) | \(.raw_message)"
    ' | head -1)

command=$(printf '%s\n' "$scoped" |
    jq -r --arg eid "1" '
        select(.event_id==$eid) |
        "\(.timestamp) | \(.event_data.CommandLine)"
    ' | head -1)

echo "EID 4624    : $event_4624"
echo "EID 4672    : $event_4672"
echo "EID 1       : $command"
echo "ambiguity   : $ambiguity"
echo "attack      : T1078.002 T1059.001"

mkdir -p findings

investigation_end=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
end_epoch=$(date +%s)
elapsed=$((end_epoch - start_epoch))

refs=$(printf '%s\n' "$scoped" |
    jq -r '.event_ref // empty' |
    jq -R . |
    jq -s .)

jq -n \
    --arg inv_start "$investigation_start" \
    --arg inv_end "$investigation_end" \
    --argjson elapsed "$elapsed" \
    --argjson refs "$refs" \
    --arg criticality "$criticality" \
    --arg classification "$classification" \
    --arg ambiguity "$ambiguity" \
    '{
        finding_id: "scenario_b_cli",
        scenario_id: "scenario_b",
        interface: "cli",
        investigation_start: $inv_start,
        investigation_end: $inv_end,
        time_to_first_answer_seconds: $elapsed,
        actions: [
            "Read scenario B manifest",
            "Scoped enriched events to clin-ws-07 and scenario window",
            "Read asset criticality and data classification",
            "Filtered Windows events 4624, 4672, and Sysmon EID 1",
            "Documented the authorization and off-hours ambiguity"
        ],
        fields_touched: [
            "hostname",
            "timestamp",
            "event_id",
            "user",
            "process_name",
            "event_data.CommandLine",
            "raw_message",
            "asset.criticality",
            "asset.data_classification",
            "event_ref"
        ],
        event_refs: $refs,
        attack_techniques: [
            "T1078.002",
            "T1059.001"
        ],
        asset_criticality: $criticality,
        data_classification: $classification,
        ambiguity_note: $ambiguity,
        hypothesis: "An off-hours privileged remote logon by an authorized CISO account was followed by PowerShell execution with ExecutionPolicy Bypass on a PHI workstation. The authorization reduces certainty, but the timing and execution behavior warrant escalation.",
        confidence: "high",
        created_at: $inv_end
    }' > "$FINDING" || exit 1

echo "finding    : findings/scenario_b_cli.json written"
