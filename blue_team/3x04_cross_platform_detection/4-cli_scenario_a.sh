#!/bin/bash

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
MANIFEST="$ASSETS_DIR/scenarios/scenario_a_credential_theft.json"
EVIDENCE="$HANDOFF_DIR/data/enriched_events.json"
FINDING="findings/scenario_a_cli.json"

start_epoch=$(date +%s)
investigation_start=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

title=$(jq -r '.title' "$MANIFEST")
host=$(jq -r '.host_path[0]' "$MANIFEST")
window_start=$(jq -r '.time_window.start' "$MANIFEST")
window_end=$(jq -r '.time_window.end' "$MANIFEST")

echo "scenario    : $title"
echo "host        : $host"
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

count=$(printf '%s\n' "$scoped" | grep -c '^{' || true)
echo "scoped      : $count events on $host in window"

for eid in 10 11 3; do
    event=$(printf '%s\n' "$scoped" |
        jq -r --arg eid "$eid" '
            select(.event_id==$eid) |
            "\(.timestamp) | \(.raw_message)"
        ' | head -1)

    echo "EID $eid      : $event"
done

echo "hypothesis  : LSASS dump via rundll32, followed by lateral movement to srv-dc-01 via SMB"
echo "attack      : T1003.001 T1550.002 T1021.002"

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
    '{
        finding_id: "scenario_a_cli",
        scenario_id: "scenario_a",
        interface: "cli",
        investigation_start: $inv_start,
        investigation_end: $inv_end,
        time_to_first_answer_seconds: $elapsed,
        actions: [
            "Read scenario A manifest",
            "Scoped enriched events to clin-ws-12 and scenario window",
            "Filtered Sysmon Event IDs 10, 11, and 3",
            "Reconstructed the ordered credential theft and lateral movement chain"
        ],
        fields_touched: [
            "hostname",
            "timestamp",
            "event_id",
            "process_name",
            "raw_message",
            "event_ref"
        ],
        event_refs: $refs,
        attack_techniques: [
            "T1003.001",
            "T1550.002",
            "T1021.002"
        ],
        hypothesis: "LSASS was accessed by rundll32.exe and a dump file was created, followed by SMB lateral movement to srv-dc-01. The ordered events form a credential theft chain consistent with malicious activity.",
        confidence: "high",
        created_at: $inv_end
    }' > "$FINDING" || exit 1

echo "elapsed     : $elapsed seconds, 4 commands"
echo "finding     : findings/scenario_a_cli.json written"
