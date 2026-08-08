#!/bin/bash
# name: 13-consolidated_export.sh
# purpose: Consolidated Telemetry Export
# author: analyst
set -e
set -u
set -o pipefail
BASE_DIR="$(dirname "$0")"
WINDOWS_FILE="$BASE_DIR/windows_events_export.json"
LINUX_FILE="$BASE_DIR/linux_events_export.json"
WINDOWS_GT="$BASE_DIR/windows_attack_log.json"
LINUX_GT="$BASE_DIR/linux_attack_log.json"
HANDOFF_DIR="$BASE_DIR/telemetry_handoff"
echo "[*] Loading Windows events..."
if [ ! -f "$WINDOWS_FILE" ]; then
    echo "ERROR: windows_events_export.json not found."
    exit 1
fi
if [ ! -f "$LINUX_FILE" ]; then
    echo "ERROR: linux_events_export.json not found."
    exit 1
fi
if [ ! -f "$WINDOWS_GT" ]; then
    echo "ERROR: windows_attack_log.json not found."
    exit 1
fi
if [ ! -f "$LINUX_GT" ]; then
    echo "ERROR: linux_attack_log.json not found."
    exit 1
fi
command -v jq >/dev/null 2>&1 || {
    echo "ERROR: jq is required."
    exit 1
}
WINDOWS_COUNT=$(jq 'length' "$WINDOWS_FILE")
LINUX_COUNT=$(jq 'length' "$LINUX_FILE")
echo "    Windows events: $WINDOWS_COUNT"
echo "[*] Loading Linux events..."
echo "    Linux events: $LINUX_COUNT"
echo "[*] Normalizing timestamps to UTC..."
normalize_events() {
    local INPUT="$1"
    local OUTPUT="$2"
    jq '
        map(
            .timestamp =
                (
                    try (
                        .timestamp
                        | fromdateiso8601
                        | todateiso8601
                    )
                    catch .timestamp
                )
        )
    ' "$INPUT" > "$OUTPUT"
}
WINDOWS_TMP=$(mktemp)
LINUX_TMP=$(mktemp)
trap 'rm -f "$WINDOWS_TMP" "$LINUX_TMP"' EXIT
normalize_events "$WINDOWS_FILE" "$WINDOWS_TMP"
normalize_events "$LINUX_FILE" "$LINUX_TMP"
WINDOWS_NORMALIZED=$(jq 'length' "$WINDOWS_TMP")
LINUX_NORMALIZED=$(jq 'length' "$LINUX_TMP")
echo "    Windows: $WINDOWS_NORMALIZED events normalized"
echo "    Linux: $LINUX_NORMALIZED events normalized"
echo "[*] Verifying field consistency..."
REQUIRED_FIELDS='["timestamp","hostname","source_type","event_category"]'
WINDOWS_MISSING=$(jq --argjson fields "$REQUIRED_FIELDS" '
    map(select( ($fields - keys | length) > 0 )) | length
' "$WINDOWS_TMP")
LINUX_MISSING=$(jq --argjson fields "$REQUIRED_FIELDS" '
    map(select( ($fields - keys | length) > 0 )) | length
' "$LINUX_TMP")
if [ "$WINDOWS_MISSING" -ne 0 ] || [ "$LINUX_MISSING" -ne 0 ]; then
    echo "ERROR: Required fields missing."
    echo "    Windows events with missing fields: $WINDOWS_MISSING"
    echo "    Linux events with missing fields: $LINUX_MISSING"
    exit 1
fi
echo "    Required fields present in all events    [OK]"
echo "[*] Combining ground truth..."
WINDOWS_ACTIONS=$(jq '.actions | length' "$WINDOWS_GT")
LINUX_ACTIONS=$(jq '.actions | length' "$LINUX_GT")
TOTAL_ACTIONS=$((WINDOWS_ACTIONS + LINUX_ACTIONS))
echo "    Windows actions: $WINDOWS_ACTIONS | Linux actions: $LINUX_ACTIONS | Total: $TOTAL_ACTIONS"
echo "[*] Building handoff directory..."
mkdir -p "$HANDOFF_DIR"
cp "$WINDOWS_TMP" "$HANDOFF_DIR/windows_events.json"
cp "$LINUX_TMP" "$HANDOFF_DIR/linux_events.json"
jq -n \
    --slurpfile windows "$WINDOWS_GT" \
    --slurpfile linux "$LINUX_GT" \
    '{
        windows: $windows[0].actions,
        linux: $linux[0].actions
    }' > "$HANDOFF_DIR/attack_ground_truth.json"
echo "telemetry_handoff/"
echo "  windows_events.json"
echo "  linux_events.json"
echo "  attack_ground_truth.json"
echo "Total: $((WINDOWS_NORMALIZED + LINUX_NORMALIZED)) events across 2 platforms"
