#!/bin/bash

set -euo pipefail

PACK="$HOME/evidence_pack_primary"
OUT="windows_events.json"
TMP=$(mktemp)

trap 'rm -f "$TMP"' EXIT

: > "$TMP"

process_evidence() {
    local file="$1"

    jq -c '
        if type != "object" then
            error("record is not a JSON object")
        elif (
            (has("timestamp_raw") | not) or
            (has("hostname") | not) or
            (has("event_id") | not) or
            (has("channel") | not) or
            (has("provider") | not) or
            (has("raw_message") | not) or
            (has("event_data") | not)
        ) then
            error("record is missing a required field")
        else
            .source_origin = "evidence_pack"
        end
    ' "$file" | tee -a "$TMP" | wc -l
}

process_student() {
    local file="$1"

    jq -c '
        if type != "object" then
            error("student telemetry record is not a JSON object")
        elif (.source_origin? == null or .source_origin == "") then
            .source_origin = "student_telemetry"
        else
            .
        end
    ' "$file" | tee -a "$TMP" | wc -l
}

for name in security.json sysmon.json powershell.json; do
    file="$PACK/windows/$name"

    if [ ! -f "$file" ]; then
        echo "Error: missing $file" >&2
        exit 1
    fi

    count=$(process_evidence "$file")
    printf "reading %-18s ... %d records\n" "$name" "$count"
done

STUDENT="$PACK/student_telemetry/windows_events.json"

if [ ! -f "$STUDENT" ]; then
    echo "Error: missing $STUDENT" >&2
    exit 1
fi

count=$(process_student "$STUDENT")
printf "appending student telemetry ... %d records\n" "$count"

mv "$TMP" "$OUT"
trap - EXIT

total=$(wc -l < "$OUT")
printf "%s: %d records\n" "$OUT" "$total"
