#!/bin/bash
set -euo pipefail

START="$SHIFT_WORKSPACE/runtime/shift_start.json"
INCIDENTS="$SHIFT_WORKSPACE/alerts/incidents.json"
CAMPAIGN="$SHIFT_WORKSPACE/campaign/campaign_assessment.json"
FEED="$ASSETS_DIR/ioc_feed.json"
HANDOFF_DIR="$SHIFT_WORKSPACE/handoff"
HANDOFF="$HANDOFF_DIR/shift_handoff.md"
MANIFEST="$SHIFT_WORKSPACE/MANIFEST.json"

REQUIRED=(
    "runtime/shift_start.json"
    "runtime/pipeline_run.json"
    "runtime/baseline_run.json"
    "runtime/catalog_run.json"
    "enriched/enriched_events.json"
    "enriched/baseline.json"
    "alerts/alert_queue.json"
    "alerts/shift_briefing.json"
    "alerts/triage_log.jsonl"
    "alerts/incidents.json"
    "investigations/incident_A.json"
    "investigations/incident_B.json"
    "investigations/incident_C_cli.json"
    "campaign/campaign_assessment.json"
    "reports/incident_A.md"
    "reports/incident_B.md"
    "reports/incident_C.md"
    "response/containment.json"
    "response/ioc_package.json"
)

echo "[handoff] checking workspace layout..."

CHECKED=0

for rel in "${REQUIRED[@]}"; do
    file="$SHIFT_WORKSPACE/$rel"

    if [ ! -s "$file" ]; then
        echo "[handoff] FAIL: $rel missing or empty" >&2
        exit 1
    fi

    echo "[handoff] OK: $rel"
    CHECKED=$((CHECKED + 1))
done

echo "[handoff] checking workspace layout... $CHECKED files OK"

mkdir -p "$HANDOFF_DIR"

SHIFT_ID=$(jq -r '.shift_id' "$START")
ANALYST_HOST=$(jq -r '.analyst_host' "$START")
STARTED_AT=$(jq -r '.started_at' "$START")
ENDED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

START_SEC=$(date -u -d "$STARTED_AT" +%s)
END_SEC=$(date -u -d "$ENDED_AT" +%s)

DURATION=$(awk -v start="$START_SEC" -v end="$END_SEC" \
    'BEGIN {printf "%.1f", (end-start)/3600}')

echo "[handoff] shift_id: $SHIFT_ID"
echo "[handoff] duration: $DURATION hours"

INCIDENT_IDS=$(jq -c '[.incidents[].incident_id]' "$INCIDENTS")
INCIDENT_COUNT=$(jq '.incidents | length' "$INCIDENTS")

CAMPAIGN_LINKED=$(jq -r '.campaign_linked' "$CAMPAIGN")
CLUSTER=$(jq -r '.cluster_id' "$CAMPAIGN")
CONFIDENCE=$(jq -r '.confidence' "$CAMPAIGN")

IOC_COUNT=$(jq '.iocs | length' "$FEED")

PACK_START=$(jq -r '
    [.incidents[].first_seen] | min // "unknown"
' "$INCIDENTS")

PACK_END=$(jq -r '
    [.incidents[].last_seen] | max // "unknown"
' "$INCIDENTS")

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

: > "$TMP/incidents"
: > "$TMP/open"

for LETTER in A B C; do
    case "$LETTER" in
        A)
            FINDING="$SHIFT_WORKSPACE/investigations/incident_A.json"
            REPORT="reports/incident_A.md"
            ;;
        B)
            FINDING="$SHIFT_WORKSPACE/investigations/incident_B.json"
            REPORT="reports/incident_B.md"
            ;;
        C)
            FINDING="$SHIFT_WORKSPACE/investigations/incident_C_cli.json"
            REPORT="reports/incident_C.md"
            ;;
    esac

    INCIDENT_ID=$(jq -r '.incident_id' "$FINDING")
    VERDICT=$(jq -r '
        .verdict // .classification // "ambiguous"
    ' "$FINDING")
    TECHNIQUE=$(jq -r '
        .attack_techniques[0] // "not identified"
    ' "$FINDING")

    printf '%s was assessed as %s. The primary ATT&CK technique is %s. The bounded incident report is available at `%s`.\n\n' \
        "$INCIDENT_ID" \
        "$VERDICT" \
        "$TECHNIQUE" \
        "$REPORT" >> "$TMP/incidents"

    jq -r '.unresolved_questions[]? // empty' "$FINDING" |
    while IFS= read -r ITEM; do
        [ -n "$ITEM" ] || continue
        printf -- '- %s; resolve using the relevant endpoint, identity, network, or change-management telemetry.\n' \
            "$ITEM" >> "$TMP/open"
    done
done

if [ ! -s "$TMP/open" ]; then
    printf -- '- Review unresolved incident evidence and validate closure using endpoint, identity, network, and change-management telemetry.\n' \
        > "$TMP/open"
fi

head -8 "$TMP/open" > "$TMP/open_bounded"

cat > "$HANDOFF" <<EOF
## Shift Identifier

shift_id: $SHIFT_ID  
analyst_host: $ANALYST_HOST  
started_at: $STARTED_AT  
ended_at: $ENDED_AT  
duration_hours: $DURATION

## Situation

The shift operated under the HC-RED7 threat advisory and associated healthcare-sector threat context. The IOC feed contained $IOC_COUNT indicators available for correlation against shift evidence. The incident evidence period runs from $PACK_START through $PACK_END. Investigation, correlation, reporting, and response artifacts were assembled from the bounded shift workspace.

## Incidents

$(cat "$TMP/incidents")
## Campaign Assessment

The mechanical campaign assessment recorded campaign_linked=$CAMPAIGN_LINKED with cluster_id=$CLUSTER and confidence=$CONFIDENCE. The counted IOC, tactic, temporal, host, and user correlation evidence is recorded in \`campaign/campaign_assessment.json\`.

## Open Items for Next Shift

$(cat "$TMP/open_bounded")
## Artifact Index

PATH | SHA256
--- | ---
EOF

build_manifest() {
    local manifest_tmp="$TMP/manifest.json"
    local files_tmp="$TMP/files.jsonl"

    : > "$files_tmp"

    while IFS= read -r -d '' FILE; do
        REL="${FILE#"$SHIFT_WORKSPACE/"}"

        [ "$REL" = "MANIFEST.json" ] && continue

        HASH=$(sha256sum "$FILE" | awk '{print $1}')
        SIZE=$(stat -c '%s' "$FILE")

        jq -cn \
            --arg path "$REL" \
            --arg hash "$HASH" \
            --argjson size "$SIZE" \
            '{path:$path,sha256:$hash,size:$size}' \
            >> "$files_tmp"
    done < <(find "$SHIFT_WORKSPACE" -type f -print0 | sort -z)

    FILES=$(jq -s '.' "$files_tmp")

    RUNTIME=$(jq '[.[] | select(.path | startswith("runtime/"))] | length' <<< "$FILES")
    ENRICHED=$(jq '[.[] | select(.path | startswith("enriched/"))] | length' <<< "$FILES")
    ALERTS=$(jq '[.[] | select(.path | startswith("alerts/"))] | length' <<< "$FILES")
    INVESTIGATIONS=$(jq '[.[] | select(.path | startswith("investigations/"))] | length' <<< "$FILES")
    CAMPAIGN_COUNT=$(jq '[.[] | select(.path | startswith("campaign/"))] | length' <<< "$FILES")
    REPORTS=$(jq '[.[] | select(.path | startswith("reports/"))] | length' <<< "$FILES")
    RESPONSE=$(jq '[.[] | select(.path | startswith("response/"))] | length' <<< "$FILES")
    HANDOFF_COUNT=$(jq '[.[] | select(.path | startswith("handoff/"))] | length' <<< "$FILES")

    jq -n \
        --arg shift "$SHIFT_ID" \
        --arg host "$ANALYST_HOST" \
        --arg started "$STARTED_AT" \
        --arg ended "$ENDED_AT" \
        --argjson duration "$DURATION" \
        --argjson files "$FILES" \
        --argjson runtime "$RUNTIME" \
        --argjson enriched "$ENRICHED" \
        --argjson alerts "$ALERTS" \
        --argjson investigations "$INVESTIGATIONS" \
        --argjson campaign_count "$CAMPAIGN_COUNT" \
        --argjson reports "$REPORTS" \
        --argjson response "$RESPONSE" \
        --argjson handoff "$HANDOFF_COUNT" \
        --argjson incidents "$INCIDENT_IDS" \
        --argjson linked "$CAMPAIGN_LINKED" \
        --arg cluster "$CLUSTER" \
        '{
            shift_id:$shift,
            analyst_host:$host,
            started_at:$started,
            ended_at:$ended,
            duration_hours:$duration,
            files:$files,
            artifact_counts:{
                runtime:$runtime,
                enriched:$enriched,
                alerts:$alerts,
                investigations:$investigations,
                campaign:$campaign_count,
                reports:$reports,
                response:$response,
                handoff:$handoff
            },
            incident_ids:$incidents,
            campaign_linked:$linked,
            cluster_id:$cluster
        }' > "$manifest_tmp"

    cp "$manifest_tmp" "$MANIFEST"
}

build_manifest

jq -r '.files[] | "\(.path) | \(.sha256)"' "$MANIFEST" >> "$HANDOFF"

build_manifest

WORDS=$(wc -w < "$HANDOFF")

[ "$WORDS" -le 900 ] || {
    echo "[handoff] shift_handoff.md exceeds 900 words: $WORDS" >&2
    exit 1
}

SECTIONS=(
    "## Shift Identifier"
    "## Situation"
    "## Incidents"
    "## Campaign Assessment"
    "## Open Items for Next Shift"
    "## Artifact Index"
)

for SECTION in "${SECTIONS[@]}"; do
    grep -Fxq "$SECTION" "$HANDOFF" || {
        echo "[handoff] missing section: $SECTION" >&2
        exit 1
    }
done

echo "[handoff] shift_handoff.md: $WORDS words, 6 sections OK"

HANDOFF_IDS=$(grep -oE 'INC-[0-9]{8}-[A-Z]' "$HANDOFF" | sort -u)

while IFS= read -r ID; do
    [ -n "$ID" ] || continue

    jq -e --arg id "$ID" '
        any(.incidents[]; .incident_id == $id)
    ' "$INCIDENTS" >/dev/null || {
        echo "[handoff] incident ID mismatch: $ID" >&2
        exit 1
    }
done <<< "$HANDOFF_IDS"

echo "[handoff] incident IDs in handoff: $(echo "$HANDOFF_IDS" | tr '\n' ' ') (all in incidents.json: OK)"

FILE_COUNT=$(jq '.files | length' "$MANIFEST")
TOTAL_BYTES=$(jq '[.files[].size] | add // 0' "$MANIFEST")
TOTAL_KB=$(awk -v bytes="$TOTAL_BYTES" 'BEGIN {printf "%.1f", bytes/1024}')

echo "[handoff] MANIFEST.json: $FILE_COUNT files, $TOTAL_KB KB total"
echo "[handoff] campaign_linked=$CAMPAIGN_LINKED cluster=$CLUSTER"
echo "[handoff] handoff package complete"
