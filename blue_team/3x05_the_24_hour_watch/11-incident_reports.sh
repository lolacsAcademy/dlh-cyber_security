#!/bin/bash
set -euo pipefail

INV="$SHIFT_WORKSPACE/investigations"
INCIDENTS="$SHIFT_WORKSPACE/alerts/incidents.json"
EVENTS="$SHIFT_WORKSPACE/enriched/enriched_events.json"
ASSETS="$ASSETS_DIR/assets.json"
IOCS="$ASSETS_DIR/ioc_feed.json"
OUTDIR="$SHIFT_WORKSPACE/reports"

mkdir -p "$OUTDIR"

for f in "$INCIDENTS" "$EVENTS" "$ASSETS" "$IOCS"; do
    [ -s "$f" ] || {
        echo "[report] missing or empty required file: $f" >&2
        exit 1
    }
done

TOTAL_VERIFIED=0

for LETTER in A B C; do
    case "$LETTER" in
        A) FINDING="$INV/incident_A.json" ;;
        B) FINDING="$INV/incident_B.json" ;;
        C) FINDING="$INV/incident_C_cli.json" ;;
    esac

    OUT="$OUTDIR/incident_${LETTER}.md"

    echo "[report] generating incident_${LETTER}.md"

    [ -s "$FINDING" ] || {
        echo "[report] missing or empty finding: $FINDING" >&2
        exit 1
    }

    INCIDENT_ID=$(jq -r '.incident_id' "$FINDING")

    INCIDENT=$(jq -c --arg id "$INCIDENT_ID" '
        .incidents[]
        | select(.incident_id == $id)
    ' "$INCIDENTS")

    [ -n "$INCIDENT" ] || {
        echo "[report] incident not found: $INCIDENT_ID" >&2
        exit 1
    }

    TMP=$(mktemp -d)

    jq -r '.event_refs[]? // empty' "$FINDING" |
        head -12 > "$TMP/refs"

    while IFS= read -r REF; do
        [ -n "$REF" ] || continue

        if ! jq -e --arg ref "$REF" '
            select(
                ((.event_ref // .event_id // .id // "") | tostring) == $ref
            )
        ' "$EVENTS" >/dev/null; then
            echo "[report] missing event reference: $REF" >&2
            rm -rf "$TMP"
            exit 1
        fi

        TOTAL_VERIFIED=$((TOTAL_VERIFIED + 1))
    done < "$TMP/refs"

    : > "$TMP/timeline"

    while IFS= read -r REF; do
        [ -n "$REF" ] || continue

        jq -r --arg ref "$REF" '
            select(
                ((.event_ref // .event_id // .id // "") | tostring) == $ref
            )
            | [
                (.timestamp // "unknown"),
                (.hostname // "unknown"),
                (
                    .raw_message
                    // .event_description
                    // .event_category
                    // "event"
                )
            ]
            | @tsv
        ' "$EVENTS"
    done < "$TMP/refs" |
        head -15 |
        awk -F '\t' '{print $1 " | " $2 " | " $3}' > "$TMP/timeline"

    jq -r '.host_list[]?' <<< "$INCIDENT" |
        head -10 > "$TMP/hosts"

    : > "$TMP/assets"

    while IFS= read -r HOST; do
        [ -n "$HOST" ] || continue

        jq -r --arg host "$HOST" '
            .assets[]
            | select(
                (.hostname // "" | ascii_downcase)
                == ($host | ascii_downcase)
            )
            | [
                (.hostname // $host),
                (.criticality // "unknown"),
                (.data_classification // "unknown"),
                (.zone // "unknown")
            ]
            | @tsv
        ' "$ASSETS" |
            head -1 |
            awk -F '\t' '{print $1 " | " $2 " | " $3 " | " $4}'
    done < "$TMP/hosts" > "$TMP/assets"

    jq -r '.matches_ioc[]? // empty' "$FINDING" |
        head -15 > "$TMP/ioc_values"

    : > "$TMP/ioc_rows"

    while IFS= read -r VALUE; do
        [ -n "$VALUE" ] || continue

        ROW=$(jq -r --arg value "$VALUE" '
            .iocs[]
            | select(.value == $value)
            | [
                (.type // "unknown"),
                .value,
                (.confidence // "unknown"),
                (.source // "IOC feed")
            ]
            | @tsv
        ' "$IOCS" | head -1)

        if [ -n "$ROW" ]; then
            printf '%s\n' "$ROW" |
                sed -E 's/([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})/\1[.]\2[.]\3[.]\4/g' |
                awk -F '\t' '{print $1 " | " $2 " | " $3 " | " $4}' \
                >> "$TMP/ioc_rows"
        fi
    done < "$TMP/ioc_values"

    jq -r '.attack_techniques[]? // empty' "$FINDING" |
        head -8 > "$TMP/techniques"

    : > "$TMP/attack"

    while IFS= read -r TECH; do
        [ -n "$TECH" ] || continue
        printf '%s | %s | %s\n' \
            "$TECH" \
            "ATT&CK technique" \
            "Supported by investigation finding" \
            >> "$TMP/attack"
    done < "$TMP/techniques"

    jq -r '.recommended_actions[]? // .actions[]? // empty' "$FINDING" |
        head -6 |
        nl -w1 -s'. ' > "$TMP/actions"

    TIMELINE_COUNT=$(wc -l < "$TMP/timeline")
    ASSET_COUNT=$(wc -l < "$TMP/assets")
    IOC_COUNT=$(wc -l < "$TMP/ioc_rows")
    TECH_COUNT=$(wc -l < "$TMP/attack")
    ACTION_COUNT=$(wc -l < "$TMP/actions")
    REF_COUNT=$(wc -l < "$TMP/refs")

    [ "$TIMELINE_COUNT" -le 15 ] || exit 1
    [ "$ASSET_COUNT" -le 10 ] || exit 1
    [ "$IOC_COUNT" -le 15 ] || exit 1
    [ "$TECH_COUNT" -le 8 ] || exit 1
    [ "$ACTION_COUNT" -le 6 ] || exit 1
    [ "$REF_COUNT" -le 12 ] || exit 1

    HYPOTHESIS=$(jq -r '.hypothesis // "Investigation finding recorded."' "$FINDING")
    CONFIDENCE=$(jq -r '.confidence // "unknown"' "$FINDING")
    VERDICT=$(jq -r '.verdict // .classification // "unknown"' "$FINDING")

    {
        echo "# Incident Report — $INCIDENT_ID"
        echo
        echo "## Executive Summary"
        echo "This report documents $INCIDENT_ID from the current SOC shift."
        echo "The investigation classified the activity as $VERDICT with $CONFIDENCE confidence."
        echo "$HYPOTHESIS"
        echo "The sections below summarize the counted evidence supporting the investigation."
        echo
        echo "## Timeline"
        cat "$TMP/timeline"
        echo
        echo "## Affected Assets"
        echo "HOST | CRITICALITY | DATA_CLASS | ZONE"
        echo "--- | --- | --- | ---"
        cat "$TMP/assets"
        echo
        echo "## Indicators of Compromise"
        echo "TYPE | VALUE | CONFIDENCE | SOURCE"
        echo "--- | --- | --- | ---"
        cat "$TMP/ioc_rows"
        echo
        echo "## ATT&CK Mapping"
        echo "TECHNIQUE | NAME | EVIDENCE"
        echo "--- | --- | ---"
        cat "$TMP/attack"
        echo
        echo "## Detection Performance"

        jq -r '
            .detection_performance[]?
            // .rules_fired[]?
            // empty
        ' "$FINDING" || true

        echo
        echo "## Recommended Actions"
        cat "$TMP/actions"
        echo
        echo "## Evidence References"
        cat "$TMP/refs"
    } |
        sed -E 's/([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})/\1[.]\2[.]\3[.]\4/g' \
        > "$OUT"

    echo "[report] $LETTER: timeline=$TIMELINE_COUNT assets=$ASSET_COUNT IOCs=$IOC_COUNT techniques=$TECH_COUNT actions=$ACTION_COUNT refs=$REF_COUNT"
    echo "[report] $LETTER: section caps respected"

    rm -rf "$TMP"
done

echo "[report] $TOTAL_VERIFIED event references verified against enriched_events.jsonl"
echo "[report] reports written"
