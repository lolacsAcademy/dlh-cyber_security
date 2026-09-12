#!/bin/bash
set -euo pipefail

INV="$SHIFT_WORKSPACE/investigations"
INCIDENTS="$SHIFT_WORKSPACE/alerts/incidents.json"
EVENTS="$SHIFT_WORKSPACE/enriched/enriched_events.json"
IOCS="$ASSETS_DIR/ioc_feed.json"
SUMMARY="$WAZUH_EXPORTS/campaign_dashboard_summary.md"
WORKFLOW="$WAZUH_EXPORTS/exported_dashboard_workflow.json"
OUTDIR="$SHIFT_WORKSPACE/campaign"
OUT="$OUTDIR/campaign_assessment.json"

A="$INV/incident_A.json"
B="$INV/incident_B.json"
C="$INV/incident_C_cli.json"

echo "[campaign] loading 3 incident findings"

for f in "$A" "$B" "$C" "$INCIDENTS" "$EVENTS" "$IOCS" "$SUMMARY" "$WORKFLOW"; do
    [ -s "$f" ] || {
        echo "[campaign] missing or empty required file: $f" >&2
        exit 1
    }
done

for f in "$A" "$B" "$C" "$INCIDENTS" "$IOCS" "$WORKFLOW"; do
    jq -e '.' "$f" >/dev/null || {
        echo "[campaign] invalid JSON: $f" >&2
        exit 1
    }
done

mkdir -p "$OUTDIR"

IOC_COUNT=$(jq '.iocs | length' "$IOCS")
echo "[campaign] ioc feed: $IOC_COUNT IOCs loaded"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

jq -r '.iocs[].value' "$IOCS" | sort -u > "$TMP/feed"

for X in A B C; do
    case "$X" in
        A) FINDING="$A" ;;
        B) FINDING="$B" ;;
        C) FINDING="$C" ;;
    esac

    jq -r '.event_refs[]? // empty' "$FINDING" > "$TMP/${X}_refs"

    jq -r --arg suffix "$X" '
        .incidents[]
        | select(.incident_id | endswith("-" + $suffix))
        | .matches_ioc[]?
    ' "$INCIDENTS" | sort -u > "$TMP/${X}_iocs"

    jq -r '.attack_techniques[]? // empty' "$FINDING" |
        sort -u > "$TMP/${X}_techniques"

    jq -r --arg suffix "$X" '
        .incidents[]
        | select(.incident_id | endswith("-" + $suffix))
        | .host_list[]?
    ' "$INCIDENTS" |
        tr '[:upper:]' '[:lower:]' |
        sort -u > "$TMP/${X}_hosts"

    jq -r --arg suffix "$X" '
        .incidents[]
        | select(.incident_id | endswith("-" + $suffix))
        | .user_list[]?
    ' "$INCIDENTS" |
        sort -u > "$TMP/${X}_users"

    : > "$TMP/${X}_feed_hits"

    while IFS= read -r ref; do
        [ -n "$ref" ] || continue

        jq -c --arg ref "$ref" '
            select(
                ((.event_ref // .event_id // .id // "") | tostring) == $ref
            )
        ' "$EVENTS" |
        jq -r '
            [
                .src_ip,
                .dst_ip,
                .user,
                .event_data.IpAddress,
                .event_data.SourceIp,
                .event_data.DestinationIp,
                .event_data.TargetUserName
            ]
            | .[]
            | select(. != null)
            | tostring
        ' |
        while IFS= read -r value; do
            if grep -Fxq "$value" "$TMP/feed"; then
                echo "$value"
            fi
        done >> "$TMP/${X}_feed_hits"
    done < "$TMP/${X}_refs"

    sort -u "$TMP/${X}_feed_hits" -o "$TMP/${X}_feed_hits"
done

A_FEED=$(wc -l < "$TMP/A_feed_hits")
B_FEED=$(wc -l < "$TMP/B_feed_hits")
C_FEED=$(wc -l < "$TMP/C_feed_hits")

overlap_count() {
    comm -12 "$TMP/$1_$3" "$TMP/$2_$3" | wc -l
}

AB_IOC=$(overlap_count A B iocs)
AC_IOC=$(overlap_count A C iocs)
BC_IOC=$(overlap_count B C iocs)

AB_TAC=$(overlap_count A B techniques)
AC_TAC=$(overlap_count A C techniques)
BC_TAC=$(overlap_count B C techniques)

AB_HOST=$(overlap_count A B hosts)
AC_HOST=$(overlap_count A C hosts)
BC_HOST=$(overlap_count B C hosts)

AB_USER=$(overlap_count A B users)
AC_USER=$(overlap_count A C users)
BC_USER=$(overlap_count B C users)

temporal_distance() {
    local X="$1"
    local Y="$2"

    local X_LAST Y_FIRST X_SEC Y_SEC DIFF

    X_LAST=$(jq -r --arg suffix "$X" '
        .incidents[]
        | select(.incident_id | endswith("-" + $suffix))
        | .last_seen
    ' "$INCIDENTS")

    Y_FIRST=$(jq -r --arg suffix "$Y" '
        .incidents[]
        | select(.incident_id | endswith("-" + $suffix))
        | .first_seen
    ' "$INCIDENTS")

    X_SEC=$(date -u -d "$X_LAST" +%s)
    Y_SEC=$(date -u -d "$Y_FIRST" +%s)

    DIFF=$((Y_SEC - X_SEC))
    [ "$DIFF" -lt 0 ] && DIFF=$((-DIFF))

    echo $((DIFF / 60))
}

AB_TIME=$(temporal_distance A B)
AC_TIME=$(temporal_distance A C)
BC_TIME=$(temporal_distance B C)

echo "[campaign] A-B: ioc_overlap=$AB_IOC tactic_overlap=$AB_TAC temporal_dist=${AB_TIME}min"
echo "[campaign] A-C: ioc_overlap=$AC_IOC tactic_overlap=$AC_TAC temporal_dist=${AC_TIME}min"
echo "[campaign] B-C: ioc_overlap=$BC_IOC tactic_overlap=$BC_TAC temporal_dist=${BC_TIME}min"
echo "[campaign] feed matches: A=$A_FEED B=$B_FEED C=$C_FEED"

LINKED=()

if { [ "$AB_IOC" -ge 1 ] && { [ "$A_FEED" -gt 0 ] || [ "$B_FEED" -gt 0 ]; }; } ||
   { [ "$AB_TAC" -ge 2 ] && [ "$AB_TIME" -le 360 ]; } ||
   [ "$AB_USER" -ge 1 ] || [ "$AB_HOST" -ge 1 ]; then
    LINKED+=("A-B")
fi

if { [ "$AC_IOC" -ge 1 ] && { [ "$A_FEED" -gt 0 ] || [ "$C_FEED" -gt 0 ]; }; } ||
   { [ "$AC_TAC" -ge 2 ] && [ "$AC_TIME" -le 360 ]; } ||
   [ "$AC_USER" -ge 1 ] || [ "$AC_HOST" -ge 1 ]; then
    LINKED+=("A-C")
fi

if { [ "$BC_IOC" -ge 1 ] && { [ "$B_FEED" -gt 0 ] || [ "$C_FEED" -gt 0 ]; }; } ||
   { [ "$BC_TAC" -ge 2 ] && [ "$BC_TIME" -le 360 ]; } ||
   [ "$BC_USER" -ge 1 ] || [ "$BC_HOST" -ge 1 ]; then
    LINKED+=("B-C")
fi

LINKED_COUNT=${#LINKED[@]}

if [ "$LINKED_COUNT" -ge 2 ]; then
    CAMPAIGN=true
else
    CAMPAIGN=false
fi

DIRECT_FEED=false

for pair in "${LINKED[@]}"; do
    case "$pair" in
        A-B)
            if [ "$A_FEED" -gt 0 ] || [ "$B_FEED" -gt 0 ]; then
                DIRECT_FEED=true
            fi
            ;;
        A-C)
            if [ "$A_FEED" -gt 0 ] || [ "$C_FEED" -gt 0 ]; then
                DIRECT_FEED=true
            fi
            ;;
        B-C)
            if [ "$B_FEED" -gt 0 ] || [ "$C_FEED" -gt 0 ]; then
                DIRECT_FEED=true
            fi
            ;;
    esac
done

if [ "$CAMPAIGN" = true ] && [ "$DIRECT_FEED" = true ]; then
    CLUSTER="HC-RED7"
else
    CLUSTER="unknown"
fi

if [ "$CAMPAIGN" = true ] && [ "$CLUSTER" = "HC-RED7" ]; then
    CONFIDENCE="high"
elif [ "$CAMPAIGN" = true ]; then
    CONFIDENCE="medium"
else
    CONFIDENCE="low"
fi

EXPORT_VERDICT=$(grep -iE 'campaign_linked|cluster|HC-RED7' "$SUMMARY" |
    head -1 |
    sed 's/^[[:space:]#*-]*//' || true)

[ -n "$EXPORT_VERDICT" ] ||
    EXPORT_VERDICT="No campaign verdict found in export summary"

echo "[campaign] linked pairs: ${LINKED[*]:-none}"
echo "[campaign] export view: $EXPORT_VERDICT"
echo "[campaign] verdict: campaign_linked=$CAMPAIGN cluster=$CLUSTER confidence=$CONFIDENCE"

LINKED_JSON=$(printf '%s\n' "${LINKED[@]}" |
    jq -R -s 'split("\n") | map(select(length > 0))')

INCIDENT_IDS=$(jq '[
    .incidents[]
    | select(
        (.incident_id | endswith("-A"))
        or (.incident_id | endswith("-B"))
        or (.incident_id | endswith("-C"))
    )
    | .incident_id
]' "$INCIDENTS")

SHARED_IOCS=$((AB_IOC + AC_IOC + BC_IOC))
SHARED_TACTICS=$((AB_TAC + AC_TAC + BC_TAC))

jq -n \
    --argjson incidents "$INCIDENT_IDS" \
    --argjson ab_ioc "$AB_IOC" \
    --argjson ac_ioc "$AC_IOC" \
    --argjson bc_ioc "$BC_IOC" \
    --argjson ab_tac "$AB_TAC" \
    --argjson ac_tac "$AC_TAC" \
    --argjson bc_tac "$BC_TAC" \
    --argjson ab_time "$AB_TIME" \
    --argjson ac_time "$AC_TIME" \
    --argjson bc_time "$BC_TIME" \
    --argjson a_feed "$A_FEED" \
    --argjson b_feed "$B_FEED" \
    --argjson c_feed "$C_FEED" \
    --argjson linked "$LINKED_JSON" \
    --argjson campaign "$CAMPAIGN" \
    --arg cluster "$CLUSTER" \
    --arg confidence "$CONFIDENCE" \
    --arg export "$EXPORT_VERDICT" \
    --argjson shared_iocs "$SHARED_IOCS" \
    --argjson shared_tactics "$SHARED_TACTICS" \
    '{
        incidents: $incidents,
        ioc_overlap_matrix: {
            "A-B": $ab_ioc,
            "A-C": $ac_ioc,
            "B-C": $bc_ioc
        },
        tactic_overlap_matrix: {
            "A-B": $ab_tac,
            "A-C": $ac_tac,
            "B-C": $bc_tac
        },
        temporal_distance_minutes: {
            "A-B": $ab_time,
            "A-C": $ac_time,
            "B-C": $bc_time
        },
        ioc_feed_matches: {
            A: $a_feed,
            B: $b_feed,
            C: $c_feed
        },
        linked_pairs: $linked,
        campaign_linked: $campaign,
        cluster_id: $cluster,
        confidence: $confidence,
        export_view_verdict: $export,
        supporting_counts: {
            shared_iocs_total: $shared_iocs,
            shared_tactics_total: $shared_tactics
        }
    }' > "$OUT"

echo "[campaign] campaign_assessment.json written"
