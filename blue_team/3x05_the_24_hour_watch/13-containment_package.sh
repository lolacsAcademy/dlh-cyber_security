#!/bin/bash
set -euo pipefail

CAMPAIGN="$SHIFT_WORKSPACE/campaign/campaign_assessment.json"
INCIDENTS="$SHIFT_WORKSPACE/alerts/incidents.json"
INV="$SHIFT_WORKSPACE/investigations"
EVENTS="$SHIFT_WORKSPACE/enriched/enriched_events.json"
FEED="$ASSETS_DIR/ioc_feed.json"
SHIFT_START="$SHIFT_WORKSPACE/runtime/shift_start.json"
OUTDIR="$SHIFT_WORKSPACE/response"
CONTAINMENT="$OUTDIR/containment.json"
IOC_PACKAGE="$OUTDIR/ioc_package.json"

echo "[resp] loading campaign_assessment and incidents"

for f in "$CAMPAIGN" "$INCIDENTS" "$EVENTS" "$FEED" "$SHIFT_START"; do
    [ -s "$f" ] || {
        echo "[resp] missing or empty required file: $f" >&2
        exit 1
    }
done

for f in \
    "$INV/incident_A.json" \
    "$INV/incident_B.json" \
    "$INV/incident_C_cli.json"
do
    [ -s "$f" ] || {
        echo "[resp] missing or empty finding: $f" >&2
        exit 1
    }
done

mkdir -p "$OUTDIR"

SHIFT_ID=$(jq -r '.shift_id' "$SHIFT_START")
CLUSTER=$(jq -r '
    if .campaign_linked == true and .cluster_id == "HC-RED7"
    then "HC-RED7"
    else "unknown"
    end
' "$CAMPAIGN")

GENERATED=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

: > "$TMP/actions"
: > "$TMP/iocs"

ACTION_NUM=0

add_action() {
    local PRIORITY="$1"
    local ACTION="$2"
    local TYPE="$3"
    local VALUE="$4"
    local INCIDENT="$5"
    local IMPACT="$6"
    local APPROVAL="$7"

    [ -n "$VALUE" ] || return 0
    [ "$ACTION_NUM" -lt 12 ] || return 0

    if ! jq -e --arg id "$INCIDENT" '
        any(.incidents[]; .incident_id == $id)
    ' "$INCIDENTS" >/dev/null; then
        echo "[resp] invalid incident_id in action: $INCIDENT" >&2
        exit 1
    fi

    ACTION_NUM=$((ACTION_NUM + 1))
    ACTION_ID=$(printf 'ACT-%03d' "$ACTION_NUM")

    jq -cn \
        --arg id "$ACTION_ID" \
        --arg priority "$PRIORITY" \
        --arg action "$ACTION" \
        --arg type "$TYPE" \
        --arg value "$VALUE" \
        --arg incident "$INCIDENT" \
        --arg impact "$IMPACT" \
        --arg approval "$APPROVAL" \
        '{
            action_id:$id,
            priority:$priority,
            action:$action,
            target_type:$type,
            target_value:$value,
            incident_id:$incident,
            operational_impact:$impact,
            requires_approval_from:$approval
        }' >> "$TMP/actions"
}

for LETTER in A B C; do
    case "$LETTER" in
        A) FINDING="$INV/incident_A.json" ;;
        B) FINDING="$INV/incident_B.json" ;;
        C) FINDING="$INV/incident_C_cli.json" ;;
    esac

    INCIDENT_ID=$(jq -r '.incident_id' "$FINDING")

    jq -e --arg id "$INCIDENT_ID" '
        any(.incidents[]; .incident_id == $id)
    ' "$INCIDENTS" >/dev/null || {
        echo "[resp] finding cites non-existent incident: $INCIDENT_ID" >&2
        exit 1
    }

    HOST=$(jq -r '
        (.hosts[0] // .host_list[0] // empty)
    ' "$FINDING")

    if [ -n "$HOST" ]; then
        add_action \
            "immediate" \
            "Isolate confirmed compromised host from the network." \
            "host" \
            "$HOST" \
            "$INCIDENT_ID" \
            "Host network connectivity is interrupted during containment." \
            "SOC incident commander"
    fi

    jq -r '.matches_ioc[]? // empty' "$FINDING" |
    while IFS= read -r IOC; do
        TYPE=$(jq -r --arg value "$IOC" '
            first(.iocs[] | select(.value == $value) | .type) // empty
        ' "$FEED")

        if [ "$TYPE" = "ip" ]; then
            add_action \
                "immediate" \
                "Block confirmed IOC IP at the perimeter firewall." \
                "ip" \
                "$IOC" \
                "$INCIDENT_ID" \
                "Traffic to or from the IOC IP is blocked." \
                "on-call network engineer"
        fi
    done

    jq -r '
        (.users[]? // empty),
        (.accounts[]? // empty)
    ' "$FINDING" | sort -u |
    while IFS= read -r USER; do
        [ -n "$USER" ] || continue

        add_action \
            "short_term" \
            "Reset credentials for account identified in the investigation." \
            "user" \
            "$USER" \
            "$INCIDENT_ID" \
            "Existing sessions or dependent services may require reauthentication." \
            "identity and access management"
    done

    jq -r '.matches_ioc[]? // empty' "$FINDING" |
    while IFS= read -r IOC; do
        TYPE=$(jq -r --arg value "$IOC" '
            first(.iocs[] | select(.value == $value) | .type) // empty
        ' "$FEED")

        if [ "$TYPE" = "service_name" ]; then
            add_action \
                "short_term" \
                "Audit service accounts matching the identified IOC service pattern." \
                "service" \
                "$IOC" \
                "$INCIDENT_ID" \
                "Service ownership and authentication activity require review." \
                "SOC lead"
        fi
    done

    if [ -n "$HOST" ]; then
        add_action \
            "medium_term" \
            "Review and tighten firewall rules for the affected host zone." \
            "rule" \
            "$HOST" \
            "$INCIDENT_ID" \
            "Firewall policy changes may affect legitimate application traffic." \
            "security architecture review"

        add_action \
            "medium_term" \
            "Deploy additional Sysmon rules on the affected host." \
            "rule" \
            "$HOST" \
            "$INCIDENT_ID" \
            "Additional telemetry may increase endpoint logging volume." \
            "security architecture review"
    fi
done

ACTIONS_JSON=$(jq -s '.' "$TMP/actions")

IMMEDIATE=$(jq '[.[] | select(.priority=="immediate")] | length' <<< "$ACTIONS_JSON")
SHORT=$(jq '[.[] | select(.priority=="short_term")] | length' <<< "$ACTIONS_JSON")
MEDIUM=$(jq '[.[] | select(.priority=="medium_term")] | length' <<< "$ACTIONS_JSON")
TOTAL=$(jq 'length' <<< "$ACTIONS_JSON")

[ "$TOTAL" -le 12 ] || {
    echo "[resp] containment action cap exceeded" >&2
    exit 1
}

echo "[resp] actions: immediate=$IMMEDIATE short_term=$SHORT medium_term=$MEDIUM total=$TOTAL"

jq -n \
    --arg shift "$SHIFT_ID" \
    --arg generated "$GENERATED" \
    --argjson actions "$ACTIONS_JSON" \
    '{
        shift_id:$shift,
        generated_at:$generated,
        actions:$actions
    }' > "$CONTAINMENT"

for LETTER in A B C; do
    case "$LETTER" in
        A) FINDING="$INV/incident_A.json" ;;
        B) FINDING="$INV/incident_B.json" ;;
        C) FINDING="$INV/incident_C_cli.json" ;;
    esac

    INCIDENT_ID=$(jq -r '.incident_id' "$FINDING")

    FIRST=$(jq -r --arg id "$INCIDENT_ID" '
        .incidents[]
        | select(.incident_id==$id)
        | .first_seen
    ' "$INCIDENTS")

    LAST=$(jq -r --arg id "$INCIDENT_ID" '
        .incidents[]
        | select(.incident_id==$id)
        | .last_seen
    ' "$INCIDENTS")

    jq -r '.event_refs[]? // empty' "$FINDING" > "$TMP/${LETTER}_refs"

    jq -r '.matches_ioc[]? // empty' "$FINDING" |
    sort -u |
    while IFS= read -r VALUE; do
        [ -n "$VALUE" ] || continue

        FEED_ROW=$(jq -c --arg value "$VALUE" '
            first(.iocs[] | select(.value==$value)) // empty
        ' "$FEED")

        if [ -n "$FEED_ROW" ]; then
            TYPE=$(jq -r '.type' <<< "$FEED_ROW")
            CONF=$(jq -r '.confidence // "medium"' <<< "$FEED_ROW")
            SOURCE="ioc_feed"
        else
            TYPE=$(jq -r --arg value "$VALUE" '
                if $value | test("^[0-9]{1,3}(\\.[0-9]{1,3}){3}$") then "ip"
                elif $value | test("^[A-Fa-f0-9]{32,64}$") then "hash"
                elif $value | test("^[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$") then "domain"
                else "account"
                end
            ' <<< '{}')
            CONF="medium"
            SOURCE="shift_discovered"
        fi

        BACKED=false

        while IFS= read -r REF; do
            [ -n "$REF" ] || continue

            if jq -e --arg ref "$REF" --arg value "$VALUE" '
                select(
                    ((.event_ref // .event_id // .id // "") | tostring) == $ref
                )
                | tostring
                | contains($value)
            ' "$EVENTS" >/dev/null; then
                BACKED=true
                break
            fi
        done < "$TMP/${LETTER}_refs"

        if [ "$BACKED" != true ]; then
            echo "[resp] IOC has no event backing: $VALUE ($INCIDENT_ID)" >&2
            exit 1
        fi

        DEFANGED="$VALUE"

        if [ "$TYPE" = "ip" ]; then
            DEFANGED=$(printf '%s' "$VALUE" | sed 's/\./[.]/g')
        elif [ "$TYPE" = "domain" ]; then
            DEFANGED=$(printf '%s' "$VALUE" | sed 's/\./[.]/g')
        fi

        jq -cn \
            --arg type "$TYPE" \
            --arg value "$DEFANGED" \
            --arg first "$FIRST" \
            --arg last "$LAST" \
            --arg incident "$INCIDENT_ID" \
            --arg source "$SOURCE" \
            --arg confidence "$CONF" \
            '{
                type:$type,
                value:$value,
                first_seen:$first,
                last_seen:$last,
                incident_id:$incident,
                source:$source,
                confidence:$confidence
            }' >> "$TMP/iocs"
    done
done

IOCS_JSON=$(jq -s 'unique_by(.type,.value,.incident_id)' "$TMP/iocs")

IP_COUNT=$(jq '[.[] | select(.type=="ip")] | length' <<< "$IOCS_JSON")
DOMAIN_COUNT=$(jq '[.[] | select(.type=="domain")] | length' <<< "$IOCS_JSON")
HASH_COUNT=$(jq '[.[] | select(.type=="hash")] | length' <<< "$IOCS_JSON")
ACCOUNT_COUNT=$(jq '[.[] | select(.type=="account")] | length' <<< "$IOCS_JSON")
SERVICE_COUNT=$(jq '[.[] | select(.type=="service_name")] | length' <<< "$IOCS_JSON")
IOC_TOTAL=$(jq 'length' <<< "$IOCS_JSON")
NEW_COUNT=$(jq '[.[] | select(.source=="shift_discovered")] | length' <<< "$IOCS_JSON")

echo "[resp] IOCs: ip=$IP_COUNT domain=$DOMAIN_COUNT hash=$HASH_COUNT account=$ACCOUNT_COUNT service=$SERVICE_COUNT total=$IOC_TOTAL"
echo "[resp] newly discovered (not in feed): $NEW_COUNT"
echo "[resp] all IOCs traced to events: OK"

jq -n \
    --arg shift "$SHIFT_ID" \
    --arg cluster "$CLUSTER" \
    --arg generated "$GENERATED" \
    --argjson iocs "$IOCS_JSON" \
    '{
        shift_id:$shift,
        tlp:"AMBER",
        cluster_id:$cluster,
        generated_at:$generated,
        iocs:$iocs
    }' > "$IOC_PACKAGE"

echo "[resp] containment.json written"
echo "[resp] ioc_package.json written"
