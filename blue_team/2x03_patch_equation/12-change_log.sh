#!/bin/bash
set -uo pipefail

OUT="patch_change_log.json"
WIN_FILE="maintenance_windows.json"
VULN_FILE="vulnerability_inventory.json"
EXEC_LOG="patch_execution_log.json"

TZ_NAME="Europe/Paris"
[ -f "$WIN_FILE" ] && TZ_NAME=$(jq -r '.timezone' "$WIN_FILE")

LOG_FILES=$(ls /var/log/apt/history.log /var/log/apt/history.log.*.gz 2>/dev/null)

TRANSACTIONS="[]"
for f in $LOG_FILES; do
    if [[ "$f" == *.gz ]]; then
        CONTENT_CMD="zcat \"$f\""
    else
        CONTENT_CMD="cat \"$f\""
    fi

    while IFS=$'\x01' read -r sd cl rb up ins rem; do
        [ -z "$sd" ] && continue
        pkg_count=0
        [ -n "$up" ] && pkg_count=$((pkg_count + $(echo "$up" | tr ',' '\n' | grep -c .)))
        [ -n "$ins" ] && pkg_count=$((pkg_count + $(echo "$ins" | tr ',' '\n' | grep -c .)))
        [ -n "$rem" ] && pkg_count=$((pkg_count + $(echo "$rem" | tr ',' '\n' | grep -c .)))
        user=$(echo "$rb" | awk '{print $1}')
        [ -z "$user" ] && user="unknown"

        entry=$(jq -n --arg sd "$sd" --arg cl "$cl" --arg u "$user" --argjson pc "$pkg_count" \
            '{start_date:$sd, commandline:$cl, user:$u, packages:$pc}')
        TRANSACTIONS=$(echo "$TRANSACTIONS" | jq --argjson e "$entry" '. + [$e]')
    done < <(eval "$CONTENT_CMD" | awk -v RS="" '{
        sd=""; cl=""; rb=""; up=""; ins=""; rem="";
        n=split($0, arr, "\n");
        for(i=1;i<=n;i++){
            if(arr[i] ~ /^Start-Date: /) { sd=arr[i]; sub(/^Start-Date: /,"",sd); }
            else if(arr[i] ~ /^Commandline: /) { cl=arr[i]; sub(/^Commandline: /,"",cl); }
            else if(arr[i] ~ /^Requested-By: /) { rb=arr[i]; sub(/^Requested-By: /,"",rb); }
            else if(arr[i] ~ /^Upgrade: /) { up=arr[i]; sub(/^Upgrade: /,"",up); }
            else if(arr[i] ~ /^Install: /) { ins=arr[i]; sub(/^Install: /,"",ins); }
            else if(arr[i] ~ /^Remove: /) { rem=arr[i]; sub(/^Remove: /,"",rem); }
        }
        if (sd != "") print sd "\x01" cl "\x01" rb "\x01" up "\x01" ins "\x01" rem;
    }')
done

TRANSACTIONS=$(echo "$TRANSACTIONS" | jq 'sort_by(.start_date)')

EVENTS="[]"
TXN_COUNT=$(echo "$TRANSACTIONS" | jq 'length')

if [ "$TXN_COUNT" -gt 0 ]; then
    prev_epoch=0
    current_event_start=""
    current_event_user=""
    current_event_pkgs=0

    i=0
    while [ "$i" -lt "$TXN_COUNT" ]; do
        txn=$(echo "$TRANSACTIONS" | jq -c ".[$i]")
        sd=$(echo "$txn" | jq -r '.start_date')
        u=$(echo "$txn" | jq -r '.user')
        pc=$(echo "$txn" | jq -r '.packages')

        epoch=$(date -d "$sd" +%s 2>/dev/null || echo 0)

        if [ "$prev_epoch" -eq 0 ] || [ $((epoch - prev_epoch)) -gt 900 ]; then
            if [ -n "$current_event_start" ]; then
                iso_start=$(date -d "$current_event_start" -Iseconds 2>/dev/null)
                EVENTS=$(echo "$EVENTS" | jq --arg s "$iso_start" --arg u "$current_event_user" --argjson p "$current_event_pkgs" \
                    '. + [{started:$s, user:$u, packages:$p}]')
            fi
            current_event_start="$sd"
            current_event_user="$u"
            current_event_pkgs="$pc"
        else
            current_event_pkgs=$((current_event_pkgs + pc))
        fi

        prev_epoch=$epoch
        i=$((i+1))
    done

    if [ -n "$current_event_start" ]; then
        iso_start=$(date -d "$current_event_start" -Iseconds 2>/dev/null)
        EVENTS=$(echo "$EVENTS" | jq --arg s "$iso_start" --arg u "$current_event_user" --argjson p "$current_event_pkgs" \
            '. + [{started:$s, user:$u, packages:$p}]')
    fi
fi

EVENT_COUNT=$(echo "$EVENTS" | jq 'length')
ENRICHED="[]"
INSIDE=0
OUTSIDE=0
TOTAL_CVES_RESOLVED=0

i=0
while [ "$i" -lt "$EVENT_COUNT" ]; do
    ev=$(echo "$EVENTS" | jq -c ".[$i]")
    started=$(echo "$ev" | jq -r '.started')
    user=$(echo "$ev" | jq -r '.user')
    packages=$(echo "$ev" | jq -r '.packages')

    ev_epoch=$(date -d "$started" +%s 2>/dev/null || echo 0)
    ev_day=$(TZ="$TZ_NAME" date -d "@$ev_epoch" +%a)
    ev_hm=$(TZ="$TZ_NAME" date -d "@$ev_epoch" +%H:%M)
    ev_dom=$(TZ="$TZ_NAME" date -d "@$ev_epoch" +%d)
    week_of_month=$(( (10#$ev_dom - 1) / 7 + 1 ))

    within="outside"
    if [ -f "$WIN_FILE" ]; then
        win_count=$(jq '.windows | length' "$WIN_FILE")
        wi=0
        while [ "$wi" -lt "$win_count" ]; do
            w=$(jq -c ".windows[$wi]" "$WIN_FILE")
            always=$(echo "$w" | jq -r '.always // false')
            [ "$always" = "true" ] && { wi=$((wi+1)); continue; }
            days=$(echo "$w" | jq -r '.days[]' 2>/dev/null)
            start=$(echo "$w" | jq -r '.start')
            end=$(echo "$w" | jq -r '.end')
            wom=$(echo "$w" | jq -r '.week_of_month // empty')
            if echo "$days" | grep -qxF "$ev_day"; then
                if [ -z "$wom" ] || [ "$wom" = "$week_of_month" ]; then
                    if [[ "$ev_hm" > "$start" || "$ev_hm" == "$start" ]] && [[ "$ev_hm" < "$end" ]]; then
                        within="inside"
                    fi
                fi
            fi
            wi=$((wi+1))
        done
    fi

    [ "$within" = "inside" ] && INSIDE=$((INSIDE+1)) || OUTSIDE=$((OUTSIDE+1))

    linked_log="null"
    if [ -f "$EXEC_LOG" ]; then
        log_started=$(jq -r '.started_at' "$EXEC_LOG" 2>/dev/null)
        log_finished=$(jq -r '.finished_at' "$EXEC_LOG" 2>/dev/null)
        if [ -n "$log_started" ] && [ -n "$log_finished" ]; then
            log_start_epoch=$(date -d "$log_started" +%s 2>/dev/null || echo 0)
            log_end_epoch=$(date -d "$log_finished" +%s 2>/dev/null || echo 0)
            if [ "$ev_epoch" -ge "$((log_start_epoch - 60))" ] && [ "$ev_epoch" -le "$((log_end_epoch + 60))" ]; then
                linked_log="\"$EXEC_LOG\""
            fi
        fi
    fi

    cves_resolved=0
    if [ "$linked_log" != "null" ] && [ -f "$EXEC_LOG" ] && [ -f "$VULN_FILE" ]; then
        success_pkgs=$(jq -r '.entries[] | select(.status=="success") | .package' "$EXEC_LOG")
        while IFS= read -r p; do
            [ -z "$p" ] && continue
            cve_count=$(jq --arg p "$p" '[.packages[] | select(.package==$p) | .cves[]?] | length' "$VULN_FILE")
            cves_resolved=$((cves_resolved + cve_count))
        done <<< "$success_pkgs"
    fi
    TOTAL_CVES_RESOLVED=$((TOTAL_CVES_RESOLVED + cves_resolved))

    entry=$(jq -n --arg s "$started" --arg u "$user" --arg w "$within" --argjson p "$packages" \
        --argjson ll "$linked_log" --argjson cr "$cves_resolved" \
        '{started:$s, user:$u, within_window:$w, packages:$p, linked_execution_log:$ll, cves_resolved:$cr}')
    ENRICHED=$(echo "$ENRICHED" | jq --argjson e "$entry" '. + [$e]')

    i=$((i+1))
done

PERIOD_START=$(echo "$ENRICHED" | jq -r '.[0].started // ""')
PERIOD_END=$(echo "$ENRICHED" | jq -r '.[-1].started // ""')

SUMMARY=$(jq -n --argjson total "$EVENT_COUNT" --argjson inside "$INSIDE" --argjson outside "$OUTSIDE" --argjson cves "$TOTAL_CVES_RESOLVED" \
    '{total_events:$total, inside_window:$inside, outside_window:$outside, cves_resolved:$cves}')

jq -n --arg ps "$PERIOD_START" --arg pe "$PERIOD_END" --argjson events "$ENRICHED" --argjson summary "$SUMMARY" \
    '{period_start:$ps, period_end:$pe, events:$events, summary:$summary}' > "$OUT"

echo "Change log: $EVENT_COUNT events (inside: $INSIDE, outside: $OUTSIDE)"
echo "Report saved to: $OUT"
