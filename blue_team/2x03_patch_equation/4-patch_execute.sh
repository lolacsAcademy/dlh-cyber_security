#!/bin/bash
# Records pre and post service states for each patched package
set -uo pipefail

LOCK_FILE="/var/lock/meddefense-patch.lock"
PLAN_FILE="patch_plan.json"
OUT="patch_execution_log.json"

exec 200>"$LOCK_FILE"
echo -n "[*] Acquiring lock $LOCK_FILE...  "
if ! flock -n 200; then
    echo "FAILED"
    exit 2
fi
echo "OK"

release_lock() {
    flock -u 200
}
trap release_lock EXIT

STARTED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
HOSTNAME=$(hostname)
PLAN_HASH=$(sha256sum "$PLAN_FILE" | awk '{print $1}')

TOTAL=$(jq '.plan | length' "$PLAN_FILE")
echo "[*] Loading plan: $PLAN_FILE ($TOTAL entries)"

ENTRIES="[]"
SUCCEEDED=0
FAILED=0
STOP=0

i=0
while IFS= read -r plan_entry; do
    i=$((i+1))
    pkg=$(echo "$plan_entry" | jq -r '.package')
    bucket=$(echo "$plan_entry" | jq -r '.bucket')
    services=$(echo "$plan_entry" | jq -c '.affected_services')
    requires_restart=$(echo "$plan_entry" | jq -r '.requires_restart')
    requires_reboot=$(echo "$plan_entry" | jq -r '.requires_reboot')

    if [ "$STOP" -eq 1 ]; then
        break
    fi

    printf "[%d/%d] %-20s %-12s apt-get ... " "$i" "$TOTAL" "$pkg" "$bucket"

    pre_version=$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null || echo "not_installed")
    pre_svc_states="[]"
    for svc in $(echo "$services" | jq -r '.[]'); do
        [ "$svc" = "(kernel-wide)" ] && continue
        st=$(systemctl show -p ActiveState --value "$svc" 2>/dev/null || echo "unknown")
        pre_svc_states=$(echo "$pre_svc_states" | jq --arg s "$svc" --arg st "$st" '. + [{service:$s, ActiveState:$st}]')
    done

    START_TS=$(date +%s.%N)

    max_wait=120
    waited=0
    backoff=2
    stdout_out=""
    stderr_out=""
    exit_code=0
    lock_fail=0

    while true; do
        stdout_out=$(DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade -y "$pkg" 2>/tmp/stderr_capture)
        exit_code=$?
        stderr_out=$(cat /tmp/stderr_capture)
        if [ $exit_code -ne 0 ] && echo "$stderr_out" | grep -q "E: Could not get lock"; then
            if [ "$waited" -ge "$max_wait" ]; then
                lock_fail=1
                break
            fi
            sleep "$backoff"
            waited=$((waited+backoff))
            backoff=$((backoff*2))
            continue
        fi
        break
    done

    END_TS=$(date +%s.%N)
    DURATION=$(awk -v a="$START_TS" -v b="$END_TS" 'BEGIN{printf "%.1f", b-a}')

    post_version=$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null || echo "not_installed")
    post_svc_states="[]"
    for svc in $(echo "$services" | jq -r '.[]'); do
        [ "$svc" = "(kernel-wide)" ] && continue
        st=$(systemctl show -p ActiveState --value "$svc" 2>/dev/null || echo "unknown")
        post_svc_states=$(echo "$post_svc_states" | jq --arg s "$svc" --arg st "$st" '. + [{service:$s, ActiveState:$st}]')
    done

    if [ "$lock_fail" -eq 1 ]; then
        status="failed"
        echo "FAILED (dpkg lock timeout)"
        FAILED=$((FAILED+1))
        STOP=1
    elif [ $exit_code -eq 0 ]; then
        status="success"
        echo "OK (${DURATION}s)"
        SUCCEEDED=$((SUCCEEDED+1))

        if [ "$requires_restart" = "true" ] && [ "$requires_reboot" != "true" ]; then
            for svc in $(echo "$services" | jq -r '.[]'); do
                [ "$svc" = "(kernel-wide)" ] && continue
                printf "      try-restart %-30s " "$svc"
                if systemctl try-restart "$svc" 2>/dev/null; then
                    echo "OK"
                else
                    echo "FAILED"
                fi
            done
        fi
    else
        status="failed"
        echo "FAILED"
        FAILED=$((FAILED+1))
        STOP=1
    fi

    stdout_tail=$(echo "$stdout_out" | tail -5)
    stderr_tail=$(echo "$stderr_out" | tail -5)

    entry=$(jq -n \
        --arg pkg "$pkg" \
        --arg pre_v "$pre_version" --argjson pre_svc "$pre_svc_states" \
        --arg post_v "$post_version" --argjson post_svc "$post_svc_states" \
        --arg status "$status" --argjson dur "$DURATION" \
        --arg sout "$stdout_tail" --arg serr "$stderr_tail" \
        '{package:$pkg, pre:{installed_version:$pre_v, service_states:$pre_svc}, post:{installed_version:$post_v, service_states:$post_svc}, status:$status, duration_seconds:$dur, stdout_tail:$sout, stderr_tail:$serr}')

    ENTRIES=$(echo "$ENTRIES" | jq --argjson e "$entry" '. + [$e]')

done < <(jq -c '.plan[]' "$PLAN_FILE")

FINISHED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

jq -n \
    --arg started "$STARTED_AT" --arg finished "$FINISHED_AT" \
    --arg host "$HOSTNAME" --arg hash "$PLAN_HASH" --argjson entries "$ENTRIES" \
    '{started_at:$started, finished_at:$finished, hostname:$host, plan_source_hash:$hash, entries:$entries}' > "$OUT"

echo "Succeeded: $SUCCEEDED  Failed: $FAILED"
echo "Log saved to: $OUT"

if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
exit 0
