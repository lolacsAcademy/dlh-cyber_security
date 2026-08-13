#!/bin/bash
set -uo pipefail

PRE_FILE="pre_patch_state.json"
DEPS_FILE="service_dependency_map.json"
PROBES_FILE="service_probes.json"
OUT="post_patch_validation.json"

DETAILS="[]"

# 1. Service state checks: same ActiveState or better (anything other than active is a regression)
svc_total=0
svc_pass=0
while IFS= read -r pre_svc; do
    svc=$(echo "$pre_svc" | jq -r '.service')
    svc_total=$((svc_total+1))
    current_state=$(systemctl show -p ActiveState --value "$svc" 2>/dev/null || echo "unknown")
    if [ "$current_state" = "active" ]; then
        status="pass"
        svc_pass=$((svc_pass+1))
    else
        status="regression"
    fi
    entry=$(jq -n --arg check "service_state" --arg svc "$svc" --arg current "$current_state" --arg status "$status" \
        '{check:$check, service:$svc, current_state:$current, status:$status}')
    DETAILS=$(echo "$DETAILS" | jq --argjson e "$entry" '. + [$e]')
done < <(jq -c '.services[]' "$PRE_FILE")

# 2. Listening socket checks: verify port still listening
listen_total=0
listen_pass=0
CURRENT_LISTEN=$(ss -tulnp 2>/dev/null)
while IFS= read -r line; do
    [ -z "$line" ] && continue
    listen_total=$((listen_total+1))
    port_field=$(echo "$line" | awk '{print $5}')
    if echo "$CURRENT_LISTEN" | grep -qF "$port_field"; then
        status="pass"
        listen_pass=$((listen_pass+1))
    else
        status="regression"
    fi
    entry=$(jq -n --arg check "listening_socket" --arg socket "$port_field" --arg status "$status" \
        '{check:$check, socket:$socket, status:$status}')
    DETAILS=$(echo "$DETAILS" | jq --argjson e "$entry" '. + [$e]')
done < <(jq -r '.listening[]' "$PRE_FILE")

# 3. Critical liveness probes
probe_total=0
probe_pass=0
crit_services=$(jq -s -r '.[] | select(.criticality=="critical") | .service' "$DEPS_FILE")
for svc in $crit_services; do
    probe=$(jq -c --arg s "$svc" '.[$s] // empty' "$PROBES_FILE")
    [ -z "$probe" ] && continue
    probe_total=$((probe_total+1))
    ptype=$(echo "$probe" | jq -r '.type')
    target=$(echo "$probe" | jq -r '.target')

    ok=0
    case "$ptype" in
        curl)
            curl -sf -o /dev/null "$target" && ok=1
            ;;
        mysqladmin_ping)
            sudo mysqladmin ping -h "$target" >/dev/null 2>&1 && ok=1
            ;;
        ssh_batchmode)
            ssh -o BatchMode=yes -o ConnectTimeout=3 "$target" true 2>/dev/null
            rc=$?
            [ $rc -eq 0 ] || [ $rc -eq 255 ] && ok=1
            ;;
    esac

    if [ "$ok" -eq 1 ]; then
        status="pass"
        probe_pass=$((probe_pass+1))
    else
        status="probe_failed"
    fi
    entry=$(jq -n --arg check "liveness_probe" --arg svc "$svc" --arg type "$ptype" --arg status "$status" \
        '{check:$check, service:$svc, probe_type:$type, status:$status}')
    DETAILS=$(echo "$DETAILS" | jq --argjson e "$entry" '. + [$e]')
done

TOTAL=$((svc_total + listen_total + probe_total))
PASSED=$((svc_pass + listen_pass + probe_pass))
FAILED=$((TOTAL - PASSED))

jq -n --argjson total "$TOTAL" --argjson passed "$PASSED" --argjson failed "$FAILED" --argjson details "$DETAILS" \
    '{total_checks:$total, passed:$passed, failed:$failed, details:$details}' > "$OUT"

echo "Service state checks:     $svc_pass/$svc_total   $([ "$svc_pass" -eq "$svc_total" ] && echo PASS || echo FAIL)"
echo "Listening socket checks:  $listen_pass/$listen_total   $([ "$listen_pass" -eq "$listen_total" ] && echo PASS || echo FAIL)"
echo "Critical liveness probes: $probe_pass/$probe_total     $([ "$probe_pass" -eq "$probe_total" ] && echo PASS || echo FAIL)"

if [ "$FAILED" -eq 0 ]; then
    echo "VERDICT: PASS ($PASSED/$TOTAL)"
else
    echo "VERDICT: FAIL ($PASSED/$TOTAL)"
fi
echo "Report saved to: $OUT"

if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
exit 0
