#!/bin/bash
# Detects packages in half-configured, half-installed, unpacked, or triggers-pending state
set -uo pipefail

OUT="apt_recovery.json"
DEPS_FILE="service_dependency_map.json"
START_TS=$(date +%s)

echo "[*] Diagnosing..."

LIVE_PROCS=$(pgrep -fa 'dpkg|apt-get|apt ' 2>/dev/null | grep -v "$$" || true)

if [ -n "$LIVE_PROCS" ]; then
    echo "    live dpkg/apt processes: detected"
    DIAGNOSIS=$(jq -n --arg procs "$LIVE_PROCS" '{live_processes:$procs}')
    jq -n --argjson diag "$DIAGNOSIS" '{initial_diagnosis:$diag, actions_taken:[], final_state:"aborted", recovered:false, duration_seconds:0}' > "$OUT"
    exit 2
fi
echo "    live dpkg/apt processes: none"

STALE_LOCKS=""
for lockfile in /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock; do
    if [ -f "$lockfile" ]; then
        STALE_LOCKS="$STALE_LOCKS $lockfile"
    fi
done
echo "    lock files present:$STALE_LOCKS"

AUDIT_OUTPUT=$(dpkg --audit 2>/dev/null || true)

BROKEN_PKGS=$(dpkg -l 2>/dev/null | awk '$1 ~ /^.[HFU]|^.i[HFU]/ {print $2}')
BROKEN_COUNT=0
if [ -n "$BROKEN_PKGS" ]; then
    BROKEN_COUNT=$(echo "$BROKEN_PKGS" | grep -c .)
fi
echo "    dpkg --audit: broken packages: $BROKEN_COUNT"

FREE_ROOT=$(df -h / | tail -1 | awk '{print $4}')
FREE_VAR=$(df -h /var | tail -1 | awk '{print $4}')

ACTIONS="[]"
FINAL_STATE="clean"
RECOVERED="true"

if [ "$BROKEN_COUNT" -eq 0 ]; then
    echo "[*] No broken packages detected — system already clean."
else
    echo "[*] Repairing..."

    if [ -n "$STALE_LOCKS" ]; then
        for lockfile in $STALE_LOCKS; do
            rm -f "$lockfile"
        done
        echo "    remove stale locks                     OK"
        ACTIONS=$(echo "$ACTIONS" | jq '. + ["remove stale locks"]')
    fi

    if dpkg --configure -a; then
        echo "    dpkg --configure -a                    OK"
        ACTIONS=$(echo "$ACTIONS" | jq '. + ["dpkg --configure -a"]')
    fi

    if DEBIAN_FRONTEND=noninteractive apt-get --fix-broken install -y; then
        echo "    apt-get --fix-broken install           OK"
        ACTIONS=$(echo "$ACTIONS" | jq '. + ["apt-get --fix-broken install"]')
    fi

    AUDIT_RECHECK=$(dpkg --audit 2>/dev/null || true)
    if [ -z "$AUDIT_RECHECK" ]; then
        echo "    dpkg --audit (re-run)                  clean"
        FINAL_STATE="clean"
        RECOVERED="true"
        ACTIONS=$(echo "$ACTIONS" | jq '. + ["dpkg --audit re-run: clean"]')
    else
        echo "    dpkg --audit (re-run)                  still broken"
        FINAL_STATE="broken"
        RECOVERED="false"
        ACTIONS=$(echo "$ACTIONS" | jq '. + ["dpkg --audit re-run: still broken"]')
    fi

    echo "[*] Restarting affected services..."
    for pkg in $BROKEN_PKGS; do
        svcs=$(jq -s -r --arg p "$pkg" '.[] | select(.owning_package==$p) | .service' "$DEPS_FILE" 2>/dev/null)
        for svc in $svcs; do
            [ -z "$svc" ] && continue
            systemctl try-restart "$svc" 2>/dev/null
            state=$(systemctl show -p ActiveState --value "$svc" 2>/dev/null)
            echo "    $svc                        $state"
        done
    done
fi

END_TS=$(date +%s)
DURATION=$((END_TS - START_TS))

INITIAL_DIAGNOSIS=$(jq -n \
    --arg locks "$STALE_LOCKS" \
    --arg audit "$AUDIT_OUTPUT" \
    --argjson broken_count "$BROKEN_COUNT" \
    --arg broken_pkgs "$BROKEN_PKGS" \
    --arg free_root "$FREE_ROOT" \
    --arg free_var "$FREE_VAR" \
    '{stale_locks:$locks, dpkg_audit:$audit, broken_package_count:$broken_count, broken_packages:$broken_pkgs, free_space_root:$free_root, free_space_var:$free_var}')

jq -n --argjson diag "$INITIAL_DIAGNOSIS" --argjson actions "$ACTIONS" \
    --arg final "$FINAL_STATE" --argjson recovered "$RECOVERED" --argjson dur "$DURATION" \
    '{initial_diagnosis:$diag, actions_taken:$actions, final_state:$final, recovered:$recovered, duration_seconds:$dur}' > "$OUT"

if [ "$RECOVERED" = "true" ]; then
    echo "RECOVERED: yes"
else
    echo "RECOVERED: no"
fi
echo "Duration: ${DURATION}s"
echo "Report saved to: $OUT"

if [ "$RECOVERED" = "true" ]; then
    exit 0
fi
exit 1
