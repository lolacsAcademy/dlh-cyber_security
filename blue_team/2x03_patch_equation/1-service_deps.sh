#!/bin/bash
set -euo pipefail

CRIT_FILE="service_criticality.json"
OUT="service_dependency_map.json"

# Criticality levels: critical, high, medium, low
# Cross-check hint: needrestart -b

: > "$OUT"

systemctl list-units --type=service --state=running --no-legend | awk '{print $1}' | while IFS= read -r svc; do
    [ -z "$svc" ] && continue

    pid=$(systemctl show -p MainPID --value "$svc" 2>/dev/null || echo 0)
    exec_path=""
    if [ "$pid" != "0" ] && [ -n "$pid" ]; then
        exec_path=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "")
    fi
    if [ -z "$exec_path" ]; then
        exec_start_line=$(systemctl show -p ExecStart --value "$svc" 2>/dev/null)
        # ExecStart= format: parse path= field
        exec_path=$(echo "$exec_start_line" | grep -oP '(?<=path=)[^ ;]+' | head -1)
    fi
    [ -z "$exec_path" ] && continue
    [ ! -e "$exec_path" ] && continue

    owning_pkg=$( (dpkg -S "$exec_path" 2>/dev/null || true) | head -1 | cut -d':' -f1)
    [ -z "$owning_pkg" ] && owning_pkg="unknown"

    linked_pkgs="[]"
    libs=$(ldd "$exec_path" 2>/dev/null | grep -oP '(?<=> )/\S+' || true)
    for lib in $libs; do
        pkg=$( (dpkg -S "$lib" 2>/dev/null || true) | head -1 | cut -d':' -f1)
        [ -z "$pkg" ] && continue
        linked_pkgs=$(echo "$linked_pkgs" | jq --arg p "$pkg" 'if index($p) then . else . + [$p] end')
    done
    linked_pkgs=$(echo "$linked_pkgs" | jq --arg op "$owning_pkg" 'if index($op) then . else [$op] + . end')

    criticality=$(jq -r --arg s "$svc" '.[$s] // "low"' "$CRIT_FILE" 2>/dev/null)
    [ "$criticality" = "null" ] && criticality="low"

    restart_required="true"

    entry=$(jq -n --arg svc "$svc" --arg ep "$exec_path" --arg op "$owning_pkg" \
        --argjson lp "$linked_pkgs" --arg cr "$criticality" --argjson rr "$restart_required" \
        '{service:$svc, exec_path:$ep, owning_package:$op, linked_packages:$lp, criticality:$cr, restart_required_on_patch:$rr}')

    echo "$entry" >> "$OUT"
done

echo "Done -> $OUT"
