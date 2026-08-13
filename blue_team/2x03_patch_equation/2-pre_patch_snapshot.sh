#!/bin/bash
set -euo pipefail

# Records SHA-256 hashes of dpkg-tracked conffiles under /etc

OUT="pre_patch_state.json"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
HOSTNAME=$(hostname)
KERNEL=$(uname -r)

if [ -f /var/run/reboot-required ]; then
    REBOOT_REQUIRED="true"
else
    REBOOT_REQUIRED="false"
fi

# 1. Package versions via dpkg
PACKAGES=$(dpkg-query -W -f='{"package":"${binary:Package}","version":"${Version}"}\n' | jq -s '.')

# 2. Service state: ActiveState, SubState, MainPID
SERVICES="[]"
for svc in $(systemctl list-units --type=service --state=running --no-legend | awk '{print $1}'); do
    active=$(systemctl show -p ActiveState --value "$svc")
    sub=$(systemctl show -p SubState --value "$svc")
    pid=$(systemctl show -p MainPID --value "$svc")
    entry=$(jq -n --arg s "$svc" --arg a "$active" --arg sub "$sub" --arg p "$pid" \
        '{service:$s, ActiveState:$a, SubState:$sub, MainPID:$p}')
    SERVICES=$(echo "$SERVICES" | jq --argjson e "$entry" '. + [$e]')
done

# 3. Listening sockets via ss -tulnp
LISTENING=$(ss -tulnp 2>/dev/null | tail -n +2 | jq -R -s 'split("\n") | map(select(length > 0))')

# 4. Config file SHA-256 hashes for dpkg-tracked /etc files
CONFFILES="{}"
for f in $(dpkg-query -W -f='${Conffiles}\n' 2>/dev/null | tr ',' '\n' | awk '{print $1}' | grep '^/etc/' | sort -u); do
    if [ -f "$f" ]; then
        hash=$(sha256sum "$f" 2>/dev/null | awk '{print $1}')
        [ -n "$hash" ] && CONFFILES=$(echo "$CONFFILES" | jq --arg k "$f" --arg v "$hash" '. + {($k): $v}')
    fi
done

jq -n \
    --arg ts "$TIMESTAMP" \
    --arg host "$HOSTNAME" \
    --arg kernel "$KERNEL" \
    --argjson packages "$PACKAGES" \
    --argjson services "$SERVICES" \
    --argjson listening "$LISTENING" \
    --argjson conffiles "$CONFFILES" \
    --argjson reboot "$REBOOT_REQUIRED" \
    '{timestamp:$ts, hostname:$host, kernel:$kernel, packages:$packages, services:$services, listening:$listening, conffile_hashes:$conffiles, reboot_required:$reboot}' > "$OUT"

SIZE=$(du -h "$OUT" | cut -f1)
PKG_COUNT=$(echo "$PACKAGES" | jq 'length')
SVC_COUNT=$(echo "$SERVICES" | jq 'length')

echo "Snapshot: $OUT"
echo "Size: $SIZE"
echo "Kernel: $KERNEL"
echo "Reboot required: $REBOOT_REQUIRED"
echo "Packages: $PKG_COUNT"
echo "Services: $SVC_COUNT"
