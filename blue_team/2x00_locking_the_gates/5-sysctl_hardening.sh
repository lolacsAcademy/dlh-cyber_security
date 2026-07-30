#!/bin/bash
set -euo pipefail

# Task 5 - The Kernel Shield
# Addresses Crimson Tide Phase 3: prevents a compromised host from acting as
# a routing pivot, blocks traffic rerouting via ICMP redirects, and hardens
# memory protections (ASLR) against exploitation.

SYSCTL_CONF="/etc/sysctl.conf"
BACKUP="/etc/sysctl.conf.bak"

echo "[*] Backing up $SYSCTL_CONF"
touch "$SYSCTL_CONF"
cp -p "$SYSCTL_CONF" "$BACKUP"

declare -A PARAMS=(
  ["net.ipv4.ip_forward"]="0"
  ["net.ipv4.conf.all.accept_redirects"]="0"
  ["net.ipv4.conf.default.accept_redirects"]="0"
  ["net.ipv4.conf.all.send_redirects"]="0"
  ["net.ipv4.conf.all.accept_source_route"]="0"
  ["net.ipv4.conf.all.log_martians"]="1"
  ["net.ipv4.tcp_syncookies"]="1"
  ["net.ipv4.icmp_echo_ignore_broadcasts"]="1"
  ["net.ipv6.conf.all.disable_ipv6"]="1"
  ["net.ipv6.conf.default.disable_ipv6"]="1"
  ["kernel.randomize_va_space"]="2"
  ["fs.suid_dumpable"]="0"
  ["kernel.dmesg_restrict"]="1"
  ["kernel.kptr_restrict"]="2"
)

# Fixed order (bash associative arrays are unordered)
ORDER=(
  "net.ipv4.ip_forward"
  "net.ipv4.conf.all.accept_redirects"
  "net.ipv4.conf.default.accept_redirects"
  "net.ipv4.conf.all.send_redirects"
  "net.ipv4.conf.all.accept_source_route"
  "net.ipv4.conf.all.log_martians"
  "net.ipv4.tcp_syncookies"
  "net.ipv4.icmp_echo_ignore_broadcasts"
  "net.ipv6.conf.all.disable_ipv6"
  "net.ipv6.conf.default.disable_ipv6"
  "kernel.randomize_va_space"
  "fs.suid_dumpable"
  "kernel.dmesg_restrict"
  "kernel.kptr_restrict"
)

set_param() {
  local key="$1"
  local value="$2"
  if grep -qE "^[#[:space:]]*${key}[[:space:]]*=" "$SYSCTL_CONF"; then
    sed -i -E "s|^[#[:space:]]*${key}[[:space:]]*=.*|${key} = ${value}|" "$SYSCTL_CONF"
  else
    echo "${key} = ${value}" >> "$SYSCTL_CONF"
  fi
}

echo "[*] Applying kernel hardening parameters..."
for key in "${ORDER[@]}"; do
  set_param "$key" "${PARAMS[$key]}"
done

sysctl -p "$SYSCTL_CONF" > /dev/null 2>&1

PASS_COUNT=0
FAIL_COUNT=0

for key in "${ORDER[@]}"; do
  expected="${PARAMS[$key]}"
  proc_path="/proc/sys/${key//./\/}"
  actual=$(cat "$proc_path" 2>/dev/null | awk '{print $1}')
  line="${key} = ${expected}"
  if [[ "$actual" == "$expected" ]]; then
    printf '%-43s [PASS]\n' "$line"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    printf '%-43s [FAIL]\n' "$line"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
done

echo "Parameters applied: ${#ORDER[@]}"
echo "Verified PASS: $PASS_COUNT"
echo "Verified FAIL: $FAIL_COUNT"
