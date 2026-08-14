#!/bin/bash
set -euo pipefail

OUT="network_baseline.json"
TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
HOST=$(hostname)

# MAC, link state
INTERFACES=$(ip -j addr show | jq '[.[] | {name: .ifname, mac: .address, link_state: .operstate, addresses: [.addr_info[] | {family: .family, address: .local, prefixlen: .prefixlen}]}]')

ROUTES=$(ip -j route show)
DEFAULT_GW=$(ip -j route show default)
NEIGHBORS=$(ip -j neigh show)

# PID
if command -v ss >/dev/null 2>&1 && ss -j -tulnpH >/dev/null 2>&1; then
  LISTENERS=$(ss -j -tulnpH)
  ESTABLISHED=$(ss -j -tnpH state established)
else
  LISTENERS=$(ss -tulnpH | jq -R -s '[splitlines(.)[] | select(length > 0)]' 2>/dev/null || echo "[]")
  ESTABLISHED=$(ss -tnpH state established | jq -R -s '[splitlines(.)[] | select(length > 0)]' 2>/dev/null || echo "[]")
fi

RESOLV_CONF=$(cat /etc/resolv.conf 2>/dev/null | jq -R -s '.' || echo '""')
if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
  RESOLVECTL=$(resolvectl status --no-pager 2>/dev/null | jq -R -s '.' || echo '""')
else
  RESOLVECTL='""'
fi

jq -n \
  --arg timestamp "$TS" \
  --arg hostname "$HOST" \
  --argjson interfaces "$INTERFACES" \
  --argjson routes "$ROUTES" \
  --argjson default_gateway "$DEFAULT_GW" \
  --argjson neighbors "$NEIGHBORS" \
  --argjson listening_sockets "$LISTENERS" \
  --argjson established_connections "$ESTABLISHED" \
  --arg resolv_conf "$RESOLV_CONF" \
  --arg resolvectl_status "$RESOLVECTL" \
  '{
    timestamp: $timestamp,
    hostname: $hostname,
    interfaces: $interfaces,
    routes: $routes,
    default_gateway: $default_gateway,
    neighbors: $neighbors,
    listening_sockets: $listening_sockets,
    established_connections: $established_connections,
    dns_resolvers: {
      resolv_conf: $resolv_conf,
      resolvectl_status: $resolvectl_status
    }
  }' > "$OUT"

echo "Baseline written to $OUT"
