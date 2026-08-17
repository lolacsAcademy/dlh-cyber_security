#!/bin/bash
# dpkg -S
# systemctl show
# web
# ssh
set -euo pipefail

BASELINE="network_baseline.json"
CATALOG="/home/analyst/MedDefense_Lab/capstone/service_catalog.json"
CRITICALITY="/home/analyst/MedDefense_Lab/capstone/service_criticality.json"
OUT="attack_surface.json"
TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
HOST=$(hostname)

SOCKETS=$(jq -n \
  --slurpfile baseline "$BASELINE" \
  --slurpfile catalog "$CATALOG" \
  --slurpfile criticality "$CRITICALITY" \
  '
  ($catalog[0] | map({(.process): .function}) | add) as $funcmap |
  ($criticality[0] | map({(.process): .criticality}) | add) as $critmap |
  $baseline[0].listening_sockets | map(
    . as $sock |
    ($funcmap[$sock.process] // "unknown") as $function |
    ($critmap[$sock.process] // "unknown") as $crit |
    (
      [
        (if ($sock.bind_addr == "0.0.0.0" or $sock.bind_addr == "*") and ($function == "database" or $function == "rpc") then "database_exposed" else empty end),
        (if ($sock.bind_addr == "0.0.0.0" or $sock.bind_addr == "*") then "bound_0.0.0.0" else empty end),
        (if $function == "telnet" then "insecure_protocol_telnet" else empty end),
        (if $function == "ftp" then "insecure_protocol_ftp" else empty end),
        (if $function == "snmpv1" or $function == "snmpv2c" then "insecure_protocol_" + $function else empty end),
        (if $function == "rlogin" then "insecure_protocol_rlogin" else empty end),
        (if $function == "nfs v2/v3" then "insecure_protocol_nfs" else empty end)
      ]
    ) as $flags |
    {
      proto: $sock.proto,
      port: ($sock.port | tonumber? // $sock.port),
      bind_addr: $sock.bind_addr,
      process: $sock.process,
      package: (($catalog[0][] | select(.process == $sock.process) | .package) // "unknown"),
      function: $function,
      criticality: $crit,
      exposure_flags: $flags
    }
  )
  ' )

SUMMARY=$(echo "$SOCKETS" | jq '
  {
    total_sockets: length,
    flagged: [.[] | select(.exposure_flags | length > 0)] | length,
    unknown_function: [.[] | select(.function == "unknown")] | length,
    by_criticality: (group_by(.criticality) | map({(.[0].criticality): length}) | add)
  }
')

jq -n \
  --arg generated_at "$TS" \
  --arg hostname "$HOST" \
  --argjson sockets "$SOCKETS" \
  --argjson summary "$SUMMARY" \
  '{
    generated_at: $generated_at,
    hostname: $hostname,
    sockets: $sockets,
    summary: $summary
  }' > "$OUT"

echo "Attack surface report written to $OUT"
