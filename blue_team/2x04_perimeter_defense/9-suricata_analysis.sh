#!/bin/bash
# $1
# reconnaissance
# exploit
set -euo pipefail

PCAP="${1:-/home/analyst/MedDefense_Lab/PCAPs/mixed_traffic.pcap}"
CATEGORIES="/home/analyst/MedDefense_Lab/capstone/signature_categories.json"
TMPDIR=$(mktemp -d)
OUT="suricata_alerts.json"

STARTED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)

sudo suricata -c ./suricata.yaml -r "$PCAP" -l "$TMPDIR" >/dev/null 2>&1

FINISHED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)

sudo chmod 644 "$TMPDIR/eve.json" 2>/dev/null || true

ALERTS=$(sudo jq -c '
  select(.event_type=="alert") | {
    timestamp: .timestamp,
    src_ip: .src_ip,
    src_port: .src_port,
    dst_ip: .dest_ip,
    dst_port: .dest_port,
    proto: .proto,
    signature: .alert.signature,
    signature_id: .alert.signature_id,
    category: .alert.category,
    severity: .alert.severity
  }' "$TMPDIR/eve.json" | jq -s '.')

echo "$ALERTS" > /tmp/alerts_tmp.json

jq -n \
  --arg pcap "$PCAP" \
  --arg started_at "$STARTED_AT" \
  --arg finished_at "$FINISHED_AT" \
  --slurpfile alertsfile /tmp/alerts_tmp.json \
  --slurpfile catfile "$CATEGORIES" \
  '
  ($alertsfile[0]) as $alerts |
  ($catfile[0].signatures) as $catmap |
  ($alerts | length) as $total |
  ($alerts | map(.signature) | unique) as $unique_sigs |
  ($alerts | group_by(.severity) | map({(.[0].severity|tostring): length}) | add // {}) as $sev_dist |
  ($alerts | group_by(.src_ip) | map({ip: .[0].src_ip, count: length}) | sort_by(-.count)) as $top_src |
  ($alerts | group_by(.dst_ip) | map({ip: .[0].dst_ip, count: length}) | sort_by(-.count)) as $top_dst |
  ($alerts | map(. + {mapped_category: ($catmap[(.signature_id|tostring)] // "other")}) ) as $alerts_categorized |
  ($alerts_categorized | group_by(.mapped_category) | map({(.[0].mapped_category): length}) | add // {}) as $by_category |
  {
    pcap: $pcap,
    started_at: $started_at,
    finished_at: $finished_at,
    total_alerts: $total,
    unique_signatures: ($unique_sigs | length),
    severity_distribution: $sev_dist,
    by_category: $by_category,
    top_sources: $top_src,
    top_destinations: $top_dst,
    alerts: $alerts_categorized
  }
  ' > "$OUT"

echo "Suricata alert analysis written to $OUT"
rm -rf "$TMPDIR" /tmp/alerts_tmp.json
