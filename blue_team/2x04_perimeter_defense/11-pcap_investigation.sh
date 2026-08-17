#!/bin/bash
set -euo pipefail

PCAP="${1:-/home/analyst/MedDefense_Lab/PCAPs/suspicious_session.pcap}"
OUT="pcap_findings.json"

echo "[*] PCAP: $PCAP"

CAPINFO=$(capinfos "$PCAP" 2>/dev/null)
DURATION=$(echo "$CAPINFO" | grep "Capture duration" | grep -oP '[\d.]+' | head -1)
PACKETS=$(echo "$CAPINFO" | grep "Number of packets" | head -1 | grep -oP '\d+')
echo "[*] Duration: ${DURATION} s     Packets: $PACKETS"

TCP_CONV_RAW=$(tshark -r "$PCAP" -q -z conv,tcp 2>/dev/null | tail -n +6 | grep -v '^===' | awk 'NF' || true)
TCP_COUNT=$(echo "$TCP_CONV_RAW" | grep -c . || echo 0)
echo "[*] Extracting TCP conversations...      ($TCP_COUNT)"

UDP_CONV_RAW=$(tshark -r "$PCAP" -q -z conv,udp 2>/dev/null | tail -n +6 | grep -v '^===' | awk 'NF' || true)
UDP_COUNT=$(echo "$UDP_CONV_RAW" | grep -c . || echo 0)
echo "[*] Extracting UDP conversations...      ($UDP_COUNT)"

DNS_RAW=$(tshark -r "$PCAP" -Y "dns.flags.response==0" -T fields -e frame.time_epoch -e ip.src -e dns.qry.name -e dns.qry.type 2>/dev/null || true)
DNS_JSON=$(echo "$DNS_RAW" | awk -F'\t' 'NF{printf "{\"time\":\"%s\",\"src\":\"%s\",\"query\":\"%s\",\"type\":\"%s\"}\n",$1,$2,$3,$4}' | jq -s '.' 2>/dev/null || echo "[]")
DNS_COUNT=$(echo "$DNS_JSON" | jq 'length')
echo "[*] Extracting DNS queries...            ($DNS_COUNT)"

HTTP_RAW=$(tshark -r "$PCAP" -Y "http.request" -T fields -e frame.time_epoch -e ip.src -e ip.dst -e http.host -e http.request.method -e http.request.uri 2>/dev/null || true)
HTTP_JSON=$(echo "$HTTP_RAW" | awk -F'\t' 'NF{printf "{\"time\":\"%s\",\"src\":\"%s\",\"dst\":\"%s\",\"host\":\"%s\",\"method\":\"%s\",\"uri\":\"%s\"}\n",$1,$2,$3,$4,$5,$6}' | jq -s '.' 2>/dev/null || echo "[]")
HTTP_COUNT=$(echo "$HTTP_JSON" | jq 'length')
echo "[*] Extracting HTTP requests...          ($HTTP_COUNT)"

TLS_RAW=$(tshark -r "$PCAP" -Y "tls.handshake.type==1" -T fields -e frame.time_epoch -e ip.src -e ip.dst -e tls.handshake.extensions_server_name 2>/dev/null || true)
TLS_JSON=$(echo "$TLS_RAW" | awk -F'\t' 'NF{printf "{\"time\":\"%s\",\"src\":\"%s\",\"dst\":\"%s\",\"sni\":\"%s\"}\n",$1,$2,$3,$4}' | jq -s '.' 2>/dev/null || echo "[]")
TLS_COUNT=$(echo "$TLS_JSON" | jq 'length')
echo "[*] Extracting TLS SNI...                ($TLS_COUNT)"

FILE_RAW=$(tshark -r "$PCAP" -Y "http.content_type or smb2.filename" -T fields -e frame.time_epoch -e ip.src -e ip.dst -e http.file_data -e smb2.filename 2>/dev/null || true)
FILE_JSON=$(echo "$FILE_RAW" | awk -F'\t' 'NF{printf "{\"time\":\"%s\",\"src\":\"%s\",\"dst\":\"%s\",\"http_file_data\":\"%s\",\"smb2_filename\":\"%s\"}\n",$1,$2,$3,$4,$5}' | jq -s '.' 2>/dev/null || echo "[]")
FILE_COUNT=$(echo "$FILE_JSON" | jq 'length')
echo "[*] Extracting file transfers...         ($FILE_COUNT)"

PHS_RAW=$(tshark -r "$PCAP" -q -z io,phs 2>/dev/null || true)
echo "[*] Protocol distribution...             (see pcap_findings.json)"

echo "Top conversations:"
echo "$TCP_CONV_RAW" | head -5 | while read -r line; do echo "  $line"; done

echo "Long DNS labels (> 50 chars):"
echo "$DNS_JSON" | jq -r '.[] | select((.query | split(".")[0] | length) > 50) | "  " + .query'

TCP_CONV_JSON=$(echo "$TCP_CONV_RAW" | jq -R -s 'split("\n") | map(select(length>0))')

jq -n \
  --arg pcap "$PCAP" \
  --arg duration "$DURATION" \
  --arg packets "$PACKETS" \
  --argjson tcp_conversations "$TCP_CONV_JSON" \
  --argjson dns_queries "$DNS_JSON" \
  --argjson http_requests "$HTTP_JSON" \
  --argjson tls_sni "$TLS_JSON" \
  --argjson file_transfers "$FILE_JSON" \
  --arg phs_raw "$PHS_RAW" \
  '{
    pcap: $pcap,
    duration_seconds: ($duration | tonumber? // 0),
    packet_count: ($packets | tonumber? // 0),
    tcp_conversations: $tcp_conversations,
    dns_queries: $dns_queries,
    http_requests: $http_requests,
    tls_sni: $tls_sni,
    file_transfers: $file_transfers,
    protocol_distribution_raw: $phs_raw
  }' > "$OUT"

echo ""
echo "Findings written to $OUT"
