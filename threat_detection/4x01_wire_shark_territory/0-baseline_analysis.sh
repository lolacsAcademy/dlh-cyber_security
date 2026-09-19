#!/bin/bash

PCAP="${1:-}"

if [ ! -f "$PCAP" ]; then
    echo "Usage: $0 <pcap>"
    exit 1
fi

TOTAL=$(tshark -r "$PCAP" -T fields -e frame.number 2>/dev/null | wc -l)

echo "=== PROTOCOL DISTRIBUTION ==="
for p in "TCP:tcp" "UDP:udp" "ICMP:icmp"; do
    name="${p%%:*}"
    filter="${p#*:}"
    count=$(tshark -r "$PCAP" -Y "$filter" -T fields -e frame.number 2>/dev/null | wc -l)
    awk -v n="$name" -v c="$count" -v t="$TOTAL" 'BEGIN{printf "%s: %.2f%% (%d packets)\n",n,c*100/t,c}'
done
known=$(tshark -r "$PCAP" -Y "tcp || udp || icmp" -T fields -e frame.number 2>/dev/null | wc -l)
other=$((TOTAL-known))
awk -v c="$other" -v t="$TOTAL" 'BEGIN{printf "Other: %.2f%% (%d packets)\n",c*100/t,c}'

echo
echo "=== APPLICATION BREAKDOWN ==="
while IFS='|' read -r name filter; do
    count=$(tshark -r "$PCAP" -Y "$filter" -T fields -e frame.number 2>/dev/null | wc -l)
    awk -v n="$name" -v c="$count" -v t="$TOTAL" 'BEGIN{printf "%-18s %.2f%% (%d)\n",n,c*100/t,c}'
done <<'EOF'
HTTPS (443)|tcp.port==443
HTTP (80)|tcp.port==80
DNS (53)|tcp.port==53 || udp.port==53
Kerberos (88)|tcp.port==88 || udp.port==88
LDAP (389)|tcp.port==389 || udp.port==389
SMB (445)|tcp.port==445
NTP (123)|udp.port==123
Printing (9100)|tcp.port==9100
EOF

echo "Other/agent traffic:"
tshark -r "$PCAP" -q -z io,phs 2>/dev/null

echo
echo "=== TOP 10 TALKERS ==="
tshark -r "$PCAP" -T fields -e ip.src -e frame.len 2>/dev/null |
awk 'NF==2{b[$1]+=$2} END{for(i in b) print b[i],i}' | sort -nr | head -10

echo
echo "=== TOP 10 DESTINATIONS ==="
tshark -r "$PCAP" -Y "tcp.flags.syn==1 && tcp.flags.ack==0" -T fields -e ip.dst 2>/dev/null |
sort | uniq -c | sort -nr | head -10

echo
echo "=== DNS QUERY PROFILE ==="
DNS=$(tshark -r "$PCAP" -Y "dns.flags.response==0 && dns.qry.name" -T fields -e dns.qry.name 2>/dev/null | wc -l)
FIRST=$(tshark -r "$PCAP" -T fields -e frame.time_epoch 2>/dev/null | sed -n '1p')
LAST=$(tshark -r "$PCAP" -T fields -e frame.time_epoch 2>/dev/null | tail -1)
MIN=$(awk -v a="$FIRST" -v b="$LAST" 'BEGIN{printf "%.2f",(b-a)/60}')
RATE=$(awk -v q="$DNS" -v m="$MIN" 'BEGIN{printf "%.2f",q/m}')

echo "Total queries: $DNS"
echo "Average queries/minute: $RATE"
echo "Top 20 domains:"
tshark -r "$PCAP" -Y "dns.flags.response==0 && dns.qry.name" -T fields -e dns.qry.name 2>/dev/null |
sort | uniq -c | sort -nr | head -20

echo "Query types:"
for q in "A:1" "AAAA:28" "TXT:16" "MX:15"; do
    name="${q%%:*}"
    type="${q#*:}"
    count=$(tshark -r "$PCAP" -Y "dns.flags.response==0 && dns.qry.type==$type" -T fields -e dns.qry.type 2>/dev/null | wc -l)
    echo "$name: $count"
done
TXT=$(tshark -r "$PCAP" -Y "dns.flags.response==0 && dns.qry.type==16" -T fields -e dns.qry.name 2>/dev/null | wc -l)

echo
echo "=== CONNECTION DURATION DISTRIBUTION ==="
tshark -r "$PCAP" -q -z conv,tcp 2>/dev/null |
awk '/<->/ && $(NF-1)~/^[0-9.]+$/ {d=$(NF-1); n++; if(d<1)s++; else if(d<=30)m++; else l++}
END{if(n){printf "Short (<1s): %.2f%%\nMedium (1-30s): %.2f%%\nLong (>30s): %.2f%%\n",s*100/n,m*100/n,l*100/n}}'

echo
echo "=== TLS ANALYSIS ==="
echo "SNI:"
tshark -r "$PCAP" -Y "tls.handshake.extensions_server_name" -T fields -e tls.handshake.extensions_server_name 2>/dev/null | sort -u
echo "TLS versions:"
tshark -r "$PCAP" -Y "tls" -T fields -e tls.record.version 2>/dev/null | sed '/^$/d' | sort | uniq -c
echo "Certificate issuers:"
tshark -r "$PCAP" -Y "x509sat.uTF8String" -T fields -e x509sat.uTF8String 2>/dev/null | sed '/^$/d' | sort -u

echo
echo "=== TEMPORAL PATTERN ==="
tshark -r "$PCAP" -T fields -e frame.time_epoch -e frame.len 2>/dev/null |
awk 'NF==2{m=int($1/60)*60;p[m]++;b[m]+=$2} END{for(m in p)print m,p[m],b[m]}' | sort -n

echo
echo "=== BASELINE SIGNATURES ==="
echo "Normal DNS rate: $RATE queries/minute"
echo "Normal TXT query rate: $TXT queries in $MIN minutes"
echo "Normal external connection rhythm: see destinations and temporal pattern"
echo "Normal packet volume range: see temporal pattern"
echo "Known-good services: see application, DNS and TLS results"

cat > baseline_clinical.json <<EOF
{
  "total_packets": $TOTAL,
  "duration_minutes": $MIN,
  "dns_queries": $DNS,
  "dns_queries_per_minute": $RATE,
  "txt_queries": $TXT
}
EOF

echo "BASELINE SAVED: baseline_clinical.json"
