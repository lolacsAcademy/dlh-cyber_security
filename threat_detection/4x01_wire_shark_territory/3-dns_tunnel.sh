#!/bin/bash

PCAP="${1:-}"
SRC="10.10.1.10"
DOMAIN="data-sync.meddefense-portal.com"

if [ ! -f "$PCAP" ]; then
    echo "Usage: $0 <pcap>"
    exit 1
fi

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

# tshark: extract all DNS queries from billing-srv-01
tshark -r "$PCAP" -Y "ip.src==$SRC && dns.flags.response==0" \
-T fields -e frame.time_epoch -e dns.qry.name -e dns.qry.type \
2>/dev/null > "$TMP"

TOTAL=$(wc -l < "$TMP")
ANOM=$(awk -v d="$DOMAIN" '$2 ~ d"$" {n++} END{print n+0}' "$TMP")
NORMAL=$((TOTAL-ANOM))

echo "=== DNS QUERY CLASSIFICATION ==="
echo "Total DNS queries: $TOTAL"
echo "Normal queries: $NORMAL"
echo "Anomalous queries: $ANOM"

echo
echo "Normal queries:"
awk -v d="$DOMAIN" '$2 !~ d"$" {print $2}' "$TMP" |
sort | uniq -c | sort -nr

echo
echo "=== ANOMALOUS QUERY ANALYSIS ==="
echo "Base domain: $DOMAIN"
echo "Full query | label length | type"

awk -v d="$DOMAIN" '
$2 ~ d"$" {
    split($2,a,".")
    type=($3==16 ? "TXT" : $3)
    print $2, length(a[1]), type
}' "$TMP"

FIRST=$(awk -v d="$DOMAIN" '$2 ~ d"$" {print $1; exit}' "$TMP")
LAST=$(awk -v d="$DOMAIN" '$2 ~ d"$" {x=$1} END{print x}' "$TMP")

SPAN=$(awk -v a="$FIRST" -v b="$LAST" \
'BEGIN{if(a!="" && b!="") printf "%.2f",(b-a)/60; else print 0}')

RATE=$(awk -v n="$ANOM" -v m="$SPAN" \
'BEGIN{if(m>0) printf "%.2f",n/m; else print 0}')

AVG=$(awk -v d="$DOMAIN" '
$2 ~ d"$" {
    split($2,a,".")
    sum+=length(a[1])
    n++
}
END {
    if(n) printf "%.2f",sum/n
    else print 0
}' "$TMP")

echo
echo "Anomalous queries: $ANOM"
echo "Time span: $SPAN minutes"
echo "Query rate: $RATE queries/minute"
echo "Average encoded label length: $AVG"
echo "Encoding pattern: Base32-like labels."

echo
echo "=== SAMPLE DECODING ==="
echo "Decoding approach: Base32 with required '=' padding."

awk -v d="$DOMAIN" '$2 ~ d"$" {split($2,a,"."); print a[1]}' "$TMP" |
head -5 |
while read -r label; do
    echo "Label: $label"

    upper=$(printf '%s' "$label" | tr '[:lower:]' '[:upper:]')
    mod=$((${#upper} % 8))
    padded="$upper"

    if [ "$mod" -ne 0 ]; then
        need=$((8-mod))
        i=0
        while [ "$i" -lt "$need" ]; do
            padded="${padded}="
            i=$((i+1))
        done
    fi

    if decoded=$(printf '%s' "$padded" | base32 -d 2>/dev/null); then
        echo "Base32 decoded: $decoded"
    else
        echo "Base32 decode failed; no decoded content claimed."
    fi
done

echo
echo "=== DNS RESPONSE ANALYSIS ==="

# tshark: TXT responses for the tunnel domain
tshark -r "$PCAP" \
-Y "dns.flags.response==1 && dns.qry.name contains \"$DOMAIN\"" \
-T fields -e frame.time -e dns.qry.type -e dns.txt -e frame.len 2>/dev/null

TXT_RESP=$(tshark -r "$PCAP" \
-Y "dns.flags.response==1 && dns.qry.name contains \"$DOMAIN\" && dns.txt" \
-T fields -e dns.txt 2>/dev/null | wc -l)

AVG_RESP=$(tshark -r "$PCAP" \
-Y "dns.flags.response==1 && dns.qry.name contains \"$DOMAIN\" && dns.txt" \
-T fields -e frame.len 2>/dev/null |
awk '{s+=$1;n++} END{if(n) printf "%.2f",s/n; else print 0}')

echo "TXT responses: $TXT_RESP"
echo "Average TXT response packet size: $AVG_RESP bytes"

echo "Sample decoded TXT responses:"
tshark -r "$PCAP" \
-Y "dns.flags.response==1 && dns.qry.name contains \"$DOMAIN\" && dns.txt" \
-T fields -e dns.txt 2>/dev/null |
head -5 |
while read -r txt; do
    echo "Encoded: $txt"
    if decoded=$(printf '%s' "$txt" | base64 -d 2>/dev/null); then
        echo "Decoded: $decoded"
    else
        echo "Decode failed; no content claimed."
    fi
done

echo
echo "=== EXFILTRATION VOLUME ==="

ENCODED=$(awk -v n="$ANOM" -v a="$AVG" \
'BEGIN{printf "%.0f",n*a}')

RAW=$(awk -v n="$ENCODED" \
'BEGIN{printf "%.0f",n*0.625}')

EXFIL_RATE=$(awk -v n="$RAW" -v m="$SPAN" \
'BEGIN{if(m>0) printf "%.2f",n/m; else print 0}')

echo "Queries: $ANOM"
echo "Average encoded payload: $AVG bytes/query"
echo "Approximate encoded volume: $ENCODED bytes"
echo "Estimated raw payload: $RAW bytes"
echo "Estimated exfiltration rate: $EXFIL_RATE bytes/minute"
echo "Raw estimate assumes Base32 encoding overhead."

echo
echo "=== DETECTION COMPARISON ==="
echo "Task 0 normal DNS rate: 17.35 queries/minute"
echo "Task 0 TXT queries: 7 in 29.97 minutes"
echo "Tunnel DNS rate: $RATE queries/minute"
echo "Tunnel TXT behavior: repeated encoded labels under $DOMAIN"
echo "Baseline: readable domains, variable DNS behavior, very low TXT volume"
echo "Tunnel: long encoded labels, TXT queries, regular campaign-related traffic"

echo
echo "=== CONCLUSION ==="

if [ "$ANOM" -gt 0 ]; then
    echo "Packet evidence shows repeated anomalous TXT queries from $SRC to $DOMAIN."
    echo "The behavior is consistent with DNS tunneling and data exfiltration."
else
    echo "No DNS tunneling evidence to $DOMAIN was found."
fi
