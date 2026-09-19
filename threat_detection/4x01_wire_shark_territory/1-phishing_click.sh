#!/bin/bash

PCAP="${1:-}"
DOMAIN="meddefense-portal.com"
IP="91.234.99.107"

if [ ! -f "$PCAP" ]; then
    echo "Usage: $0 <pcap>"
    exit 1
fi

echo "=== DNS RESOLUTION ==="
tshark -r "$PCAP" -Y "dns.qry.name==\"$DOMAIN\"" \
-T fields -e frame.time -e ip.src -e ip.dst -e dns.qry.name \
-e dns.a -e dns.resp.ttl 2>/dev/null

echo
echo "=== TLS HANDSHAKE ==="
tshark -r "$PCAP" \
-Y "tls.handshake.type==1 && tls.handshake.extensions_server_name==\"$DOMAIN\"" \
-T fields -e frame.time -e tls.handshake.extensions_server_name \
-e tls.handshake.version -e tls.handshake.ciphersuite 2>/dev/null

echo
echo "=== SERVER CERTIFICATE ==="
CERT=$(tshark -r "$PCAP" -Y "tls.handshake.type==11 && ip.src==$IP" \
-T fields -e frame.number 2>/dev/null)

if [ -z "$CERT" ]; then
    echo "Certificate details not available in the PCAP."
else
    tshark -r "$PCAP" -Y "tls.handshake.type==11 && ip.src==$IP" \
    -T fields -e x509sat.printableString -e x509sat.uTF8String \
    -e x509af.utcTime -e x509af.serialNumber 2>/dev/null
fi

echo
echo "=== DATA EXCHANGE ==="
CLIENT=$(tshark -r "$PCAP" -Y "tcp.dstport==443 && ip.dst==$IP" \
-T fields -e ip.src 2>/dev/null | sed -n '1p')

C_BYTES=$(tshark -r "$PCAP" -Y "ip.src==$CLIENT && ip.dst==$IP && tcp" \
-T fields -e frame.len 2>/dev/null | awk '{s+=$1} END{print s+0}')

S_BYTES=$(tshark -r "$PCAP" -Y "ip.src==$IP && ip.dst==$CLIENT && tcp" \
-T fields -e frame.len 2>/dev/null | awk '{s+=$1} END{print s+0}')

C_SEG=$(tshark -r "$PCAP" -Y "ip.src==$CLIENT && ip.dst==$IP && tcp" \
-T fields -e frame.number 2>/dev/null | wc -l)

S_SEG=$(tshark -r "$PCAP" -Y "ip.src==$IP && ip.dst==$CLIENT && tcp" \
-T fields -e frame.number 2>/dev/null | wc -l)

echo "Client: $CLIENT"
echo "Client -> Server: $C_BYTES bytes, $C_SEG TCP segments"
echo "Server -> Client: $S_BYTES bytes, $S_SEG TCP segments"

echo
echo "=== SESSION TIMESTAMPS ==="
echo "Connection start:"
tshark -r "$PCAP" -Y "ip.dst==$IP && tcp.dstport==443 && tcp.flags.syn==1 && tcp.flags.ack==0" \
-T fields -e frame.time 2>/dev/null | sed -n '1p'

echo "Data transfer start:"
tshark -r "$PCAP" -Y "ip.addr==$IP && tcp.port==443 && tcp.len>0" \
-T fields -e frame.time 2>/dev/null | sed -n '1p'

echo "Data transfer end:"
tshark -r "$PCAP" -Y "ip.addr==$IP && tcp.port==443 && tcp.len>0" \
-T fields -e frame.time 2>/dev/null | tail -1

echo "Connection close:"
tshark -r "$PCAP" -Y "ip.addr==$IP && tcp.port==443 && (tcp.flags.fin==1 || tcp.flags.reset==1)" \
-T fields -e frame.time 2>/dev/null | tail -1

echo
echo "=== CREDENTIAL-SUBMISSION ASSESSMENT ==="
echo "Largest outbound TLS packet:"
tshark -r "$PCAP" -Y "ip.src==$CLIENT && ip.dst==$IP && tls.app_data" \
-T fields -e frame.time -e frame.len 2>/dev/null |
sort -k2 -nr | head -1

echo "HTTPS content is encrypted."
echo "Outbound metadata is consistent with a small HTTPS submission,"
echo "but credential contents or compromise cannot be confirmed."

echo
echo "=== POST-CLICK REAL PORTAL CHECK ==="
tshark -r "$PCAP" -Y 'dns.qry.name=="meddefense.com"' \
-T fields -e frame.time -e ip.src -e ip.dst -e dns.qry.name -e dns.a 2>/dev/null

echo
echo "=== 4x00 CORRELATION ==="
DOMAIN_MATCH=$(tshark -r "$PCAP" -Y "dns.qry.name==\"$DOMAIN\"" \
-T fields -e dns.qry.name 2>/dev/null | sed -n '1p')

IP_MATCH=$(tshark -r "$PCAP" -Y "ip.addr==$IP" \
-T fields -e ip.addr 2>/dev/null | sed -n '1p')

[ -n "$DOMAIN_MATCH" ] && echo "IOC domain match: $DOMAIN"
[ -n "$IP_MATCH" ] && echo "IOC IP match: $IP"

if [ -n "$DOMAIN_MATCH" ] && [ -n "$IP_MATCH" ]; then
    echo "Conclusion: PCAP confirms contact with the phishing infrastructure identified in 4x00."
else
    echo "Conclusion: Known 4x00 IOC contact was not fully confirmed."
fi
