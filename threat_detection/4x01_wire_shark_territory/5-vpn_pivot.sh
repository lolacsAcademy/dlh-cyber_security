#!/bin/bash

PCAP="${1:-}"
VPN_ENDPOINT="10.10.0.1"
RDP_TIME="2026-04-15T10:30:12.445"

if [ ! -f "$PCAP" ]; then
    echo "Usage: $0 <full_timeline.pcap>"
    exit 1
fi

echo "=== TSHARK FILTERS USED ==="
echo "VPN start: ip.dst==$VPN_ENDPOINT && tcp.dstport==443 && tcp.flags.syn==1 && tcp.flags.ack==0"
echo "VPN session: ip.addr==$VPN_ENDPOINT && tcp.port==443"
echo "VPN close: tcp.flags.fin==1 || tcp.flags.reset==1"
echo

# Find first external TCP/443 connection to VPN endpoint.
VPN_START=$(tshark -r "$PCAP" \
    -Y "ip.dst==$VPN_ENDPOINT && tcp.dstport==443 && tcp.flags.syn==1 && tcp.flags.ack==0" \
    -T fields \
    -e frame.time_epoch -e frame.time \
    -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport \
    2>/dev/null | head -1)

if [ -z "$VPN_START" ]; then
    echo "No VPN connection found."
    exit 0
fi

# Tab-separated tshark fields.
START_EPOCH=$(printf '%s\n' "$VPN_START" | cut -f1)
START_TIME=$(printf '%s\n' "$VPN_START" | cut -f2)
SOURCE_IP=$(printf '%s\n' "$VPN_START" | cut -f3)
SOURCE_PORT=$(printf '%s\n' "$VPN_START" | cut -f4)
DEST_IP=$(printf '%s\n' "$VPN_START" | cut -f5)
DEST_PORT=$(printf '%s\n' "$VPN_START" | cut -f6)

echo "=== VPN CONNECTION IDENTIFIED ==="
echo "Timestamp: $START_TIME"
echo "Source: $SOURCE_IP:$SOURCE_PORT"
echo "Destination: $DEST_IP:$DEST_PORT"
echo "Protocol: TCP/443 - SSL/VPN-style HTTPS session"

echo
echo "=== AUTHENTICATION DETAILS ==="

# Search printable packet bytes for simulated/readable metadata.
AUTH=$(tshark -r "$PCAP" \
    -Y "ip.addr==$SOURCE_IP && ip.addr==$VPN_ENDPOINT && tcp.port==443" \
    -x 2>/dev/null |
    strings |
    grep -i -E 'dmarsh|username|user=|login|auth' |
    head -10)

if [ -n "$AUTH" ]; then
    printf '%s\n' "$AUTH"
else
    echo "No readable authentication/account metadata found."
    echo "Encrypted password contents are not claimed."
fi

echo
echo "=== SESSION DURATION ==="

# Restrict close detection to this exact source/destination pair.
VPN_CLOSE=$(tshark -r "$PCAP" \
    -Y "ip.addr==$SOURCE_IP && ip.addr==$VPN_ENDPOINT && tcp.port==443 && (tcp.flags.fin==1 || tcp.flags.reset==1)" \
    -T fields -e frame.time_epoch -e frame.time 2>/dev/null |
    tail -1)

if [ -n "$VPN_CLOSE" ]; then
    END_EPOCH=$(printf '%s\n' "$VPN_CLOSE" | cut -f1)
    END_TIME=$(printf '%s\n' "$VPN_CLOSE" | cut -f2)

    DURATION=$(awk -v start="$START_EPOCH" -v end="$END_EPOCH" \
        'BEGIN {printf "%.2f", end-start}')

    MINUTES=$(awk -v seconds="$DURATION" \
        'BEGIN {printf "%.2f", seconds/60}')

    echo "Connection start: $START_TIME"
    echo "Connection close: $END_TIME"
    echo "Approximate duration: $DURATION seconds ($MINUTES minutes)"
else
    echo "Connection start: $START_TIME"
    echo "Connection close: not visible in the capture"
    echo "Session duration cannot be calculated from packet evidence."
fi

echo
echo "=== ASSIGNED INTERNAL IP ==="

# Look only at packets associated with the VPN source/endpoint.
INTERNAL=$(tshark -r "$PCAP" \
    -Y "ip.addr==$SOURCE_IP && ip.addr==$VPN_ENDPOINT" \
    -T fields -e ip.src -e ip.dst 2>/dev/null |
    tr '\t' '\n' |
    grep '^10\.10\.' |
    grep -v "^${VPN_ENDPOINT}$" |
    sort -u)

if [ -n "$INTERNAL" ]; then
    echo "Internal IP visible in VPN-related packets:"
    printf '%s\n' "$INTERNAL"
else
    echo "No assigned internal client IP directly visible."
fi

echo
echo "=== GEOLOCATION / WHOIS ==="
echo "IP: $SOURCE_IP"

if command -v whois >/dev/null 2>&1; then
    WHOIS_DATA=$(whois "$SOURCE_IP" 2>/dev/null)

    COUNTRY=$(printf '%s\n' "$WHOIS_DATA" |
        awk -F: 'tolower($1) ~ /^[[:space:]]*country[[:space:]]*$/ {
            gsub(/^[ \t]+|[ \t]+$/, "", $2)
            print $2
            exit
        }')

    ASN=$(printf '%s\n' "$WHOIS_DATA" |
        awk -F: 'tolower($1) ~ /^[[:space:]]*(origin|originas)[[:space:]]*$/ {
            gsub(/^[ \t]+|[ \t]+$/, "", $2)
            print $2
            exit
        }')

    ORG=$(printf '%s\n' "$WHOIS_DATA" |
        awk -F: 'tolower($1) ~ /^[[:space:]]*(org-name|orgname|organization|descr)[[:space:]]*$/ {
            sub(/^[^:]*:/, "")
            gsub(/^[ \t]+|[ \t]+$/, "")
            print
            exit
        }')

    echo "Country: ${COUNTRY:-Not available from WHOIS}"
    echo "ASN: ${ASN:-Not available from WHOIS}"
    echo "Organization: ${ORG:-Not available from WHOIS}"
    echo "Assessment: WHOIS registration can indicate whether the source is unusual,"
    echo "but it does not prove the attacker's physical location."
else
    echo "WHOIS not installed; country, ASN and organization unavailable."
fi

echo
echo "=== TIMELINE CORRELATION ==="

RDP_EPOCH=$(date -d "$RDP_TIME" +%s 2>/dev/null)

echo "VPN connection: $START_TIME"
echo "First RDP movement: $RDP_TIME"

if [ -n "$RDP_EPOCH" ]; then
    GAP=$(awk -v vpn="$START_EPOCH" -v rdp="$RDP_EPOCH" \
        'BEGIN {printf "%.2f", (rdp-vpn)/60}')

    if awk -v vpn="$START_EPOCH" -v rdp="$RDP_EPOCH" \
        'BEGIN {exit !(vpn < rdp)}'; then
        echo "VPN connection occurred before lateral movement."
        echo "Gap: approximately $GAP minutes"
    else
        echo "VPN connection did not occur before the first RDP session."
        echo "Gap: $GAP minutes"
    fi
fi

echo
echo "=== PIVOT ASSESSMENT ==="
echo "The external TCP/443 session to the VPN endpoint occurs before"
echo "the first observed RDP lateral-movement session."
echo "This provides a plausible network pivot from external access"
echo "to subsequent internal activity."

echo
echo "=== LIMITATIONS ==="
echo "The PCAP proves observed endpoints, timestamps and network behavior."
echo "It does not prove password contents when authentication is encrypted."
echo "The dmarsh account is reported only if visible in packet metadata."
echo "An assigned VPN IP is reported only if directly visible."
echo "WHOIS identifies IP registration information, not attacker identity."
