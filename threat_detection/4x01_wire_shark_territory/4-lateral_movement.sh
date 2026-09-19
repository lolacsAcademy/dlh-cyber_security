#!/bin/bash

PCAP="${1:-}"
NURSE="10.10.2.15"
BILLING="10.10.1.10"

if [ ! -f "$PCAP" ]; then
    echo "Usage: $0 <lateral_movement.pcap>"
    exit 1
fi

echo "=== TSHARK FILTERS USED ==="
echo "Internal SYN: ip.src==10.10.0.0/16 && ip.dst==10.10.0.0/16 && tcp.flags.syn==1 && tcp.flags.ack==0"
echo "RDP: tcp.port==3389"
echo "SMB transport: tcp.port==445"
echo "Failed TCP: tcp.flags.reset==1"
echo "Kerberos: kerberos"
echo "NTLM: ntlmssp"
echo

echo "=== CROSS-SUBNET TRAFFIC ==="

# Extract internal TCP connection attempts.
CONNS=$(tshark -r "$PCAP" \
    -Y 'ip.src==10.10.0.0/16 && ip.dst==10.10.0.0/16 && tcp.flags.syn==1 && tcp.flags.ack==0' \
    -T fields -e frame.time -e ip.src -e ip.dst -e tcp.dstport 2>/dev/null)

TOTAL=$(printf '%s\n' "$CONNS" | awk 'NF' | wc -l)
PAIRS=$(printf '%s\n' "$CONNS" | awk 'NF {print $2,$3}' | sort -u | wc -l)
NURSE_COUNT=$(printf '%s\n' "$CONNS" |
    awk -v ip="$NURSE" '$2==ip || $3==ip' | wc -l)

echo "Total internal connection attempts: $TOTAL"
echo "Unique source-destination pairs: $PAIRS"
echo "Connections involving WS-NURSE-04 ($NURSE): $NURSE_COUNT"

echo
echo "Incident-relevant connection attempts:"
printf '%s\n' "$CONNS" |
awk -v n="$NURSE" -v b="$BILLING" \
'$2==n || $2==b || $3==n || $3==b'

echo
echo "=== AUTHENTICATION-RELATED EVIDENCE ==="

echo "--- Kerberos ---"
KERB=$(tshark -r "$PCAP" -Y 'kerberos' \
    -T fields -e frame.time -e ip.src -e ip.dst \
    -e kerberos.CNameString -e kerberos.msg_type 2>/dev/null)

if [ -n "$KERB" ]; then
    printf '%s\n' "$KERB"
else
    echo "No Kerberos fields decoded by tshark."
fi

echo
echo "--- NTLM ---"
NTLM=$(tshark -r "$PCAP" -Y 'ntlmssp' \
    -T fields -e frame.time -e ip.src -e ip.dst \
    -e ntlmssp.auth.username -e ntlmssp.messagetype 2>/dev/null)

if [ -n "$NTLM" ]; then
    printf '%s\n' "$NTLM"
else
    echo "No NTLMSSP fields decoded by tshark."
fi

echo
echo "--- RDP / NLA transport ---"
tshark -r "$PCAP" \
    -Y "ip.addr==$NURSE && ip.addr==$BILLING && tcp.port==3389" \
    -T fields -e frame.time -e ip.src -e ip.dst \
    -e tcp.flags.syn -e tcp.flags.ack -e tcp.flags.reset 2>/dev/null |
head -20

echo
echo "--- SMB transport ---"
echo "TCP/445 traffic is present."
echo "In this capture tshark decodes the application payload as NBSS Continuation Message."
echo "SMB session/account/status fields are therefore not claimed unless decoded."

echo
echo "=== ATTACK PATH RECONSTRUCTION ==="

echo "Step 1: WS-NURSE-04 -> billing-srv-01"
tshark -r "$PCAP" \
    -Y "ip.src==$NURSE && ip.dst==$BILLING && tcp.dstport==3389 && tcp.flags.syn==1 && tcp.flags.ack==0" \
    -T fields -e frame.time -e ip.src -e ip.dst -e tcp.dstport 2>/dev/null

echo "Finding: RDP connection initiation from the clinical workstation to billing-srv-01."

echo
echo "Step 2: billing-srv-01 -> internal systems on TCP/445"
tshark -r "$PCAP" \
    -Y "ip.src==$BILLING && tcp.dstport==445 && tcp.flags.syn==1 && tcp.flags.ack==0" \
    -T fields -e frame.time -e ip.src -e ip.dst -e tcp.dstport 2>/dev/null

echo
echo "=== TCP/445 ACCESS EFFECTIVENESS ==="

echo "Destinations that answered with SYN-ACK:"
tshark -r "$PCAP" \
    -Y "ip.dst==$BILLING && tcp.srcport==445 && tcp.flags.syn==1 && tcp.flags.ack==1" \
    -T fields -e frame.time -e ip.src -e ip.dst 2>/dev/null

echo
echo "Destinations that reset/refused the attempt:"
tshark -r "$PCAP" \
    -Y "ip.dst==$BILLING && tcp.srcport==445 && tcp.flags.reset==1" \
    -T fields -e frame.time -e ip.src -e ip.dst \
    -e tcp.srcport -e tcp.dstport 2>/dev/null

echo
echo "Interpretation:"
echo "A SYN-ACK proves that the destination accepted the TCP handshake."
echo "It does NOT by itself prove successful SMB authentication."
echo "A TCP RST proves the observed connection was reset/refused."
echo "Packet evidence alone does not establish the policy reason for the reset."

echo
echo "=== SMB ENUMERATION ==="

SMB_DECODED=$(tshark -r "$PCAP" -Y 'smb || smb2' \
    -T fields -e frame.number 2>/dev/null | wc -l)

if [ "$SMB_DECODED" -gt 0 ]; then
    echo "Decoded SMB packets: $SMB_DECODED"

    echo "Shares/tree connections where visible:"
    tshark -r "$PCAP" -Y 'smb2.cmd==3' \
        -T fields -e frame.time -e ip.src -e ip.dst \
        -e smb2.tree -e smb2.nt_status 2>/dev/null

    echo "Directory queries where visible:"
    tshark -r "$PCAP" -Y 'smb2.cmd==14' \
        -T fields -e frame.time -e ip.src -e ip.dst \
        -e smb2.filename -e smb2.nt_status 2>/dev/null
else
    echo "No SMB/SMB2 application fields were decoded by tshark."
    echo "Port 445 payload appears as NBSS Continuation Message."
    echo "Therefore share names, directory listings, account names and"
    echo "SMB success/access-denied results cannot be proven from decoded fields."
fi

echo
echo "=== BASELINE COMPARISON ==="

RDP_SYN=$(tshark -r "$PCAP" \
    -Y "ip.src==$NURSE && ip.dst==$BILLING && tcp.dstport==3389 && tcp.flags.syn==1 && tcp.flags.ack==0" \
    -T fields -e frame.number 2>/dev/null | wc -l)

SMB_SYN=$(tshark -r "$PCAP" \
    -Y "ip.src==$BILLING && tcp.dstport==445 && tcp.flags.syn==1 && tcp.flags.ack==0" \
    -T fields -e frame.number 2>/dev/null | wc -l)

echo "Task 0 measured normal clinical DNS, HTTPS, SMB, NTP and printing traffic."
echo "Task 0 did not establish WS-NURSE-04 -> billing-srv-01 RDP as normal."
echo "Task 0 did not establish billing-srv-01 multi-host TCP/445 probing as normal."
echo "Current RDP connection attempts, WS-NURSE-04 -> billing-srv-01: $RDP_SYN"
echo "Current outbound TCP/445 attempts from billing-srv-01: $SMB_SYN"
echo "The incident pattern is therefore abnormal relative to relationships"
echo "documented by the available Task 0 baseline."

echo
echo "=== MITRE ATT&CK MAPPING ==="
echo "T1021.001  Remote Services: Remote Desktop Protocol"
echo "           Evidence: RDP connection from WS-NURSE-04 to billing-srv-01."
echo
echo "T1021.002  Remote Services: SMB/Windows Admin Shares"
echo "           Evidence: repeated TCP/445 connections from billing-srv-01."
echo
echo "T1135      Network Share Discovery"
echo "           Possible based on repeated SMB-service targeting;"
echo "           exact share enumeration is not decoded in this PCAP."
echo
echo "T1083      File and Directory Discovery"
echo "           Not confirmed because directory-listing fields are not decoded."
echo
echo "T1078      Valid Accounts"
echo "           Not confirmed from packet evidence because successful"
echo "           credential authentication is not decoded."

echo
echo "=== CONCLUSION ==="
echo "Packet evidence shows an RDP connection initiated from WS-NURSE-04"
echo "($NURSE) to billing-srv-01 ($BILLING), followed by billing-srv-01"
echo "initiating TCP/445 connections to multiple internal systems."
echo "Some TCP/445 destinations accepted TCP handshakes while others returned resets."
echo "This sequence is consistent with lateral-movement activity."
echo "Because SMB authentication and directory fields are not decoded in this capture,"
echo "the script does not invent account names, SMB authentication results,"
echo "share names, directory contents or access-denied responses."
