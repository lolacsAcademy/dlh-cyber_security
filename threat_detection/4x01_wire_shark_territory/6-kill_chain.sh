#!/bin/bash

# Known evidence from the completed investigations.
PHISH_TIME="2026-04-14T11:02:33"
PHISH_END="2026-04-14T11:03:20"
VPN_TIME="2026-04-15T09:45:22"
RDP_TIME="2026-04-15T10:30:12"
DNS_COUNT="120"
DNS_BYTES="3914"

echo "================================================================"
echo "   COMPLETE KILL CHAIN RECONSTRUCTION"
echo "   Incident: Phishing -> VPN Pivot -> Lateral Movement -> DNS Exfiltration"
echo "================================================================"

echo
echo "PHASE 1: INITIAL ACCESS"
echo "ATT&CK: T1566.002 - Spearphishing Link"
echo "Evidence: 4x00 phishing investigation"
echo "IOC domain: meddefense-portal.com"
echo "IOC IP: 91.234.99.107"
echo "Status: Context from 4x00, not packet evidence."

echo
echo "PHASE 2: PHISHING CLICK / CREDENTIAL-HARVESTING SESSION"
echo "ATT&CK: T1056.003 - Web Portal Capture"
echo "PCAP: phishing_click.pcap"
echo "Time: $PHISH_TIME to $PHISH_END"
echo "Source: 10.10.2.15"
echo "Destination: 91.234.99.107"
echo "Confirmed packet evidence:"
echo "  DNS: meddefense-portal.com -> 91.234.99.107"
echo "  TLS SNI: meddefense-portal.com"
echo "  Client -> server: 2000 bytes across 13 TCP segments"
echo "  Largest outbound TLS packet: 541 bytes"
echo "Inference:"
echo "  Encrypted metadata is consistent with a small HTTPS form submission."
echo "  Password contents were not visible and are not claimed."

echo
echo "PHASE 3: BEACONING"
echo "ATT&CK: T1071.001 - Web Protocols"
echo "PCAP: c2_beaconing.pcap"
echo "Status: Include only findings established by the c2_beaconing investigation."
echo "Visibility tested: repeated outbound communication pattern."
echo "No beacon count, interval or endpoint is invented here."

echo
echo "PHASE 4: VPN PIVOT"
echo "ATT&CK: T1133 - External Remote Services"
echo "PCAP: full_timeline.pcap"
echo "Time: $VPN_TIME"
echo "Source: 154.118.42.89:49872"
echo "Destination: 10.10.0.1:443"
echo "Confirmed packet evidence:"
echo "  AUTH:user=dmarsh,pass=***"
echo "  AUTH:OK"
echo "  VPN-style TCP/443 session"
echo "  Session duration: approximately 48.42 minutes"
echo "WHOIS context:"
echo "  Country: NG"
echo "  ASN: AS37340"
echo "Inference:"
echo "  The session provides a plausible external-to-internal pivot."
echo "  Plaintext password contents were not observed."

echo
echo "PHASE 5: RDP LATERAL MOVEMENT"
echo "ATT&CK: T1021.001 - Remote Desktop Protocol"
echo "PCAP: lateral_movement.pcap"
echo "Time: $RDP_TIME"
echo "Source: 10.10.2.15"
echo "Destination: 10.10.1.10:3389"
echo "Confirmed packet evidence:"
echo "  RDP TCP connection initiated from WS-NURSE-04 to billing-srv-01."
echo "  VPN activity occurred approximately 44.83 minutes earlier."

echo
echo "PHASE 6: INTERNAL TCP/445 ACTIVITY"
echo "ATT&CK: T1021.002 - SMB/Windows Admin Shares"
echo "ATT&CK: T1135 - Network Share Discovery (possible)"
echo "PCAP: lateral_movement.pcap"
echo "Source: 10.10.1.10"
echo "Confirmed packet evidence:"
echo "  TCP/445 attempts to:"
echo "    10.10.1.20"
echo "    10.10.1.30"
echo "    10.10.1.31"
echo "    10.10.4.100"
echo "    10.10.4.101"
echo "    10.10.1.60"
echo "  10.10.1.20, .30, .31 and .60 answered with SYN-ACK."
echo "  Two restricted attempts received TCP resets."
echo "Limitation:"
echo "  SMB fields were not decoded; authentication success, share names,"
echo "  directory listings and T1083 File and Directory Discovery are unconfirmed."

echo
echo "PHASE 7: DNS EXFILTRATION"
echo "ATT&CK: T1048.003 - Exfiltration Over Unencrypted Non-C2 Protocol"
echo "PCAP: dns_exfil.pcap"
echo "Source: billing-srv-01 (10.10.1.10)"
echo "Destination domain: data-sync.meddefense-portal.com"
echo "Confirmed packet evidence:"
echo "  Anomalous TXT queries: $DNS_COUNT"
echo "  Base32-like encoded subdomain labels"
echo "  Decodable structured data fragments were recovered"
echo "  TXT response metadata contained command/control-style content"
echo "  Estimated raw payload: $DNS_BYTES bytes"
echo "Assessment:"
echo "  Packet behavior is consistent with DNS tunneling and data exfiltration."

echo
echo "=== VISIBILITY / DEFENSE LAYERS ==="
echo "Email authentication/policy:"
echo "  Tested during phishing delivery; details come from 4x00 context."
echo "User click:"
echo "  Confirmed by DNS/TLS contact with phishing infrastructure."
echo "TLS encryption:"
echo "  Hid exact submitted HTTPS form contents."
echo "Beaconing visibility:"
echo "  Evaluated in c2_beaconing.pcap."
echo "VPN authentication:"
echo "  AUTH metadata exposed dmarsh context and AUTH:OK."
echo "RDP access:"
echo "  RDP connection initiation observed."
echo "SMB enumeration:"
echo "  Repeated TCP/445 targeting observed; detailed SMB enumeration unconfirmed."
echo "DNS exfiltration:"
echo "  Repeated encoded TXT tunnel traffic observed."

echo
echo "=== DWELL TIME ==="

START_EPOCH=$(date -d "$PHISH_TIME" +%s 2>/dev/null)

# Find last exfiltration time if the DNS PCAP hash/path is supplied.
if [ -n "${DNS_PCAP:-}" ] && [ -f "$DNS_PCAP" ]; then
    LAST_DNS=$(tshark -r "$DNS_PCAP" \
        -Y 'ip.src==10.10.1.10 && dns.flags.response==0 && dns.qry.name contains "data-sync.meddefense-portal.com"' \
        -T fields -e frame.time_epoch -e frame.time 2>/dev/null | tail -1)

    LAST_EPOCH=$(printf '%s\n' "$LAST_DNS" | cut -f1)
    LAST_TIME=$(printf '%s\n' "$LAST_DNS" | cut -f2)

    if [ -n "$START_EPOCH" ] && [ -n "$LAST_EPOCH" ]; then
        DWELL=$(awk -v a="$START_EPOCH" -v b="$LAST_EPOCH" \
            'BEGIN {printf "%.2f", (b-a)/3600}')

        echo "First known access-related packet activity: $PHISH_TIME"
        echo "Last observed exfiltration activity: $LAST_TIME"
        echo "Observed dwell time: approximately $DWELL hours"
    fi
else
    echo "First known access-related packet activity: $PHISH_TIME"
    echo "Last exfiltration timestamp must be taken from dns_exfil.pcap."
    echo "Exact total dwell time is not invented without that timestamp."
fi

echo
echo "=== CRITICAL PIVOT POINTS ==="
echo "1. Phishing delivery - blocking the malicious link could stop initial access."
echo "2. User click - domain/IP blocking could prevent contact."
echo "3. VPN authentication - stronger access controls could stop the external pivot."
echo "4. RDP movement - restricting abnormal workstation-to-server RDP could limit movement."
echo "5. TCP/445 activity - internal controls could limit server probing."
echo "6. DNS tunnel - TXT/encoded-label monitoring could detect or block exfiltration."

echo
echo "=== IMPACT ASSESSMENT ==="
echo "Confirmed systems/endpoints involved:"
echo "  WS-NURSE-04 (10.10.2.15)"
echo "  VPN endpoint (10.10.0.1)"
echo "  billing-srv-01 (10.10.1.10)"
echo "  Multiple internal TCP/445 destinations"
echo
echo "Likely data impact:"
echo "  Structured data fragments were decoded from the DNS tunnel."
echo "  Approximate raw tunnel payload: $DNS_BYTES bytes."
echo
echo "Systems that resisted access:"
echo "  Two TCP/445 attempts were reset/refused."
echo
echo "Unconfirmed:"
echo "  Exact plaintext phishing password"
echo "  Exact VPN password"
echo "  VPN-assigned internal client IP"
echo "  SMB authentication results"
echo "  SMB share/directory contents"
echo "  Endpoint malware execution"
echo "  MFA state"
echo "  SIEM alerting"

echo
echo "=== CONFIRMED VS INFERENCE ==="
echo "CONFIRMED:"
echo "  Packet timestamps, IPs, ports, DNS queries, TLS SNI,"
echo "  VPN AUTH metadata, RDP transport, TCP/445 attempts/resets,"
echo "  and DNS tunnel behavior described above."
echo
echo "INFERENCE:"
echo "  Credential harvesting from encrypted HTTPS metadata,"
echo "  the VPN session acting as the attacker pivot,"
echo "  and the overall relationship between the observed phases."

echo
echo "================================================================"
echo "Kill-chain reconstruction complete."
echo "================================================================"
