#!/bin/bash

TOTAL_PHASES=7
DIRECT_PHASES=6
VISIBILITY=$(awk -v d="$DIRECT_PHASES" -v t="$TOTAL_PHASES" 'BEGIN {printf "%.0f", (d/t)*100}')

echo "================================================================"
echo "   EVIDENCE CROSS-CHECK - PCAP VISIBILITY"
echo "================================================================"

echo
printf "%-5s | %-23s | %-14s | %s\n" "Phase" "Attack Action" "PCAP Evidence?" "Verdict"
echo "------|-------------------------|----------------|------------------"
printf "%-5s | %-23s | %-14s | %s\n" "1" "Phishing delivery" "No" "NOT VISIBLE IN PCAP"
printf "%-5s | %-23s | %-14s | %s\n" "2" "Credential harvesting" "Yes" "STRONG INFERENCE"
printf "%-5s | %-23s | %-14s | %s\n" "3" "C2 beaconing" "Yes" "CONFIRMED"
printf "%-5s | %-23s | %-14s | %s\n" "4" "VPN pivot" "Yes" "STRONG INFERENCE"
printf "%-5s | %-23s | %-14s | %s\n" "5" "RDP lateral movement" "Yes" "CONFIRMED"
printf "%-5s | %-23s | %-14s | %s\n" "6" "SMB discovery" "Yes" "STRONG INFERENCE"
printf "%-5s | %-23s | %-14s | %s\n" "7" "DNS exfiltration" "Yes" "CONFIRMED"

echo
echo "=== PHASE 1: PHISHING DELIVERY ==="
echo "Verdict: NOT VISIBLE IN PCAP"
echo "Confirmed by PCAP:"
echo "  Nothing about the original email delivery."
echo "Context:"
echo "  4x00 identified the phishing campaign, malicious domain and IOC."
echo "Cannot confirm from packets alone:"
echo "  Email sender, message content, delivery result or mail policy decision."
echo "Additional evidence needed:"
echo "  Mail gateway logs, message headers and 4x00 email evidence."

echo
echo "=== PHASE 2: CREDENTIAL HARVESTING ==="
echo "Verdict: STRONG INFERENCE"
echo "Confirmed by PCAP:"
echo "  10.10.2.15 queried meddefense-portal.com."
echo "  DNS resolved the domain to 91.234.99.107."
echo "  TLS SNI identified meddefense-portal.com."
echo "  Encrypted client-to-server data was transmitted."
echo "Inferred:"
echo "  The outbound HTTPS metadata is consistent with a small form submission."
echo "Cannot confirm from packets alone:"
echo "  Exact password or exact form fields entered by the user."
echo "Additional evidence needed:"
echo "  Phishing web-server logs, browser/endpoint artifacts or user interview."

echo
echo "=== PHASE 3: C2 BEACONING ==="
echo "Verdict: CONFIRMED"
echo "Confirmed by PCAP:"
echo "  Repeated outbound communication with a regular beaconing pattern"
echo "  was established during the c2_beaconing.pcap investigation."
echo "Inferred:"
echo "  Regular automated communication is consistent with C2 behavior."
echo "Cannot confirm from packets alone:"
echo "  Which endpoint process generated the traffic."
echo "Additional evidence needed:"
echo "  Endpoint process logs, EDR telemetry and process/network correlation."

echo
echo "=== PHASE 4: VPN PIVOT ==="
echo "Verdict: STRONG INFERENCE"
echo "Confirmed by PCAP:"
echo "  External source 154.118.42.89 connected to 10.10.0.1:443."
echo "  Packet metadata exposed AUTH:user=dmarsh,pass=*** and AUTH:OK."
echo "  Session began before the observed RDP activity."
echo "Inferred:"
echo "  The VPN session was the external-to-internal pivot."
echo "Cannot confirm from packets alone:"
echo "  Exact password used, attacker identity or MFA state."
echo "Additional evidence needed:"
echo "  VPN authentication logs, identity-provider logs and MFA logs."

echo
echo "=== PHASE 5: RDP LATERAL MOVEMENT ==="
echo "Verdict: CONFIRMED"
echo "Confirmed by PCAP:"
echo "  10.10.2.15 initiated TCP/3389 communication to 10.10.1.10."
echo "  The destination answered the RDP TCP connection."
echo "Inferred:"
echo "  The timing and sequence are consistent with lateral movement."
echo "Cannot confirm from packets alone:"
echo "  Interactive user actions or exact authenticated account."
echo "Additional evidence needed:"
echo "  Windows authentication logs, RDP logs and endpoint telemetry."

echo
echo "=== PHASE 6: SMB DISCOVERY ==="
echo "Verdict: STRONG INFERENCE"
echo "Confirmed by PCAP:"
echo "  billing-srv-01 initiated six TCP/445 connection attempts."
echo "  Four destinations returned SYN-ACK."
echo "  Two attempts were reset/refused."
echo "Inferred:"
echo "  Repeated targeting of SMB services is consistent with discovery"
echo "  or lateral-movement activity."
echo "Cannot confirm from packets alone:"
echo "  SMB authentication success, share names, directory listings or files."
echo "Additional evidence needed:"
echo "  Windows server logs, SMB audit logs and endpoint telemetry."

echo
echo "=== PHASE 7: DNS EXFILTRATION ==="
echo "Verdict: CONFIRMED"
echo "Confirmed by PCAP:"
echo "  billing-srv-01 generated 120 anomalous TXT queries."
echo "  Queries used long Base32-like labels."
echo "  Structured data fragments were decoded from sample labels."
echo "  TXT responses contained command/control-style content."
echo "  Estimated raw tunnel payload was approximately 3914 bytes."
echo "Inferred:"
echo "  The behavior is consistent with DNS tunneling for data exfiltration."
echo "Cannot confirm from packets alone:"
echo "  Whether every transmitted record was successfully received or used."
echo "Additional evidence needed:"
echo "  Authoritative DNS logs, destination infrastructure logs and endpoint evidence."

echo
echo "=== CONFIRMED FROM PCAP ==="
echo "- DNS and TLS contact with meddefense-portal.com / 91.234.99.107"
echo "- C2-style repeated communication pattern"
echo "- External VPN connection and visible dmarsh AUTH metadata"
echo "- RDP transport from 10.10.2.15 to 10.10.1.10"
echo "- Multiple TCP/445 connection attempts and reset/refused responses"
echo "- Encoded DNS TXT tunneling behavior and decoded data fragments"

echo
echo "=== STRONG INFERENCE ==="
echo "- Credential submission through the phishing page"
echo "- VPN session acting as the external-to-internal pivot"
echo "- TCP/445 activity representing SMB discovery/lateral movement"
echo "- DNS tunnel being used for deliberate data exfiltration"

echo
echo "=== UNCONFIRMED / NOT VISIBLE IN PCAP ==="
echo "- Original phishing email delivery and mail-policy decision"
echo "- Exact phishing password entered"
echo "- Exact VPN password"
echo "- MFA state or user approval of authentication prompts"
echo "- Endpoint malware/process execution"
echo "- Exact SMB account, shares, directory contents or files"
echo "- Whether a SIEM alert fired"
echo "- Whether every exfiltrated record reached the attacker"

echo
echo "=== ADDITIONAL EVIDENCE NEEDED ==="
echo "- Endpoint/EDR process logs"
echo "- VPN authentication and identity-provider logs"
echo "- Windows/domain-controller authentication logs"
echo "- Mail gateway logs and message headers"
echo "- SMB/server audit logs"
echo "- DNS resolver and authoritative DNS logs"
echo "- Phishing web-server logs"
echo "- User interview where user intent/action must be established"

echo
echo "=== PACKET VISIBILITY SCORE ==="
echo "Direct PCAP evidence exists for $DIRECT_PHASES of $TOTAL_PHASES phases."
echo "Packet visibility: $VISIBILITY%"

echo
echo "=== WHERE PACKET EVIDENCE IS STRONG ==="
echo "Packets are strong evidence for timestamps, IP addresses, ports,"
echo "DNS names, connection direction, TCP behavior, TLS metadata and"
echo "observable communication patterns."

echo
echo "=== WHERE PACKET EVIDENCE HAS LIMITS ==="
echo "Packets may not reveal encrypted application contents, endpoint"
echo "process state, user intent, identity-provider decisions, server-side"
echo "actions or SIEM detections."

echo
echo "=== KEY LESSON ==="
echo "Packet evidence shows what communicated across the network."
echo "Log evidence can show authentication decisions, processes, accounts"
echo "and server-side actions that packets may not expose."
echo "A defensible investigation separates confirmed packet facts from"
echo "strong inference and from facts requiring additional log evidence."

echo
echo "================================================================"
echo "Evidence cross-check complete."
echo "================================================================"
