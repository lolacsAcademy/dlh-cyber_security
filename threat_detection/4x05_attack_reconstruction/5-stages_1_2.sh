#!/bin/bash

echo "================================================================"
echo "   ATTACK RECONSTRUCTION: Stages 1-2"
echo "   Initial Access through C2 Establishment"
echo "================================================================"

echo
echo "STAGE 1: INITIAL ACCESS (Phishing)"
echo
echo "  2026-04-14T13:18:05Z  Diane (dmarsh) clicked the credential link"
echo "    Host: WS-RECV-03"
echo "    URL: meddefense-portal.com/login.aspx"
echo "    Evidence: 4x00_phishing_summary.txt - browser history + user report"
echo "    Email evidence: SPF hardfail; DKIM missing"
echo "    Technique: T1566.001 Spearphishing Link"
echo "    Confidence: CONFIRMED"
echo
echo "  2026-04-14T13:18:42Z  Credentials submitted"
echo "    Evidence: 4x00 phishing findings + 4x01 PCAP POST"
echo "    Technique: T1078 Valid Accounts"
echo "    Confidence: CONFIRMED - converged evidence"
echo
echo "  Temporal anchor: credential exposure = 2026-04-14T13:18:42Z"

echo
echo "STAGE 2: C2 ESTABLISHMENT"
echo
echo "  2026-04-15T08:43:18Z  Second-wave email E1B delivered"
echo "    Subject: Updated invoice - Q1 reconciliation"
echo "    Attachment: April-Invoice-MD2026.docm"
echo "    Evidence: 4x01_network_timeline.txt"
echo "    Confidence: CONFIRMED"
echo
echo "  2026-04-15T08:51:09Z  DNS query for update.healthbane-c2.net"
echo "    Resolved: 185.220.101.45"
echo "    Evidence: 4x01 DNS PCAP"
echo "    Confidence: CONFIRMED"
echo
echo "  2026-04-15T08:51:11Z  Stage 2 RAT downloaded"
echo "    Destination: 185.220.101.45:443"
echo "    File: svchost_update.exe"
echo "    Evidence: 4x01 TLS payload-size analysis"
echo "    Confidence: CONFIRMED"
echo
echo "  2026-04-15T08:51:38Z  First canonical C2 beacon"
echo "    Source: WS-RECV-03 (10.10.3.21)"
echo "    Destination: 185.220.101.45:443"
echo "    SNI: sync.healthbane-c2.net"
echo "    URI: POST /api/v1/checkin"
echo "    Pattern: 300 +/- 10 seconds; mean 304 seconds in 4x01"
echo "    Encryption: RC4-wrapped JSON over TLS"
echo "    Evidence: 4x01 PCAP; IR firewall later confirms same C2 infrastructure"
echo "    Technique: T1071.001 Application Layer Protocol: Web"
echo "    Technique: T1573.001 Encrypted Channel: Symmetric Cryptography"
echo "    Confidence: CONFIRMED"
echo
echo "  NETWORK TIMESTAMP RESOLUTION:"
echo "    Firewall timestamps are 4 seconds ahead of PCAP/Wazuh."
echo "    Firewall time is authoritative for connection initiation."
echo
echo "  SECONDARY C2:"
echo "    203.0.113.47:8443 first seen 2026-05-07T06:48:11Z"
echo "    Evidence: 3-firewall_analysis.sh / IR firewall sessions"
echo "    Assessment: PROBABLE secondary/fallback C2"
echo "    Confidence: PROBABLE"
echo "    Finding: NOT active during Stage 2; it appeared later in the attack."
echo
echo "  T1568 Dynamic Resolution: NOT MAPPED"
echo "    Supplied 4x01/4x02 evidence does not support this technique."

echo
echo "STAGE 1-2 SUMMARY:"
echo "  Credential exposure: 2026-04-14T13:18:42Z"
echo "  First canonical C2 beacon: 2026-04-15T08:51:38Z"
echo "  Elapsed time: approximately 19 hours 33 minutes"
echo "  Techniques: T1566.001, T1078, T1071.001, T1573.001"
echo "  Primary C2: 185.220.101.45:443"
echo "  Secondary C2: 203.0.113.47:8443 - appeared later, not Stage 2"
echo "  Overall confidence: HIGH - correlated primary network/email evidence"

echo
echo "================================================================"
