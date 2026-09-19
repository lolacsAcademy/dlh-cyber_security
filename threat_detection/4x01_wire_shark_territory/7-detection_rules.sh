#!/bin/bash

echo "================================================================"
echo "   DETECTION ENGINEERING PLAN"
echo "================================================================"

echo
echo "[*] Detection 1: C2 Beaconing"
echo "    Attack phase: Phase 3 - C2 Beaconing"
echo "    Type: Frequency-based behavioral detection"
echo
echo "    Rule logic:"
echo "      Group connections by src_ip and dst_ip over 3600 seconds."
echo "      If connection_count > 10:"
echo "        calculate intervals between consecutive connections"
echo "        interval_mean = average(intervals)"
echo "        interval_stddev = standard_deviation(intervals)"
echo "      If interval_stddev < interval_mean * 0.15:"
echo "        ALERT: Possible C2 beaconing"
echo
echo "    Data source:"
echo "      PCAP-derived session logs, Zeek conn.log, NetFlow or proxy logs."
echo
echo "    Test scenario:"
echo "      10.10.2.15 connects to the same external IP every 300 seconds"
echo "      for more than 10 sessions within 60 minutes."
echo
echo "    Expected false positives:"
echo "      Monitoring agents, update clients, health checks and backup tools."
echo "      Allowlisting and baseline comparison reduce false positives."
echo
echo "    Implementation options:"
echo "      SIEM: aggregate src_ip/dst_ip sessions and calculate interval regularity."
echo "      Zeek: track connection timestamps per source/destination pair."
echo "      Python: scheduled analysis calculates mean and standard deviation."
echo "      NetFlow: aggregate repeated flows and evaluate periodicity."

echo
echo "[*] Detection 2: DNS Query Length Anomaly"
echo "    Attack phase: Phase 7 - DNS Exfiltration"
echo
echo "    Rule logic:"
echo "      Extract the left-most label from dns.qry.name."
echo "      If length(left_most_label) > 40:"
echo "        ALERT: Abnormally long DNS subdomain label"
echo
echo "    Data source:"
echo "      DNS resolver logs, Zeek dns.log, PCAP or SIEM DNS events."
echo
echo "    Test scenario:"
echo "      Host queries:"
echo "      <45-character-encoded-label>.data-sync.meddefense-portal.com"
echo
echo "    Why it matters:"
echo "      Long labels containing Base32/Base64-like characters can represent"
echo "      data encoded into DNS names for tunneling."
echo
echo "    Expected false positives:"
echo "      CDNs, tracking systems, cloud services and security products can"
echo "      legitimately generate long labels."

echo
echo "[*] Detection 3: VPN Geo-Anomaly"
echo "    Attack phase: Phase 4 - External Access / VPN Pivot"
echo
echo "    Rule logic:"
echo "      Enrich VPN source_ip with country and ASN."
echo "      If country NOT IN expected_countries"
echo "      OR ASN NOT IN expected_asns:"
echo "        compare with account login history"
echo "        ALERT: Suspicious VPN geography/network"
echo
echo "    Data source:"
echo "      VPN authentication logs plus GeoIP/WHOIS enrichment and"
echo "      historical account-login data."
echo
echo "    Test scenario:"
echo "      Account dmarsh authenticates from external IP 154.118.42.89."
echo "      Source registration/geography is outside the organization's"
echo "      established access baseline."
echo
echo "    Expected false positives:"
echo "      Employee travel, mobile carriers, corporate proxies and commercial VPNs."
echo
echo "    Requirement:"
echo "      Geo-anomaly detection requires an IP-to-country/ASN enrichment source."
echo "      WHOIS/GeoIP location is context, not proof of attacker location."

echo
echo "[*] Detection 4: Cross-Role RDP"
echo "    Attack phase: Phase 5 - Lateral Movement"
echo
echo "    Rule logic:"
echo "      If destination_port == 3389"
echo "      AND destination_ip belongs to server subnet"
echo "      AND source account/asset role is clinical or non-IT:"
echo "        ALERT: Unexpected cross-role RDP"
echo
echo "    Data source:"
echo "      Packet/session metadata for RDP source and destination."
echo "      Authentication logs or identity inventory are required to determine"
echo "      account role and authentication result."
echo
echo "    Test scenario:"
echo "      WS-NURSE-04 (10.10.2.15) initiates RDP to"
echo "      billing-srv-01 (10.10.1.10)."
echo
echo "    Expected false positives:"
echo "      Approved support activity, administrators using clinical systems,"
echo "      or documented remote-maintenance workflows."

echo
echo "[*] Detection 5: DNS Tunneling TXT Query Pattern"
echo "    Attack phase: Phase 7 - DNS Exfiltration"
echo
echo "    Rule logic:"
echo "      Group DNS TXT queries by src_ip and base_domain."
echo "      If TXT query count > 10 within 120 seconds"
echo "      AND left-most labels appear encoded or high-entropy:"
echo "        ALERT: Possible DNS tunneling"
echo
echo "    Data source:"
echo "      DNS resolver logs, Zeek dns.log or packet-derived DNS events."
echo
echo "    Test scenario:"
echo "      billing-srv-01 repeatedly sends TXT queries containing"
echo "      Base32-like labels to data-sync.meddefense-portal.com."
echo
echo "    Expected false positives:"
echo "      SPF/DKIM/DMARC activity, service discovery and legitimate applications"
echo "      that make repeated TXT queries."
echo
echo "    Tuning:"
echo "      Require repeated queries to one base domain plus encoded-label"
echo "      characteristics rather than alerting on every TXT query."

echo
echo "[*] Detection 6: TLS to Campaign Lookalike Domain"
echo "    Attack phase: Phase 2 - Phishing Click"
echo
echo "    Rule logic:"
echo "      Maintain:"
echo "        phishing_ioc_list = known campaign domains"
echo "        first_seen_table = domains first observed by the organization"
echo
echo "      If tls.sni matches phishing_ioc_list"
echo "      OR tls.sni matches a campaign lookalike in first_seen_table:"
echo "        ALERT: TLS connection to suspicious campaign domain"
echo
echo "    Data source:"
echo "      TLS SNI from Zeek ssl.log, proxy logs, firewall metadata or PCAP,"
echo "      plus an internal IOC list or first-seen domain table."
echo
echo "    Test scenario:"
echo "      10.10.2.15 sends TLS ClientHello with SNI:"
echo "      meddefense-portal.com"
echo
echo "    Expected false positives:"
echo "      Legitimate newly observed domains and unrelated domains with"
echo "      organization-like naming."
echo
echo "    Requirement:"
echo "      A live domain-age feed is NOT required."
echo "      Campaign IOC lists and an internal first-seen table are sufficient."

echo
echo "=== DETECTION COVERAGE UPDATE ==="
echo "Before packet analysis:"
echo "  Campaign visibility was primarily based on phishing/email IOCs."
echo
echo "After packet analysis:"
echo "  Detection coverage includes:"
echo "    phishing-domain TLS contact"
echo "    periodic C2-style connections"
echo "    anomalous VPN access"
echo "    cross-role RDP"
echo "    internal lateral-movement indicators"
echo "    long encoded DNS labels"
echo "    high-frequency TXT tunneling"
echo
echo "Remaining gaps:"
echo "  Endpoint execution requires endpoint/EDR telemetry."
echo "  Account role requires identity or asset context."
echo "  VPN geography requires GeoIP/ASN enrichment."
echo "  Encrypted TLS does not expose exact credential contents."
echo
echo "================================================================"
echo "Detection engineering plan complete."
echo "================================================================"
