#!/bin/bash

REPORT="11-network_forensics_report.md"

cat > "$REPORT" <<'EOF'
# Network Forensics Investigation Report

## Executive Summary

Between 14 and 15 April 2026, packet evidence documented a sequence beginning with contact with phishing infrastructure and continuing through external VPN access, internal RDP/SMB activity, and DNS-based data transfer. The phishing session contacted `meddefense-portal.com` and `91.234.99.107`, while later traffic showed an external VPN connection using visible `dmarsh` authentication metadata followed by internal access activity. The DNS capture showed repeated TXT queries with long encoded labels from `billing-srv-01`, consistent with DNS tunneling and data exfiltration. Approximately 3,914 bytes of raw payload were estimated from the observed DNS tunnel. Several internal TCP/445 destinations accepted connections, while two observed attempts were reset/refused; exact credentials, endpoint execution and complete data contents remain unconfirmed from PCAP alone.

## Investigation Scope

### PCAPs analyzed

- `phishing_click.pcap` — phishing-domain DNS/TLS session.
- `c2_beaconing.pcap` — repeated outbound communication pattern.
- `dns_exfil.pcap` — DNS TXT tunneling and encoded labels.
- `lateral_movement.pcap` — RDP and internal TCP/445 activity.
- `full_timeline.pcap` — external VPN session and timeline correlation.

### Time period

Observed packet evidence spans 14–15 April 2026.

The documented phishing-click session occurred from approximately:
`2026-04-14T11:02:33` to `2026-04-14T11:03:20` (-0400).

The documented VPN session began:
`2026-04-15T09:45:22` (-0400).

The first documented RDP activity began:
`2026-04-15T10:30:12.445` (-0400).

The last observed DNS exfiltration activity in the analyzed capture occurred:
`2026-04-15T18:39:46.952494` (-0400).

### Tools

- `tshark`
- Wireshark packet-analysis filters
- Bash
- `awk`
- `whois`
- `shellcheck`

### Evidence not used

This report does not claim endpoint process telemetry, EDR telemetry, domain-controller logs, VPN server logs, mail-gateway logs, SIEM alerts or user interviews unless explicitly identified as additional evidence required for confirmation.

## Methodology

The investigation used:

1. Baseline comparison against the available Task 0 observations.
2. Known-IOC searches for campaign domains and IP addresses.
3. DNS query and response analysis.
4. TLS metadata and SNI analysis.
5. TCP connection and reset analysis.
6. Timing and interval analysis.
7. Behavioral analysis of repeated communications.
8. Cross-PCAP chronological correlation.
9. Separation of directly observed packet evidence from analytical inference.

Encrypted application payloads were not treated as plaintext evidence.

## Findings by Attack Phase

### Phase 1 — Initial Access

**ATT&CK:** T1566.002 — Phishing: Spearphishing Link

**Evidence source:** 4x00 phishing investigation context.

The original email delivery is not directly established by the analyzed PCAPs. The 4x00 investigation provides the phishing context and identifies `meddefense-portal.com` and `91.234.99.107` as campaign infrastructure.

**Confidence:** Context-supported; not directly visible in the PCAP evidence.

**Packet evidence proves:** Nothing about the original email delivery itself.

### Phase 2 — Phishing Click / Credential Harvesting

**ATT&CK:** T1056.003 — Web Portal Capture

**PCAP:** `phishing_click.pcap`

**Time:** `2026-04-14T11:02:33` to `2026-04-14T11:03:20` (-0400)

**Source:** `10.10.2.15`

**Destination:** `91.234.99.107`

Observed evidence included:

- DNS query for `meddefense-portal.com`.
- DNS response resolving the domain to `91.234.99.107`.
- TLS SNI identifying `meddefense-portal.com`.
- Client-to-server traffic of approximately 2,000 bytes across 13 TCP segments.
- Largest observed outbound TLS packet: 541 bytes.

**Confidence:** Strong inference.

**Packet evidence proves:** Network contact with the phishing infrastructure and encrypted data exchange.

**Packet evidence does not prove:** The exact password or form contents submitted.

### Phase 3 — C2 Beaconing

**ATT&CK:** T1071.001 — Web Protocols

**PCAP:** `c2_beaconing.pcap`

The investigation established repeated outbound communication with a regular beaconing pattern.

**Confidence:** Confirmed for the observed network communication pattern; endpoint process origin remains unconfirmed.

**Packet evidence proves:** Repeated network communication and its timing pattern.

**Packet evidence does not prove:** Which endpoint process generated the traffic or the attacker's intent.

### Phase 4 — VPN Pivot

**ATT&CK:** T1133 — External Remote Services

**PCAP:** `full_timeline.pcap`

**Time:** `2026-04-15T09:45:22` (-0400)

**Source:** `154.118.42.89:49872`

**Destination:** `10.10.0.1:443`

Observed metadata included:

- `AUTH:user=dmarsh,pass=***`
- `AUTH:OK`
- TCP/443 VPN-style session.
- Session duration: approximately 48.42 minutes.
- WHOIS context: country `NG`, ASN `AS37340`.
- No assigned internal client IP was directly visible.

**Confidence:** Strong inference for the pivot relationship.

**Packet evidence proves:** An external TCP/443 session to the VPN endpoint and visible authentication metadata.

**Packet evidence does not prove:** The plaintext password, attacker identity, MFA state or physical location.

### Phase 5 — RDP Lateral Movement

**ATT&CK:** T1021.001 — Remote Services: Remote Desktop Protocol

**PCAP:** `lateral_movement.pcap`

**Time:** `2026-04-15T10:30:12.445` (-0400)

**Source:** `10.10.2.15`

**Destination:** `10.10.1.10:3389`

The RDP connection was initiated from the clinical workstation toward `billing-srv-01`.

The VPN session began approximately 44.83 minutes before this RDP activity.

**Confidence:** Confirmed for the observed RDP network connection.

**Packet evidence proves:** RDP transport between the two observed hosts.

**Packet evidence does not prove:** Exact authenticated account or interactive actions.

### Phase 6 — Internal SMB Activity / Discovery

**ATT&CK:** T1021.002 — SMB/Windows Admin Shares  
**ATT&CK:** T1135 — Network Share Discovery (inference)

**PCAP:** `lateral_movement.pcap`

`billing-srv-01` initiated TCP/445 connections to:

- `10.10.1.20`
- `10.10.1.30`
- `10.10.1.31`
- `10.10.4.100`
- `10.10.4.101`
- `10.10.1.60`

Four destinations returned SYN-ACK responses. Two attempts received TCP resets/refusals.

**Confidence:** Strong inference for discovery/lateral-movement behavior.

**Packet evidence proves:** TCP/445 targeting and observed connection outcomes.

**Packet evidence does not prove:** SMB authentication success, account names, share names, directory listings or files because SMB application fields were not decoded.

### Phase 7 — DNS Exfiltration

**ATT&CK:** T1048.003 — Exfiltration Over Unencrypted Non-C2 Protocol

**PCAP:** `dns_exfil.pcap`

**Source:** `billing-srv-01` (`10.10.1.10`)

**Destination domain:** `data-sync.meddefense-portal.com`

Observed evidence included:

- 120 anomalous TXT queries.
- Long Base32-like encoded labels.
- Structured data fragments recovered from sample labels.
- TXT response metadata containing command/control-style content.
- Estimated raw tunnel payload of approximately 3,914 bytes.

**Confidence:** Confirmed for the observed DNS tunneling behavior; complete successful receipt/use of the data remains unconfirmed.

**Packet evidence proves:** Repeated encoded TXT DNS traffic consistent with a tunnel.

## Network-Level IOC Table

| Type | Value | Source | Confidence | Detection Utility |
|---|---|---|---|---|
| Domain | `meddefense-portal.com` | 4x00 / phishing_click | Confirmed network contact | High |
| IP | `91.234.99.107` | 4x00 / phishing_click | Confirmed network contact | High |
| Domain | `data-sync.meddefense-portal.com` | dns_exfil | Confirmed observed DNS destination | High |
| IP | `154.118.42.89` | full_timeline | Confirmed external VPN source | High |
| IP | `10.10.0.1` | full_timeline | Confirmed VPN endpoint | High |
| Host | `10.10.2.15` | phishing_click / lateral_movement | Confirmed involved endpoint | High |
| Host | `10.10.1.10` | lateral_movement / dns_exfil | Confirmed involved server | High |
| Destination | `10.10.1.20` | lateral_movement | Confirmed TCP/445 target | Medium |
| Destination | `10.10.1.30` | lateral_movement | Confirmed TCP/445 target | Medium |
| Destination | `10.10.1.31` | lateral_movement | Confirmed TCP/445 target | Medium |
| Destination | `10.10.4.100` | lateral_movement | Confirmed TCP/445 target | Medium |
| Destination | `10.10.4.101` | lateral_movement | Confirmed TCP/445 target | Medium |
| Destination | `10.10.1.60` | lateral_movement | Confirmed TCP/445 target | Medium |

## Impact Assessment

### Systems involved

- `WS-NURSE-04` — `10.10.2.15`
- VPN endpoint — `10.10.0.1`
- `billing-srv-01` — `10.10.1.10`
- Multiple internal TCP/445 destinations
- DNS infrastructure involved in the observed tunnel

### Data impact

The DNS capture contained structured encoded data fragments and an estimated raw tunnel payload of approximately 3,914 bytes.

The exact plaintext contents and business records represented by that payload are not established by PCAP alone.

### Protected or not reached

Two observed TCP/445 attempts were reset/refused. Packet evidence therefore shows that those connection attempts were not completed at the TCP level.

This does not establish why they were refused or whether other access methods were attempted.

### Credential exposure

The phishing PCAP strongly supports an HTTPS submission pattern but does not expose the exact password.

The VPN PCAP exposes simulated/readable authentication metadata identifying `dmarsh` and `AUTH:OK`, but does not expose the plaintext password.

### Regulatory/business concerns

If the encoded DNS payload represents healthcare or other regulated records, the incident requires validation against the organization's data-classification, privacy and breach-assessment procedures. The PCAP alone does not establish the exact records contained in the payload.

## Detection Gap Analysis

### Packet evidence revealed

- Phishing infrastructure contact.
- Repeated beaconing behavior.
- External VPN activity.
- Cross-role RDP.
- Repeated TCP/445 targeting.
- Encoded DNS TXT tunneling.

### Earlier detection opportunities

- TLS SNI matching known phishing infrastructure.
- Periodic outbound connection analysis.
- VPN country/ASN anomaly detection.
- Clinical-to-server RDP monitoring.
- Repeated internal TCP/445 targeting.
- Long encoded DNS labels.
- High-frequency TXT queries to a single domain.

### Behavioral gaps

Simple IOC matching would not necessarily identify periodic beaconing, abnormal RDP relationships or repeated SMB targeting when infrastructure changes.

### DNS tunneling gap

Long encoded labels and repeated TXT queries provide behavioral indicators suitable for DNS analytics.

### VPN anomaly gap

VPN source country and ASN require GeoIP/WHOIS enrichment combined with expected access history.

### Lateral movement gap

RDP and SMB activity should be evaluated against asset role, account role and established communication baselines.

## Detection Rules Recommended

| Rule | Data Source | Phase | False Positives |
|---|---|---|---|
| C2 Beaconing | Zeek, NetFlow, proxy, PCAP-derived sessions | C2 | Updates, monitoring, backups |
| DNS Query Length Anomaly | DNS logs, Zeek, PCAP | DNS exfiltration | CDNs, cloud services |
| VPN Geo-Anomaly | VPN logs + GeoIP/ASN | VPN pivot | Travel, mobile networks, proxies |
| Cross-Role RDP | RDP metadata + identity/asset context | Lateral movement | Approved administration |
| DNS TXT Tunnel Pattern | DNS logs / Zeek / PCAP | DNS exfiltration | SPF/DKIM/DMARC, service discovery |
| Campaign Lookalike TLS | TLS SNI + IOC/first-seen table | Phishing click | Legitimate new domains |

### Recommended C2 logic

Alert when the same internal source communicates with the same external destination more than 10 times in 60 minutes and the interval standard deviation is less than 15% of the interval mean.

### Recommended DNS logic

Alert when the left-most DNS label exceeds 40 characters, particularly when TXT queries repeatedly target the same base domain and labels have encoded/high-entropy characteristics.

## Recommendations

### Immediate — next 24 hours

- Isolate involved systems according to incident-response procedures.
- Reset credentials associated with the observed activity.
- Block confirmed malicious infrastructure where operationally appropriate.
- Preserve the original PCAPs and associated evidence.
- Preserve relevant endpoint, VPN, DNS and authentication logs.

### Short-term — next 7 days

- Deploy behavioral beaconing detection.
- Review VPN authentication and access history.
- Improve DNS egress visibility.
- Search for additional hosts communicating with the identified infrastructure.
- Review RDP and SMB activity involving the affected server.

### Medium-term — next 30 days

- Strengthen email authentication and phishing controls.
- Implement DNS anomaly and tunneling detection.
- Implement role-based RDP restrictions.
- Review internal SMB access baselines.
- Conduct a healthcare-data exposure assessment using server and application evidence.

## Evidence Chain

| Capture | Purpose | Time Window | Hash / File Identifier | Evidence Handling |
|---|---|---|---|---|
| `phishing_click.pcap` | Phishing DNS/TLS session | 14 Apr 2026 | Capture file identifier recorded in working environment | Preserve original |
| `c2_beaconing.pcap` | Repeated outbound communication | 14–15 Apr 2026 | Capture file identifier recorded in working environment | Preserve original |
| `dns_exfil.pcap` | DNS tunneling/exfiltration | 15 Apr 2026 | `bb36d359ab826005966ee6bf17e10a7e25c2724c` | Preserve original |
| `lateral_movement.pcap` | RDP/SMB activity | 15 Apr 2026 | `ff8cd05aa6a712d6ec222653f9964d1bc6a86895` | Preserve original |
| `full_timeline.pcap` | VPN/timeline correlation | 15 Apr 2026 | `6340cbdb819aafe15469bfd396baa5f73a0e33f1` | Preserve original |

The file identifiers above are the identifiers available from the investigation workflow. No unavailable cryptographic hash is invented.

## Continuity with 4x00

The network investigation extends the 4x00 findings in four ways:

1. **Credential exposure:** The phishing PCAP provides strong network evidence consistent with a credential-submission session, while the exact password remains unconfirmed from encrypted traffic.
2. **Network timeline:** The investigation documents the progression from phishing contact through VPN activity, RDP, internal TCP/445 activity and DNS tunneling.
3. **Campaign infrastructure:** `meddefense-portal.com` and `91.234.99.107` are linked from the phishing context to observed post-click network activity.
4. **Impact assessment:** The DNS tunnel adds network evidence of structured data transfer from `billing-srv-01`, expanding the investigation beyond initial credential exposure.

## Final Evidence Boundary

The strongest conclusions are those directly supported by packet timestamps, addresses, ports, DNS records, TLS metadata and TCP behavior.

Credential contents, endpoint execution, exact SMB actions, user intent, MFA state, server-side processing and complete data receipt require supporting logs or endpoint evidence.

This report deliberately separates packet facts from inference and does not treat encrypted or undecoded content as known plaintext.
EOF

echo "Generating $REPORT..."
echo "Done."
