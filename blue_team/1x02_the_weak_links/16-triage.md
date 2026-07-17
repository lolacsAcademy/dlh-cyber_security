# Task 16 — The Noise Filter

## Full Triage (All 31 Findings)

Finding 001 | CVSS 9.8 | billing-srv-01 | Category: AC | Reason: Weaponizable RCE that chains directly into Finding 002 for full root compromise.
Finding 002 | CVSS 7.8 | billing-srv-01 | Category: AC | Reason: Completes the root-compromise chain with Finding 001 on an already twice-compromised host.
Finding 003 | Critical (scanner) | ehr-db-01 | Category: AC | Reason: Direct, unauthenticated-at-network-layer path to PHI on the Critical-rated EHR database.
Finding 004 | Critical (multi-CVE) | WS-RAD-01 | Category: AC | Reason: Three KEV-listed weaponized exploits on a patient-safety device with no segmentation containing it.
Finding 005 | CVSS 7.5 | web-srv-01 | Category: AS | Reason: Real weak-TLS exposure on the internet-facing portal, fixable via config change within a planned window.
Finding 006 | High (scanner) | billing-srv-01 | Category: AS | Reason: Real network-wide database exposure requiring a bind-address config fix.
Finding 007 | High (scanner) | ad-dc-01 | Category: AC | Reason: Enables LDAP relay attacks on the Critical-rated Identity/AD asset, reachable from the entire flat network.
Finding 008 | High (scanner) | print-srv-01 | Category: AS | Reason: Real EOL-driven RCE risk, but on a Low-criticality print service.
Finding 009 | High (scanner) | billing-srv-01 | Category: AS | Reason: Real brute-force exposure on a repeat-compromised host, needs config change not emergency response.
Finding 010 | High (scanner) | Medical IoT (BD Alaris) | Category: AC | Reason: Trivial default-credential access on patient-safety devices with vendor mitigation never implemented.

Finding 011 | High (scanner) | billing-srv-01 | Category: AS | Reason: Real lifecycle gap (no ESM), directly enabling Finding 026's kernel exposure.
Finding 012 | Medium (scanner) | web-srv-01 | Category: AS | Reason: Real missing headers on internet-facing portal, straightforward config fix.
Finding 013 | Medium (scanner) | web-srv-01 | Category: AS | Reason: Real, time-bound issue — certificate expires in 23 days.
Finding 014 | Medium (scanner) | Westside router | Category: AS | Reason: Real architectural weakness on the site-to-site VPN device, needs hardware/config remediation.
Finding 015 | Medium (scanner) | NAS-01 | Category: AC | Reason: Network exposure combined with a real unauthenticated RCE CVE (Task 9) on the Critical-rated backup asset.
Finding 016 | Medium (scanner) | Medical IoT (Philips) | Category: AS | Reason: Real exposure on patient-safety devices, but no confirmed exploit path yet identified.
Finding 017 | Medium (scanner) | ehr-srv-01 | Category: AC | Reason: This exact finding led directly to discovering Finding 031 on the Critical-rated EHR asset — treat with urgency, not routine filing.
Finding 018 | Medium (scanner) | ad-dc-01/02 | Category: AS | Reason: Real weak-crypto exposure enabling Kerberoasting, needs config change.
Finding 019 | Medium (scanner) | Multiple hosts | Category: AS | Reason: Real unnecessary service exposure across 5 hosts, needs review and restriction.

Finding 020 | CVSS 9.8 (flagged) | backup-srv-01 | Category: FP | Reason: SecurePoint explicitly flagged this as a likely false positive — exploit precondition unlikely in this environment.
Finding 021 | Medium (scanner) | web-srv-01 | Category: AS | Reason: Real misconfiguration on internet-facing host, simple fix (disable TRACE).
Finding 022 | Low (scanner) | ehr-srv-01 | Category: I | Reason: Minor clock drift with negligible security impact — document and monitor.
Finding 023 | Low (scanner) | ~280 workstations | Category: AS | Reason: Real, fixable via GPO — data exfiltration/malware entry vector across a large endpoint population.
Finding 024 | Low (scanner) | pacs-srv-01 | Category: AS | Reason: Real unencrypted protocol exposure, fixable by enabling TLS on DICOM traffic.
Finding 025 | Low (scanner) | ad-dc-01 | Category: AS | Reason: Real reconnaissance-enabling misconfiguration, simple ACL fix.
Finding 026 | Low (scanner) | billing-srv-01 | Category: AS | Reason: Real accumulated kernel CVE backlog, resolved once Finding 011 (ESM) is remediated.
Finding 027 | Informational | Multiple workstations | Category: FP | Reason: "Defender not primary" is expected by design (Sophos is the real EDR); the 15 inactive-agent detail needs separate follow-up outside this finding.
Finding 028 | Informational | 10.10.2.99 | Category: AS | Reason: Undocumented shadow-IT device with exposed services — needs investigation and formal inventory action.

Finding 029 | Informational (scanner) | 10.10.10.200 | Category: AC | Reason: Reclassified up from the scanner's own label — this is a real, weaponized, trivially exploitable CVE on an undocumented device.
Finding 030 | Informational | ehr-srv-01 | Category: FP | Reason: The report's own description confirms this is an operational issue, not a security vulnerability.
Finding 031 | CVSS 9.8 | ehr-srv-01 | Category: AC | Reason: Weaponized, KEV-listed, direct path to PHI database credentials on the organization's highest-value asset.

## Triage Summary

| Category | Count |
|---|---|
| Actionable Critical (AC) | 10 |
| Actionable Standard (AS) | 17 |
| Informational (I) | 1 |
| False Positive (FP) | 3 |
| **Total** | **31** |

## Actionable Findings List (Priority Order)

**Actionable Critical (24-48h):**
1. Finding 031 — Ghostcat, ehr-srv-01
2. Finding 003 — PostgreSQL exposure, ehr-db-01
3. Finding 004 — Windows XP EOL cluster, WS-RAD-01
4. Finding 001 — Apache RCE, billing-srv-01
5. Finding 002 — Apache privesc, billing-srv-01
6. Finding 015 — NAS-01 exposure + CVE-2024-10441
7. Finding 007 — LDAP relay/SMBv1, ad-dc-01
8. Finding 010 — BD Alaris default credentials
9. Finding 029 — Grafana CVE-2021-43798, shadow IT device
10. Finding 017 — Tomcat disclosure, ehr-srv-01

**Actionable Standard (7-30 days):**
1. Finding 009 — SSH password auth, billing-srv-01
2. Finding 006 — MySQL exposure, billing-srv-01
3. Finding 008 — PrintNightmare/EOL, print-srv-01
4. Finding 011 — ESM not enrolled, billing-srv-01
5. Finding 005 — TLS 1.0, web-srv-01
6. Finding 026 — Kernel CVE backlog, billing-srv-01
7. Finding 018 — Kerberos weak encryption, ad-dc-01/02
8. Finding 016 — Philips monitors exposed
9. Finding 014 — Westside consumer router
10. Finding 028 — Shadow IT device, 10.10.2.99
11. Finding 012 — Missing security headers, web-srv-01
12. Finding 013 — SSL cert expiring, web-srv-01
13. Finding 019 — RDP enabled, multiple hosts
14. Finding 021 — HTTP TRACE, web-srv-01
15. Finding 024 — DICOM unencrypted, pacs-srv-01
16. Finding 025 — DNS zone transfer, ad-dc-01
17. Finding 023 — USB mass storage unrestricted
