# Task 0 — The Scan Report

## 1. Scan Metadata
- **Target:** 10.10.0.0/16 (all internal subnets)
- **Scanner:** OpenVAS 22.x (Greenbone Community Edition)
- **Policy:** Full and Deep, authenticated where credentials were available
- **Requested by:** James Chen, Deputy CISO
- **Executed by:** SecurePoint Consulting (third-party)
- **Hosts scanned:** 47 responsive hosts
- **Not scanned:** Cloud services (O365), mobile devices (iPads), and any asset offline during the scan window. Medical devices were scanned **unauthenticated only** (no credentials provided).

## 2. Finding Distribution
| Severity | Count |
|---|---|
| Critical | 4 |
| High | 7 |
| Medium | 11 |
| Low | 5 |
| Informational | 4 |
| **Total** | **31** |

**Medium** has the most findings (11), not Critical. The instinct to jump to the 4 Critical findings would mean ignoring nearly two-thirds of the dataset.

## 3. Asset Heat Map — Top 5 Hosts by Finding Count
| Rank | Host | Findings | Asset ID | Role (per 1x00 Registry) |
|---|---|---|---|---|
| 1 | billing-srv-01 | 6 (001,002,006,009,011,026) | A-04 | Billing/claims server, Ubuntu 18.04 (EOL). Registry notes it was already compromised twice (ransomware, cryptominer). |
| 2 | web-srv-01 | 4 (005,012,013,021) | A-11 | Public website + patient portal, DMZ |
| 2 | ehr-srv-01 | 4 (017,022,030,031) | A-01 | Core clinical system, EHR application |
| 4 | ad-dc-01 | 3 (007,018,025) | A-05 | Primary domain controller |
| 5 | ehr-db-01 | 1 (003 — Critical) | A-02 | EHR database (PostgreSQL). Registry already flags its port 5432 as open network-wide (Task 4 gap). |
## 4. First Observations
- Critical findings are **not spread evenly** — 2 of the 4 Criticals (001, 002) sit on the same host, billing-srv-01 (A-04), and the report explicitly states they chain together (remote code execution as www-data, then privilege escalation to root).
- Findings 017 and 031 are also related and on the same host (ehr-srv-01, A-01): 017 flagged a Tomcat info-disclosure issue and could not confirm if the AJP connector was active; 031 is SecurePoint's manual follow-up confirming it is active and exploitable (Ghostcat, CVSS 9.8).
- billing-srv-01 (A-04) has the highest finding count of any host, which lines up with the asset registry noting it has already been compromised twice before this scan — a repeat-victim asset.
- Two devices are not in the asset registry at all: 10.10.2.99 and 10.10.10.200 (Findings 028, 029) — shadow IT.
- Finding 020 is explicitly flagged by SecurePoint itself as a likely false positive, pending manual verification.
- Corporate HQ workstations/laptops (A-30, A-31) do not appear in any finding — either genuinely clean or under-covered (laptops were noted as only "intermittently present" during the scan).

## 5. Scan Limitations
- Does not cover cloud services (O365), mobile devices (iPads), or any asset offline during the scan window.
- Medical devices (A-18 Patient Monitors, A-19 Infusion Pumps, A-20, A-21) were scanned **unauthenticated only**, so findings on them are likely incomplete compared to the authenticated Linux/Windows hosts.
- No active exploitation was attempted — all findings come from version detection and configuration checks, except Finding 031, which was manually verified.
- OpenVAS has a stated 5–10% false-positive rate in this configuration; manual verification is recommended before committing remediation resources to any single finding.
- Physical infrastructure assets (A-22 Badge Readers, A-23 Server Room, A-24 Network Closet) are outside the scope of a network vulnerability scan entirely.
