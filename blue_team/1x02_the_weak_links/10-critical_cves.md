# Task 10 — The Critical CVEs

Selected using judgment from earlier tasks, not just CVSS: these 5 combine high technical severity with critical asset roles, confirmed exploit activity, and direct ties to named threat actors and kill chains.

## 1. Finding 031 — Ghostcat (ehr-srv-01)

Finding: 031
CVE: CVE-2020-1938
Host: ehr-srv-01 (10.10.2.10)
Asset Role: A-01, core EHR application server
Asset Criticality: EHR System — Confidentiality Critical, Integrity Critical, Availability Critical, Overall Critical (primary clinical record; already caused a real outage per 1x00)

Technical Analysis:
- Vulnerability Description: A flaw in Tomcat's AJP connector lets an attacker read any file on the server, including config files that may hold database credentials.
- CVSS Base Score: 9.8
- Exploit Availability: 5 (Task 4 — weaponized, public PoC, trivial to run)
- CISA KEV Status: Listed (added 2022-03-03) — the scan report itself claimed it wasn't listed; this was corrected in Task 4/9.
- CWE: Not formally assigned by NVD (NVD-CWE-Other)

Contextual Analysis:
- Network Exposure: Internal server subnet (10.10.2.0/24), reachable from anywhere on the flat network — no segmentation exists.
- Kill Chain Position: Fits Kill Chain 1 (VPN Exploit → Full Ransomware Deployment) and Kill Chain 5 (Supply Chain), both of which target EHR directly.
- Threat Actor: Ransomware/RaaS — top-priority actor per the Threat Actor Matrix, and EHR is one of its named preferred targets.
- Related Findings: Combines with Finding 017 (Tomcat info disclosure that first flagged this AJP connector) and Finding 003 (PostgreSQL exposure) — reading config files here could hand an attacker the exact database credentials Finding 003 already leaves reachable.

Adjusted Priority: Critical 
Justification: Weaponized, confirmed KEV, sits directly on the Critical-rated EHR system, and chains straight into the PostgreSQL exposure — this is the clearest, most complete attack path in the whole report.

## 2. Finding 003 — PostgreSQL Exposure (ehr-db-01)

Finding: 003
CVE: N/A (misconfiguration)
Host: ehr-db-01 (10.10.2.11)
Asset Role: A-02, EHR database (PostgreSQL, holds PHI)
Asset Criticality: EHR System — Overall Critical

Technical Analysis:
- Vulnerability Description: PostgreSQL accepts connections from the entire internal network with no firewall restriction.
- CVSS Base Score: N/A — no CVE, scanner rated Critical
- Exploit Availability: N/A — not a CVE-based finding, so not part of Task 4's scope
- CISA KEV Status: N/A
- CWE: N/A (Task 3/7 already classified this as Misconfiguration, not a CWE-backed flaw)

Contextual Analysis:
- Network Exposure: Reachable from all of 10.10.0.0/16 — the entire internal network, no subnet restriction.
- Kill Chain Position: Directly enables the "reach EHR data" step in Kill Chain 1 and Kill Chain 5 — both list EHR as a named target.
- Threat Actor: Ransomware (via credential/network access, its preferred vector per the Threat Actor Matrix) or Insider (Negligent/Malicious), both of which target EHR data.
- Related Findings: Combines with Finding 031 — if Ghostcat exposes DB credentials, this misconfiguration is exactly what lets any already-compromised host use them directly.

Adjusted Priority: Critical
Justification: No CVE needed — this is a direct, standing path to the organization's most critical data, on the network's most critical asset, matching multiple named threat actors' actual preferred vectors.

## 3. Finding 004 — WS-RAD-01 / MRI Workstation (EternalBlue, BlueKeep, MS08-067)

Finding: 004
CVE: CVE-2017-0144, CVE-2019-0708, CVE-2008-4250
Host: WS-RAD-01 (10.10.1.70)
Asset Role: A-14, MRI imaging control workstation
Asset Criticality: Falls under Medical IoT-adjacent patient-safety systems — Integrity Critical, Availability Critical (direct patient-safety impact)

Technical Analysis:
- Vulnerability Description: Windows XP, over a decade past end-of-life, with three separate wormable remote code execution flaws still present and unpatched.
- CVSS Base Score: 8.1 / 9.8 / 10.0 respectively
- Exploit Availability: 5 for all three (Task 4 — all weaponized, Metasploit modules available)
- CISA KEV Status: All three listed (EternalBlue added 2022-02-10, BlueKeep added 2021-11-03, MS08-067 added 2026-05-20)
- CWE: CVE-2019-0708 (BlueKeep) = CWE-416, confirmed in Task 3 — the same weakness class found on Apache in Finding 002, on a completely different vendor/OS.

Contextual Analysis:
- Network Exposure: Same flat subnet (10.10.1.0/24) as all other clinical workstations — no VLAN isolation.
- Kill Chain Position: Wormable exploits like these are exactly the mechanism that would let ransomware spread once inside, matching the "spread to all servers" phase of Kill Chain 1.
- Threat Actor: Ransomware/RaaS — top-priority actor, and this class of self-propagating exploit is its signature tool.
- Related Findings: None of these chain from another scan finding directly, but the flat network (the root cause behind nearly every other finding in this report) is what makes lateral spread from here possible at all.

Adjusted Priority: Critical
Justification: This is the only finding in the report with a direct patient-safety consequence, three separate KEV-listed weaponized exploits on one host, and it sits on a network with zero segmentation to contain it.

## 4. Finding 015 — NAS-01 Backup Exposure

Finding: 015
CVE: CVE-2024-10441 (identified via Task 9 OSINT research, not in the original scan)
Host: NAS-01 (10.10.2.41)
Asset Role: A-10, backup storage for all MedDefense servers
Asset Criticality: Backup & Storage — Overall Critical (co-located with production, no tested DR)

Technical Analysis:
- Vulnerability Description: Synology's system plugin daemon has an output-encoding flaw that lets a remote, unauthenticated attacker run arbitrary code.
- CVSS Base Score: 9.8
- Exploit Availability: Not scored in Task 4 (found later via OSINT); no confirmed public exploit code was located during Task 9 research, only the vendor advisory and technical write-ups.
- CISA KEV Status: Not listed.
- CWE: CWE-116 — Improper Encoding or Escaping of Output

Contextual Analysis:
- Network Exposure: Finding 015 (original scan) already confirms the DSM interface is reachable from the entire internal network.
- Kill Chain Position: Backup is a named target in both Kill Chain 1 and Kill Chain 5, and "immutable backup" is explicitly listed as the break point for stopping full ransomware deployment.
- Threat Actor: Ransomware/RaaS — destroying backups to prevent recovery is a standard step in ransomware operations targeting this exact asset category.
- Related Findings: Combines directly with the original Finding 015 (open DSM interface) — the network exposure is what would let an attacker reach this flaw in the first place.

Adjusted Priority: Critical
Justification: Even without a KEV listing or confirmed public exploit, this sits on the one asset meant to be the org's recovery path if ransomware succeeds elsewhere — losing it turns a recoverable incident into an unrecoverable one.

## 5. Finding 009 — SSH Password Authentication (billing-srv-01)

Finding: 009
CVE: N/A (misconfiguration)
Host: billing-srv-01 (10.10.2.15)
Asset Role: A-04, billing/claims server
Asset Criticality: Billing Infrastructure — Overall High (not Critical; disrupts revenue, not direct patient care)

Technical Analysis:
- Vulnerability Description: SSH allows password-based login with no account lockout policy, permitting brute-force attacks.
- CVSS Base Score: N/A — scanner rated High
- Exploit Availability: N/A — not a CVE-based finding
- CISA KEV Status: N/A
- CWE: N/A (Misconfiguration per Task 3/7)

Contextual Analysis:
- Network Exposure: Reachable from the internal server subnet.
- Kill Chain Position: This is the exact host named in Kill Chain 3 ("Vulnerable Software → billing-srv-01 Compromise"), mapped to GAP-003, actor Unskilled/Opportunistic.
- Threat Actor: Unskilled/Opportunistic — the Threat Actor Matrix names billing-srv-01 as this actor's primary target specifically because it has "already hit twice."
- Related Findings: Combines with Findings 001, 002, 006, 011, 026 — all on the same host, several of which (001+002) already chain into full root compromise; brute-forcible SSH is one more independent way in on an already repeatedly-compromised system.

Adjusted Priority: High (raised from the report's own severity, not to Critical — asset criticality caps it below the EHR/backup-tier findings above)
Justification: Not the most severe technically, but it's the only finding in the report tied to a specific named kill chain by ID, on a host with a documented history of two real prior compromises — pattern matters as much as CVSS here.
