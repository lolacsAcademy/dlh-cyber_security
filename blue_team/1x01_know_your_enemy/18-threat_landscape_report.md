# MedDefense Health Systems — Threat Landscape Report
Companion to the Security Posture Assessment (1x00 — The First Watch)

## 1. Executive Summary
Healthcare is the most targeted sector for ransomware (25% of all incidents), and 3 regional hospitals near MedDefense were hit in the past 8 months. MedDefense's flat network, single-point-of-failure backup, and shared PACS login match the exact profile ransomware affiliates are told to prioritize.

**Most dangerous threat:** A ransomware campaign entering via VPN or purchased access, moving laterally across the flat network unopposed, destroying the sole backup copy, and encrypting EHR/PACS/billing simultaneously — the same pattern that hit 3 peer hospitals already.

**Top 3 Recommendations:**
- Isolate backups to offline/immutable storage — breaks the extortion model regardless of entry point.
- Segment the internal network — the single most repeated root cause across every attack path found.
- Tighten vendor and account access controls — a compromised vendor or forgotten account currently has the same reach as a targeted attacker.

## 2. Scope and Methodology
**Sources:** CISA/HC3 healthcare advisories, HHS breach statistics, a peer-hospital ransomware case, the BlackReef RaaS profile, MedDefense's own Asset Registry/Network Scan/Gap Analysis/Vendor Contracts (1x00), and 2 internal attack narratives.
**Frameworks:** STRIDE (EHR deep-dive + PACS/AD/Network survey), MITRE ATT&CK mapping, 5 kill chains with break points, vector-to-asset cross-referencing.
**Connection to 1x00:** Where the Posture Assessment looked inward (asset criticality, missing controls), this report looks outward (who exploits each gap, and how). Every finding traces to a Gap ID where one exists; undocumented gaps are flagged, not invented.

## 3. Healthcare Sector Threat Overview
**Why targeted:** Urgency (downtime = patient risk, 60% pay rate vs 46% avg), data value ($250-1000/record), legacy/flat systems (easier entry than finance/tech), insurance + HIPAA pressure.
**Trends:** Double extortion now standard (73% steal data before encrypting); ransom demands doubled 2022-2024 ($1.2M→$2.5M); avg total cost ~$2.7M+.
**Sector stats:** Healthcare = 25% of all ransomware incidents; top initial access vectors are VPN exploitation (38%), phishing (31%), valid credentials (22%) — MedDefense's FortiGate has documented overly permissive VPN rules.

## 4. MedDefense Threat Actor Profiles

| Actor | Likelihood | Rank | Why |
|---|---|---|---|
| Ransomware/Organized Crime | Critical | #1 | Matches BlackReef's Tier 1 target profile exactly |
| Insider (Negligent) | High | #2 | 3/5 assessed scenarios were negligent, daily risk |
| Unskilled/Opportunistic | High | #3 | Already realized twice on billing-srv-01 |
| Insider (Malicious) | Medium | — | 2/5 scenarios malicious, hard to detect |
| Hacktivist | Low | — | No political profile |
| Nation-State APT | Low | — | No research programs today |

**Top 3:** Ransomware groups run as a business (developers 20-30% cut, affiliates 70-80%, IABs sell hospital VPN access for $3-8k); their playbook neutralizes backups before deploying. Negligent insiders are the most frequent real-world risk (shared logins, shadow IT, plaintext creds). Opportunistic scanners already found and exploited MedDefense once via an unpatched Apache flaw.

## 5. Attack Surface Analysis
**External:** Patient portal, VPN endpoints (including a consumer-grade Westside router on a site-to-site VPN), cloud email — FortiGate VPN rules documented as too permissive.
**Internal:** Full cross-subnet reachability confirmed by scan — zero segmentation. EHR's PostgreSQL (5432) and billing's MySQL (3306) both open network-wide with no extra auth.
**Human:** Clinical staff (58% training completion at Westside), reception (first-contact target), a single IT analyst (fatigue risk), executives (BEC targets), external contractors (access MedDefense can't directly control).
**Key exposures:** Open PostgreSQL port; shared PACS login; unlocked network closet with credentials posted; backup co-located with production.
**Verdict:** Internal surface is the greatest risk — the flat network turns any single entry, through any surface, into full exposure.

## 6. Critical Attack Paths

| Kill Chain | Path | Break Points |
|---|---|---|
| 1. VPN→Ransomware | FortiGate exploit→recon→cred harvest→DC→backup destroyed→GPO ransomware | VPN hardening, segmentation, immutable backup |
| 2. Ghost Account→Insider | Terminated VPN account active 47 days→off-hours access | Automated deprovisioning, login alerting |
| 3. Vuln SW→billing-srv-01 | Apache RCE (exploited twice)→payload→MySQL exposed | Patch/replace EOL software |
| 4. BEC→Wire Fraud | Spoofed CEO email→urgency bypasses approval | DMARC, callback verification |
| 5. Supply Chain→Full Tier | Vendor breached→creds used→flat net reaches everything | PAM/jump host, least-privilege |

**Most connected assets:** PACS, EHR, Active Directory. **Most versatile vectors:** Physical Access, VPN Exploit, Supply Chain Compromise. Chains 1 and 5 converge on the same backup-then-encrypt sequence regardless of entry point — the strongest evidence in this report.

## 7. STRIDE Analysis Summary
**EHR (deep):** 12 threats across all 6 categories. Top finding: PostgreSQL open to the entire /16 with no app-layer auth — an Information Disclosure threat requiring no sophistication, and unlike encryption, disclosed data can't be "restored."
**PACS:** Top threat = Denial of Service (zero corrective control, excluded from backup — permanent loss on outage).
**AD:** Top threat = Elevation of Privilege (weak MFA + flat network = easy path to Domain Admin).
**Network:** Top threat = Elevation of Privilege via zero segmentation — no real "elevation" needed when one foothold already has full reach.

## 8. Threat Scenarios
**1. Ransomware (External):** VPN exploit→Domain Admin→backup destroyed→ransomware deployed. Impact: clinical disruption, $1-3M+, HIPAA notification, reputational damage (peer-hospital CEO resigned after same pattern).
**2. Insider Exfiltration (Internal):** Retained access→gradual record export→USB exfil→continued post-termination access via saved DB creds. Impact: resold data, HIPAA/OCR investigation, trust erosion.
**3. Supply Chain (Third Party):** Vendor (MedTech) breached→creds used→flat network reaches entire server tier. Impact: same category as Scenario 1, arguably worse since it bypasses MedDefense's own perimeter entirely.

## 9. Gap-Threat Correlation
Two gaps upgraded from 1x00's original rating:
- **GAP-003** (billing-srv-01, twice-failed): High→Critical — only gap tied to an already-proven, twice-realized compromise.
- **GAP-007** (training gap, Westside): Medium→High — foundational enabler behind nearly every social-engineering vector; the ATT&CK ransomware chain began with exactly this kind of phishing click.

**The Critical Three:** GAP-005 (credential exposure), GAP-010 (backup SPOF), GAP-002 (PACS no corrective control) — tied with GAP-004 — appear most often across every kill chain and scenario. Together: the entry point, the mechanism every ransomware attack targets first, and the irreversible-loss outcome.

## 10. Prioritized Recommendations

| Rank | Threat | Key Gap | Action |
|---|---|---|---|
| 1 | Ransomware via VPN | GAP-010 | Isolate backups (offline/immutable) — Short-term |
| 2 | Supply chain via vendor | No formal ID | PAM/MFA on vendor sessions — Short-term |
| 3 | Insider (shared access) | GAP-008 | Individual PACS logins — Quick Win |
| 4 | Opportunistic (billing) | GAP-003 | Patch Apache — Quick Win; replace EOL OS — Short-term |
| 5 | Social engineering/BEC | GAP-007 | Expand phishing sims, close training gap — Short-term |

**Strategic 2-initiative pick:** Backup isolation (GAP-010) + network segmentation (GAP-005) — both recur in every kill chain and scenario in this report, and together they stop entry from becoming catastrophic regardless of how an attacker gets in.

**Next phase:** Project 1x02 (Vulnerability Assessment) moves from this threat-informed prioritization into hands-on technical validation of the specific exploitable conditions identified here.
