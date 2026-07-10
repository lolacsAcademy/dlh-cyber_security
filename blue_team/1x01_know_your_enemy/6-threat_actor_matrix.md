# Threat Actor Matrix — MedDefense

Note: Primary Target references the Critical-rated assets from the 1x00 Gap Analysis — no separate "Top 5 asset" file was provided.

## 1. Ransomware Groups (Organized Crime)
Likelihood: Critical — healthcare = 25% of sector ransomware (T0); 3 regional hospitals hit in 8mo; matches BlackReef's Tier 1 profile exactly (T2)
Capability: Medium-High — RaaS affiliates, purchased access + custom tooling mix (T1)
Primary Motivation: Financial gain
Preferred Vector: Credential/network access via GAP-005 or vendor compromise (MedTech, T5), often paired with phishing/BEC (T4)
Primary Target: Backup & Storage (NAS-01/backup-srv-01) first — neutralize recovery — then EHR/PACS
MedDefense Exposure: GAP-005 → GAP-010 → GAP-004 → GAP-002 (T2 attack sequence)

## 2. Nation-State APT
Likelihood: Low — no research programs, MedDefense is a regional hospital without R&D (T0)
Capability: Very High — custom malware, zero-days, long dwell (T1)
Primary Motivation: Espionage
Preferred Vector: Zero-day on public-facing apps, or vendor supply chain (M365 identity federation, T5) — low overall likelihood
Primary Target: Would be research/IP data if it existed; no strong current target given MedDefense's profile
MedDefense Exposure: No dedicated gap maps to this actor specifically — would rely on same Critical gaps if ever targeted
## 3. Insider (Malicious)
Likelihood: Medium — T3 showed 2 of 5 scenarios were malicious (ghost account, curious employee)
Capability: Low-Medium — has existing legitimate access, minimal external tooling needed
Primary Motivation: Revenge / financial gain / curiosity
Preferred Vector: Misuse of legitimate access — shared login, retained VPN access, out-of-scope EHR access (T3)
Primary Target: PACS (shared login) or EHR (curiosity-driven access)
MedDefense Exposure: GAP-008 directly; T3 also flagged undocumented gaps for ghost-account offboarding and EHR access-scope monitoring

## 4. Insider (Negligent)
Likelihood: High — T3 showed 3 of 5 scenarios were negligent (shared login, personal NAS, plaintext creds)
Capability: Low — unintentional, no attacker skill involved
Primary Motivation: None — accidental/convenience-driven
Preferred Vector: Shadow IT (personal NAS/devices), shared accounts, plaintext credential sharing (T3)
Primary Target: Whatever asset the behavior touches — Cardiology data (NAS), PACS (shared login), AD admin creds (Scenario 5)
MedDefense Exposure: GAP-008, GAP-009 (Pi)/A-32 (NAS, no gap ID), GAP-007 (training gap ties to negligence broadly)

## 5. Hacktivist
Likelihood: Low — no political profile at MedDefense (T0); DDoS on patient portal remains plausible (T4)
Capability: Low-Medium — mostly DDoS, defacement (T1)
Primary Motivation: Political/philosophical belief
Preferred Vector: DDoS or defacement via public-facing web app vuln
Primary Target: web-srv-01 (public website + patient portal, DMZ)
MedDefense Exposure: No dedicated Gap ID for DMZ web server hardening in the provided Gap Analysis — undocumented gap
## 6. Unskilled / Opportunistic Attacker
Likelihood: High — already realized (billing-srv-01 crypto-miner, T0)
Capability: Low — automated scanners, public exploits (T1)
Primary Motivation: Financial gain (opportunistic, not targeted)
Preferred Vector: Automated scanning for known CVEs on unpatched/EOL public-facing systems
Primary Target: billing-srv-01 (already hit twice) or any other unpatched public-facing asset (e.g. print-srv-01, EOL)
MedDefense Exposure: GAP-003 — billing-srv-01 controls already failed twice

## Top 3 Priority Ranking
1. Ransomware Groups (Organized Crime) — highest likelihood (Critical, backed by sector stats and 3 regional hits) AND highest impact (targets backup, EHR, and AD in sequence; total operational and patient-safety consequences). Clear #1 by both dimensions.

2. Insider (Negligent) — high, ongoing likelihood (already observed in 3 of 5 T3 scenarios) and impact that compounds every other threat: negligent behavior (shared logins, shadow IT, plaintext creds) is exactly what widens the door for ransomware and malicious insiders alike.

3. Unskilled/Opportunistic Attacker — high, proven likelihood (already realized twice on billing-srv-01) with lower per-incident impact than ransomware, but it's the leading indicator: automated scanners finding MedDefense's exposed footprint today is what a targeted ransomware affiliate would find tomorrow.
