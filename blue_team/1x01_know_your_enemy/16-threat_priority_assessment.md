# Threat Priority Assessment — MedDefense

## Rank 1 — Ransomware via VPN exploit → full deployment
Actor: Organized crime/RaaS (T6)
Primary Vector: VPN Exploit
Primary Target: EHR → Backup → whole server tier
Likelihood: Critical — 25% of sector ransomware is healthcare, 3 regional hospitals hit in 8mo (T0)
Impact: Critical — clinical, financial, regulatory, reputational (T2/T10)
Overall Priority: CRITICAL — top priority
Key Gap: GAP-010 — even with entry, isolated backups break BlackReef's core extortion leverage entirely
Recommended Action: Isolate backups to offline/immutable storage — Short-term

## Rank 2 — Supply chain compromise via vendor (MedTech) → whole server tier
Actor: Ransomware via vendor compromise (T5/T6)
Primary Vector: Vendor access pathway
Primary Target: Whole server tier
Likelihood: High — proven vendor-risk pattern, requires compromising an intermediary first
Impact: Critical — same blast radius as direct ransomware
Overall Priority: HIGH-CRITICAL
Key Gap: No formal Gap ID — closest is the GAP-005 flat-network pattern applied to vendor access
Recommended Action: PAM/jump host + MFA on all vendor remote sessions — Short-term

## Rank 3 — Insider exploitation of shared/weak accountability access
Actor: Insider (Negligent/Malicious, T6)
Primary Vector: Legitimate access abuse
Primary Target: PACS, EHR
Likelihood: High — T3 showed 3/5 negligent + 2/5 malicious scenarios, ongoing daily risk
Impact: High — confidentiality breach, HIPAA notification
Overall Priority: HIGH
Key Gap: GAP-008 — PACS is the most-reachable critical asset in the whole environment (T9, 7/7 vectors)
Recommended Action: Enforce individual PACS logins with badge-tap fast switching — Quick Win
## Rank 4 — Opportunistic exploitation of billing-srv-01
Actor: Unskilled/Opportunistic (T6)
Primary Vector: Vulnerable Software Exploit
Primary Target: billing-srv-01
Likelihood: High — already realized twice
Impact: Medium-High — financial/operational, flat network raises escalation risk
Overall Priority: HIGH (upgraded per T15)
Key Gap: GAP-003
Recommended Action: Patch Apache immediately — Quick Win; replace EOL Ubuntu 18.04 — Short-term

## Rank 5 — Social engineering / BEC via low training completion
Actor: Various (Organized crime/BEC primary)
Primary Vector: Phishing/BEC
Primary Target: Financial process, initial network access broadly
Likelihood: Medium-High — T4 showed 7 viable vectors, T13 showed a real chain starting here
Impact: Medium-High — ranges from a single BEC loss to enabling a full ransomware chain
Overall Priority: HIGH (upgraded per T15)
Key Gap: GAP-007
Recommended Action: Expand phishing simulation + close training completion gap (esp. Westside) — Short-term

## Strategic Recommendation
If MedDefense could only fund two initiatives this quarter, they should be backup isolation/immutability (closes GAP-010) and network segmentation (closes GAP-005). These two mechanisms appear in every kill chain and scenario built across this project — the flat network is how any single entry point reaches everything, and the exposed backup is why an attacker can force payment once they arrive. Together they stop entry from becoming catastrophic: segmentation contains lateral movement regardless of how an attacker gets in, and isolated backups guarantee recovery even when something gets through.
