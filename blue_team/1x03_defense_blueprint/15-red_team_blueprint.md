# Task 15 — Red Team Your Blueprint

MedDefense Health Systems — attacking the Task 8 funded strategy as a BlackReef affiliate.

## Part 1 — The Attacker's Perspective

### 1. Which kill chain is still viable?

Kill Chain 1 (VPN Exploit -> Full Ransomware Deployment) is still viable — through the Management Zone, not the old flat network.

The segmentation design (Task 14) had to give the Management Zone broad access to every other zone so IT can administer servers, workstations, and medical devices. That makes it the new single highest-value target: compromise one admin account or admin workstation (phishing, or MFA push-bombing to fatigue an admin into approving a fraudulent prompt) and the attacker inherits the same reach the flat network used to give for free. The technical controls got stronger; the concentration of privilege just moved instead of disappearing.

### 2. Alternative attack path (exploiting the deferred controls)

Deferred/unfunded gaps: SIEM (RISK-005, no detection), vendor/third-party risk (CIS Control 15, never addressed by any of the 8 selected controls).

1. Reconnaissance: Identify a third-party vendor with legitimate remote access to Server or Medical Device Zone — e.g., MedTech, which supports EHR/PACS infrastructure per the 1x00 vendor contracts.
2. Initial Access: Compromise the vendor's own credentials (phishing or credential-stuffing at the vendor, not MedDefense) — this access is not blocked by any Task 14 deny rule, because it's an authorized third-party channel, not an internal zone crossing.
3. Dwell, Undetected: With SIEM deferred, this activity goes unnoticed. Dwell time returns to the multi-week pattern already proven twice on billing-srv-01.
4. Lateral Movement: Pivot from the vendor's legitimate access point into the Server Zone systems that vendor relationship touches — reaching ehr-srv-01 or ad-dc-01 through a path that was never a "deny" rule.
5. Objective Execution: Exfiltrate data before encrypting, then deploy ransomware. Backup isolation (RISK-001, funded) protects recovery — it does nothing to stop the data theft itself, so double extortion still works even if MedDefense can restore from backup.

### 3. Insider threat scenario still dangerous

RISK-004 (negligent insider, no DLP, no training) was Accepted, not funded. The 1x01 insider threat scenarios (T3, negligent insider) remain fully live: a nurse or billing clerk under time pressure exports patient data to a personal device, or is socially engineered into approving a fraudulent MFA push. MFA (funded) assumes the human approving the prompt is paying attention — CIS Control 14 (security awareness training) is still Not Implemented, and zero dollars from Task 8 went to changing that. Every funded control is technical; none address human behavior.

## Part 2 — The Honest Assessment

Overall residual risk: High.

Justification: the program made real progress — the pre-program exposure across the top 5 risks was roughly $1.38M/year (Task 9), and the funded controls close a large share of that. But four live weaknesses survive full implementation: no detection capability (SIEM deferred), the insider/human risk ($300,000 ALE, untouched), vendor/third-party risk (never addressed by any of the 8 selected controls), and the Management Zone's now-concentrated privilege. Two of these individually carry six-figure ALE on their own. That combination is not a Medium-risk posture — it's a program that closed its most obvious doors while leaving the windows open.

Single biggest remaining gap: the deferred SIEM (no detection capability). It's a force-multiplier for every other unresolved weakness above — the vendor-pivot path in Part 1.2 and the insider scenario in Part 1.3 both depend on the same thing: nobody is watching. Even where a control can't fully prevent an incident, detection is what turns a multi-week undetected compromise (the pattern that already happened twice) into a same-day catch.

#1 priority for next year's budget: fund the deferred SIEM (Wazuh). It was already costed and ready in Task 7/8, deferred only for labor bandwidth — the fastest, most concrete next step available. A security awareness training program (closing CIS Control 14 and RISK-004) should be the close second priority, since it's the only gap identified here that a technical control alone cannot fix.
