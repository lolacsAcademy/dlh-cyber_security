# Task 13 — The Quick Wins

MedDefense Health Systems — 5 no-cost improvements deployable within 2 weeks using existing resources.

## Quick Win #1

Quick Win #1: Disable dormant and former-employee accounts
Risk Addressed: RISK-002
Action: Pull the AD account list, cross-reference against current HR/staff roster, disable any account tied to a departed employee or inactive 45+ days.
Owner: IT Director (Sarah Park)
Timeline: 3-5 days
Cost: $0 — existing AD tooling, no new purchase
Risk Reduction: Disrupts Kill Chain 1 (VPN Exploit -> Ransomware) at the initial-access step — this is the exact pattern from the Breach 2/Health Network Beta case study, where a former employee's access stayed live for 47 days.
Verification: Export the disabled-account list, compare headcount against current HR roster, confirm zero mismatches.

## Quick Win #2

Quick Win #2: Enable MFA on VPN and administrative accounts
Risk Addressed: RISK-002
Action: Turn on MFA enforcement in the existing O365 E3 tenant for VPN and all admin accounts; walk affected users through enrollment.
Owner: Deputy CISO (James Chen)
Timeline: 5-7 days
Cost: $0 — licenses already owned, only staff time
Risk Reduction: Breaks Kill Chain 1 at Step 1 — credential theft alone is no longer sufficient for VPN access.
Verification: Pull the O365 MFA enrollment report, confirm 100% of admin and VPN accounts show enrolled.

## Quick Win #3

Quick Win #3: Replace default credentials on infusion pumps
Risk Addressed: RISK-006
Action: Physically walk to each of the 7 BD Alaris units, log in with the known default admin credential, set a unique strong password per device, record in the asset registry.
Owner: Deputy CISO (James Chen), with Clinical Engineering
Timeline: 2-3 days
Cost: $0 — no new hardware, staff time only
Risk Reduction: Closes the opportunistic access path used in the Breach 3/Community Hospital Gamma correlation — default credentials plus flat network access was the entire attack chain.
Verification: Checklist of all 7 units with confirmed unique credential, signed off by Clinical Engineering.

## Quick Win #4

Quick Win #4: Extend the existing backup job to ad-dc-02 and pacs-srv-01
Risk Addressed: RISK-007, RISK-008
Action: Add both servers as new targets in the existing backup software configuration on backup-srv-01 — no new hardware, just widening the job's scope.
Owner: IT Director (Sarah Park)
Timeline: 3-5 days, including one test restore
Cost: $0 — existing backup infrastructure and licensing already covers this
Risk Reduction: Removes the single point of failure that would leave domain authentication and imaging data unrecoverable after any ransomware event, closing a gap common to every kill chain that ends in encryption.
Verification: Confirm both servers appear in the next scheduled backup job log, and complete one test restore for each.

## Quick Win #5

Quick Win #5: Replace the shared PACS login with individual accounts
Risk Addressed: RISK-009
Action: Create individual AD accounts for each radiology staff member with PACS access, migrate access rights, disable the shared account.
Owner: Deputy CISO (James Chen), Radiology Dept Head consulted
Timeline: 5-7 days
Cost: $0 — existing AD infrastructure, staff time only
Risk Reduction: Not a kill-chain disruption — this closes an insider-accountability gap. Any future misuse or unauthorized access to imaging data can now be traced to a specific person instead of disappearing into a shared login.
Verification: Confirm the shared account is disabled and PACS access logs show individual usernames, not the generic account.

---

## Why Quick Wins Matter

Quick wins matter beyond their immediate risk reduction because they build the credibility a new security program needs before it can ask for anything bigger. A Board that approved $120,000 last week wants to see movement before the first big purchase lands — five documented, verified fixes in the first two weeks prove the program executes, not just plans. They also demonstrate to staff (the IT Director, department heads, clinical engineering) that security improvements don't have to mean disruption or expense, which builds the cooperation the 6-month roadmap will need later. Finally, closing the cheapest, fastest gaps first (dormant accounts, default credentials, shared logins) removes the "low-hanging fruit" an opportunistic attacker would find first, buying real time while the funded, larger controls from Task 8 are still being implemented.
