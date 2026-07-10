# MedDefense — Reality Check

## Breach 1: Regional Hospital Alpha — Ransomware via VPN

### Attack Vector
- Unpatched VPN appliance (known CVE, patch available 4 months, never applied).
- Flat network let attacker reach the domain controller in 3 hours.
- Compromised domain admin account deployed ransomware org-wide via Group Policy.

### MedDefense Correlation
- GAP-010 — backup co-located with production, exact same failure mode that destroyed Alpha's backups too.
- GAP-004 — ad-dc-02 has no backup; Alpha shows exactly how fast a DC gets weaponized once reached.

### Blind Spot Check
- Yes — no Task 12 gap covers flat-network lateral movement itself. New gap added below (GAP-011).
- No IR plan is a real gap too, but it's already documented in Task 5 (G-003); not duplicating it here.

## Breach 2: Health Network Beta — Insider + Credential Abuse

### Attack Vector
- Former employee's VPN/EHR access stayed active 47 days — offboarding was a manual, forgettable manager ticket.
- No MFA; original password still worked.
- Off-hours access from a new IP triggered no alert; logs existed but were never reviewed.

### MedDefense Correlation
- MedDefense's password policy also relies on manual action for shared-account deactivation on departure — same human-dependency pattern.
- MedDefense has no MFA anywhere except James's personal account (Task 0) — same exposure.
- Unreviewed logs already covered by GAP-001's finding (detective controls exist but nobody watches them).

### Blind Spot Check
- Yes — no Task 12 gap covers account lifecycle/offboarding or the absence of MFA. New gap added below (GAP-012).

## Breach 3: Community Hospital Gamma — Medical Device Pivot

### Attack Vector
- Unpatched patient portal (2-month-old patch, never applied) gave initial access.
- DMZ misconfiguration allowed outbound traffic to the internal network.
- Infusion pumps used default admin/admin credentials; no device segmentation; 23-day dwell time.

### MedDefense Correlation
- GAP-001 — infusion pumps fully unprotected already covers the IoT segmentation weakness.
- Medical IoT rated Critical (Task 8) for exactly this reason.

### Blind Spot Check
- Yes, two unverified items: whether web-srv-01's DMZ allows outbound-to-internal traffic, and whether MedDefense's medical devices still use default credentials. Neither has ever been checked. New gap added below (GAP-013).
## New Gaps Identified

### GAP-011 — Flat network enables unrestricted lateral movement
- Asset: Network Core — Critical (Task 8).
- Data at Risk: All data categories — the network itself is the shared path to everything (Task 9).
- Control Status: No segmentation exists anywhere (Task 0/4/7).
- Missing: Preventive control (segmentation) between servers, workstations, and medical devices.
- Risk Level: Critical.
- Justification: Critical asset, no containment control — Breach 1 shows this turns a single compromised device into a domain-wide event in 3 hours.
- Impact: Same playbook as Breach 1 — one compromised system reaches the domain controller and every server behind it.

### GAP-012 — No automated account offboarding, no MFA anywhere
- Asset: Identity/AD, all remote access — Critical (Task 8).
- Data at Risk: Credentials — Restricted (Task 9).
- Control Status: Password policy exists but offboarding depends on manual action; no MFA except James's personal account.
- Missing: Automated account deactivation tied to HR; MFA on remote access.
- Risk Level: High.
- Justification: Confidential/Restricted data, incomplete coverage — matches the High rule; Breach 2 shows this exact gap enabled 47 days of undetected access.
- Impact: A departed employee or contractor could access patient/financial data for weeks without detection.

### GAP-013 — DMZ egress and device credential hygiene never verified
- Asset: web-srv-01 (DMZ) and Medical IoT — Critical (Task 8).
- Data at Risk: Website is Public, but the internal network it may reach is Restricted (Task 9).
- Control Status: Unknown — no artifact confirms whether DMZ can reach internal, or whether device default credentials were ever changed.
- Missing: Verification/testing itself, not just a control.
- Risk Level: High.
- Justification: Unconfirmed risk, not proven — High rather than Critical, pending verification; Breach 3 shows this exact combination caused a 23-day compromise.
- Impact: If either condition is true, a portal compromise could reach infusion pumps the same way it did at Gamma.

## Priority Reassessment
- GAP-001 (infusion pumps) and GAP-010 (backup) — no change, Critical rating strongly validated by Breach 3 and Breach 1 respectively.
- GAP-004 (ad-dc-02 backup) — no change, but Breach 1 reinforces why this stays Critical.
- New GAP-011 enters at Critical, GAP-012 and GAP-013 enter at High — no existing gap is downgraded.

## Pattern Analysis
All three breaches started small — a late patch, a forgotten offboarding ticket, a web app flaw — and became severe only because nothing contained them afterward: flat networks, no monitoring, no tested recovery. None of these hospitals had zero defenses; they had a single point of failure with nothing behind it. MedDefense shows the identical pattern across its own gap analysis, so the limited security budget is better spent on containment and detection — segmentation, centralized alerting, MFA, and a tested backup/IR plan — rather than more perimeter tools alone.
