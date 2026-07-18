# Task 1 — The NIST CSF Mapping

MedDefense Health Systems — Current Profile against NIST CSF 2.0's six functions.

## Function: Govern (GV)
**Current Level:** Partial
**Evidence:** A Deputy CISO role exists (James Chen), but 1x00 found no documented cybersecurity strategy or formal policy set — Marcus's own threat intelligence sat unsynthesized in a folder rather than feeding a governance process. Risk decisions in 1x00 were made ad hoc during the assessment, not through a standing process.
**Key Gaps:** No formal, board-approved risk management strategy or written security policy.
**Target Level:** Managed — writing and approving a strategy/policy set is documentation work, not a technology purchase, so it fits a 6-month window even with 2 staff.

## Function: Identify (ID)
**Current Level:** Partial
**Evidence:** MedDefense had no asset inventory before 1x00. The 31-asset registry (A-01–A-31) and 16-gap analysis (GAP-001–GAP-016) were built as a one-time project deliverable, not a repeatable process.
**Key Gaps:** No recurring risk-assessment cadence — the inventory and gap list exist but nothing keeps them current.
**Target Level:** Managed — schedule a recurring review (e.g. quarterly) of the existing registry; low cost since the baseline already exists.

## Function: Protect (PR)
**Current Level:** Partial
**Evidence:** The 1x02 vulnerability scan (31 findings: 4 Critical, 7 High, 11 Medium, 5 Low) found safeguards exist (AV, firewall) but are poorly configured — 14 of 31 findings were misconfigurations. GAP-011 (flat network, no segmentation) and GAP-012 (no MFA) are foundational and confirmed by the scan.
**Key Gaps:** No MFA and no network segmentation — the two findings that amplify nearly every other Critical/High finding.
**Target Level:** Managed — MFA (existing O365 licenses) and Phase-1 segmentation are both funded in the $120,000 budget per the 1x02 remediation roadmap.

## Function: Detect (DE)
**Current Level:** Not Implemented
**Evidence:** Marcus's notes and GAP-014 confirm no SIEM, no centralized logging, no automated alerting. The billing server cryptominer ran undetected for 2+ weeks and was only found through a performance complaint, not monitoring.
**Key Gaps:** Zero visibility into the environment — no mechanism exists to detect an active compromise.
**Target Level:** Partial — a full 24/7 SOC/SIEM is not realistic in 6 months at this budget and staffing; centralized logging on the highest-criticality assets (ehr-srv-01, billing-srv-01, ad-dc-01) is achievable and is the minimum needed to stop repeat incidents like the cryptominer.

## Function: Respond (RS)
**Current Level:** Not Implemented
**Evidence:** The January ransomware incident and the cryptominer were both handled reactively with no evidence of a documented or tested incident response plan in 1x00's findings.
**Key Gaps:** No written, tested incident response plan.
**Target Level:** Managed — drafting and tabletop-testing an IR plan is documentation and staff-time, not capital spend, so it is achievable without competing for the $120,000 technical budget.

## Function: Recover (RC)
**Current Level:** Not Implemented
**Evidence:** GAP-010 confirms the backup is co-located with production — a single point of failure that would fail during exactly the ransomware scenario MedDefense already experienced.
**Key Gaps:** Backup isolation — the recovery mechanism itself is currently a liability, not a safety net.
**Target Level:** Managed — Marcus's own estimate (~$14,400/year) for offline/isolated backup is a small, well-defined line item against the $120,000 budget and directly closes GAP-010.
