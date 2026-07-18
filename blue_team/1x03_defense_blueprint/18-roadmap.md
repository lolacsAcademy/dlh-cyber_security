# Task 18 — The 6-Month Security Roadmap

MedDefense Health Systems — month-by-month execution plan, built from the Task 17 strategy.

## Month 1 — Quick Wins

- Actions: Execute all 5 T13 quick wins — disable dormant accounts, begin MFA enrollment, reset infusion pump default credentials, extend the existing backup job to ad-dc-02 and pacs-srv-01, replace the shared PACS login with individual accounts.
- Owner: IT Director (Sarah Park) — dormant accounts, backup extension. Deputy CISO (James Chen) — MFA rollout start, infusion pumps, PACS accounts.
- Dependencies: None — all use existing tools and licenses.
- Completion Criteria: 5/5 quick wins verified per their individual T13 verification steps (disabled-account export, MFA enrollment report, device credential checklist, backup job log, PACS access log).

## Month 2 — Procurement + MFA Completion

- Actions: Complete MFA enrollment to 100% of admin/VPN accounts. Select and contract vendors for backup replication (AWS S3 Glacier) and segmentation networking hardware. Order the Westside Clinic firewall.
- Owner: Deputy CISO (James Chen) — MFA completion and vendor contracts. IT Director (Sarah Park) — hardware procurement.
- Dependencies: MFA completion builds on Month 1's enrollment start.
- Completion Criteria: 100% MFA enrollment confirmed via O365 report; signed contracts/POs for backup replication and segmentation hardware.

## Month 3 — Backup Infrastructure + Segmentation Design

- Actions: Deploy offsite backup replication for EHR, billing, and AD servers. Begin VLAN design and configuration (not yet live). Await Westside firewall hardware delivery.
- Owner: IT Director (Sarah Park) — backup deployment and VLAN configuration. Deputy CISO (James Chen) — oversight.
- Dependencies: Backup deployment requires Month 2's signed vendor contract. VLAN design requires Month 2's hardware procurement.
- Completion Criteria: First successful backup replication cycle to isolated storage confirmed; VLAN architecture finalized and approved.

## Month 4 — Core Controls Go Live

- Actions: Cut over to the 5 segmented VLANs and enforce the 10 firewall rules. Deploy EDR upgrade across all ~330 endpoints. Install the Westside Clinic firewall. Begin medical device isolation.
- Owner: IT Director (Sarah Park) — segmentation cutover and EDR rollout. Deputy CISO (James Chen) — medical device isolation, with Clinical Engineering.
- Dependencies: Medical device isolation cannot start until network segmentation is live — device isolation is a specific case of the same VLAN architecture (Task 11).
- Completion Criteria: All 5 VLANs live with enforced rules, confirmed by firewall rule audit; EDR agent reporting on 100% of endpoints; medical devices confirmed inside the isolated VLAN.

## Month 5 — Validation

- Actions: Test restores from isolated backup for every critical asset (ad-dc-01/02, ehr-db-01, pacs-srv-01, billing-srv-01). Commission an external penetration test against the new segmented architecture.
- Owner: Deputy CISO (James Chen) — pentest coordination. IT Director (Sarah Park) — test restore execution.
- Dependencies: Test restores require Month 3's backup replication to be live. The validation pentest requires Month 4's segmentation to be live — there's no architecture to test before then.
- Completion Criteria: 100% of critical assets have a documented successful test restore; pentest complete with a findings report delivered.

## Month 6 — Review and Year 2 Planning

- Actions: Review and rescore all 10 Risk Register KRIs. Triage and remediate any critical pentest findings. Prepare and submit the Year 2 budget proposal (SIEM, security training, vendor risk management) to the Board.
- Owner: Deputy CISO (James Chen) — KRI review and Board proposal. IT Director (Sarah Park) — pentest finding remediation support.
- Dependencies: The Year 2 budget proposal requires Month 5's pentest findings to be triaged first — the Board needs to know what's still open before funding more.
- Completion Criteria: Risk Register updated with reassessed scores; every pentest finding marked remediated, accepted, or scheduled; Year 2 budget proposal submitted to the Board by end of Month 6.

---

## Dependency Chain

1. Network segmentation (Month 4) must precede medical device isolation (Month 4).
2. Backup replication live (Month 3) must precede test restores (Month 5).
3. Segmentation live (Month 4) must precede the validation pentest (Month 5).
4. Pentest findings triaged (Month 5/6) must precede the Year 2 budget proposal (Month 6).

## Milestones

| Milestone | Date | Accomplished | Success Indicator |
|---|---|---|---|
| M1 — Quick Wins Complete | End Month 1 | All 5 zero-cost fixes deployed | 5/5 verified per T13 checklists |
| M2 — Procurement Complete, MFA Live | End Month 2 | Vendors contracted, MFA fully enrolled | 100% MFA enrollment report; signed POs |
| M3 — Core Architecture Live | End Month 4 | Segmentation, EDR, device isolation, Westside firewall all deployed | Firewall rule audit passes; 100% endpoint EDR coverage |
| M4 — Program Validated, Year 2 Approved | End Month 6 | Restores tested, pentest complete, KRIs reviewed | 100% successful test restores; pentest findings triaged; Year 2 proposal submitted |

## Risks to Timeline

1. Two-person team bandwidth. The security team is James Chen and one analyst — the same constraint that already pushed SIEM to a deferred status (Task 8). If Month 3-4's technical deployment (segmentation cutover, EDR rollout) competes with day-to-day incident response, the timeline slips. Contingency: bring in a short-term contracted network engineer specifically for the segmentation cutover, funded from the $32,500 reserve if not otherwise committed, rather than cutting corners on Month 5 validation.

2. Vendor/hardware procurement delays. Segmentation networking hardware or the backup replication contract could take longer than Month 2's window allows. Contingency: identify a secondary vendor quote during Month 2 procurement as a fallback; if hardware is delayed, prioritize cutting over the lower-risk VLANs first (Guest/IoT, Management) while awaiting hardware for the Server and Medical Device zones, so progress continues rather than stalling entirely.
