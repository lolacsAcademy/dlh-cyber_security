# Task 3 — The Gap-to-Framework Bridge

MedDefense Health Systems — the 8 Critical gaps from 1x00, traced through 1x02 vulnerability evidence and 1x01 threat context to their framework controls.

## GAP-011
Gap Reference: GAP-011 (1x00)
Description: Flat network with zero segmentation allows unrestricted lateral movement.
Vulnerability Evidence: Finding 003 — PostgreSQL (ehr-db-01) reachable from the entire internal network; Finding 031 — Ghostcat (ehr-srv-01) reachable from anywhere on the flat network (1x02).
Threat Context: Ransomware/RaaS, Kill Chain 1 (VPN Exploit → Full Ransomware Deployment).
NIST CSF Function: Protect (PR.IR — Technology Infrastructure Resilience).
CIS Control: Control 12 — Network Infrastructure Management (IG1: 12.1; segmentation itself is IG2: 12.2).
Recommended Action: Segment the flat network into isolated zones (clinical, admin, guest, medical IoT) so a single compromised host cannot reach the EHR database or domain controllers directly.

## GAP-014
Gap Reference: GAP-014 (1x00)
Description: No centralized monitoring or SIEM — zero detection capability organization-wide.
Vulnerability Evidence: billing-srv-01 findings (001, 002, 006, 009, 011, 026 — 1x02) went unmonitored, letting a cryptominer run undetected for 2+ weeks.
Threat Context: Ransomware/RaaS and opportunistic cryptomining actors, all five 1x01 kill chains — detection absence benefits every actor type equally.
NIST CSF Function: Detect (DE.CM — Continuous Monitoring).
CIS Control: Control 8 — Audit Log Management (IG1); Control 13 — Network Monitoring and Defense (IG2).
Recommended Action: Deploy centralized logging on the highest-criticality assets first (ehr-srv-01, billing-srv-01, ad-dc-01) so future incidents are caught in hours, not weeks.

## GAP-010
Gap Reference: GAP-010 (1x00)
Description: Backup has no compensating control — co-located with production, single point of failure.
Vulnerability Evidence: No direct 1x02 scan finding (backup infrastructure was not in scan scope); correlated instead to the Breach 1 (Regional Hospital Alpha) case study in 1x01, where the identical co-location failure destroyed both production and backups together.
Threat Context: Ransomware/RaaS, all five kill chains — backup destruction is the final step that converts a recoverable incident into total data loss.
NIST CSF Function: Recover (RC.RP — Incident Recovery Plan Execution).
CIS Control: Control 11 — Data Recovery (IG1: 11.1–11.3; isolated instance is IG1 Safeguard 11.4).
Recommended Action: Move backups to an isolated, offline or immutable location physically separate from production.

## GAP-004
Gap Reference: GAP-004 (1x00)
Description: Secondary domain controller (ad-dc-02) has no backup coverage — the only corrective control covers ad-dc-01 alone.
Vulnerability Evidence: No direct 1x02 scan finding for ad-dc-02 specifically; ad-dc-01 carried 3 findings (007, 018, 025 — 1x02), showing the domain controller layer is already a known target.
Threat Context: Ransomware/RaaS, Kill Chain 1 — the Breach 1 (Alpha) case study shows a domain controller reached and weaponized within 3 hours once the network was breached.
NIST CSF Function: Recover (RC.RP).
CIS Control: Control 11 — Data Recovery (Safeguard 11.2, automated backups covering all critical assets, not just one).
Recommended Action: Extend the existing backup job to include ad-dc-02, closing the single point of failure in domain authentication recovery.

## GAP-002
Gap Reference: GAP-002 (1x00)
Description: PACS server (pacs-srv-01) has no corrective control — excluded from the only backup job.
Vulnerability Evidence: No 1x02 scan finding directly covers pacs-srv-01; gap is drawn from the 1x00 control coverage matrix (Task 10), flagged honestly rather than inferred from scan data.
Threat Context: Ransomware/RaaS — Restricted imaging data is a named target in the Kill Chain 1 and Kill Chain 5 (Supply Chain) patterns.
NIST CSF Function: Recover (RC.RP).
CIS Control: Control 11 — Data Recovery (Safeguard 11.2).
Recommended Action: Add pacs-srv-01 to the backup schedule so imaging data has a recovery path.

## GAP-001
Gap Reference: GAP-001 (1x00)
Description: Infusion pumps have zero controls of any function — no preventive, detective, corrective, or compensating coverage.
Vulnerability Evidence: A confirmed BD Alaris CVE was identified in 1x00 (Task 7); the 1x02 scan noted medical devices were scanned unauthenticated only, so true exposure is likely understated rather than absent.
Threat Context: Correlates to the Breach 3 (Community Hospital Gamma) case study in 1x01 — default credentials plus zero device segmentation gave a 23-day dwell time on infusion pumps.
NIST CSF Function: Protect (PR.PS — Platform Security).
CIS Control: Control 4 — Secure Configuration of Enterprise Assets and Software (Safeguard 4.7, manage default accounts).
Recommended Action: Replace default credentials on all infusion pumps and place them on an isolated medical-IoT network segment.

## GAP-008
Gap Reference: GAP-008 (1x00)
Description: Shared PACS login removes individual accountability — no control can attribute actions to a specific person.
Vulnerability Evidence: No 1x02 scan finding covers account-level configuration; this is an access-management gap identified directly in the 1x00 control inventory (Task 10), not a scanned vulnerability.
Threat Context: Insider (malicious or negligent) — unauthorized viewing or tampering with imaging studies cannot be traced to an individual.
NIST CSF Function: Protect (PR.AA — Identity Management, Authentication, and Access Control).
CIS Control: Control 5 — Account Management (Safeguard 5.1–5.2, individual account inventory and unique credentials).
Recommended Action: Replace the shared PACS login with individual accounts tied to each user, restoring accountability for every access event.

## GAP-005
Gap Reference: GAP-005 (1x00)
Description: Network closet exposes Restricted system credentials with zero detection — weak badge access, no camera.
Vulnerability Evidence: No 1x02 scan finding applies; this is a physical security gap outside the network vulnerability scan's scope, flagged honestly rather than forced into scan data.
Threat Context: Insider or opportunistic physical intruder — the 1x00 data map (Task 9) named this the single widest exposure point for Restricted credentials.
NIST CSF Function: Protect (PR.AA — Identity Management, Authentication, and Access Control).
CIS Control: None of the 18 CIS Controls in the provided reference directly covers physical security; the closest related control is Control 12 — Network Infrastructure Management, since the closet houses core network equipment. Flagged as a coverage gap in the CIS mapping itself, not invented.
Recommended Action: Add a camera and stronger physical access control (keycard audit trail) to the network closet.

---

## Traceability Summary Table

| Gap | Description | Vuln Evidence | Threat/Kill Chain | CSF Function | CIS Control |
|---|---|---|---|---|---|
| GAP-011 | Flat network, no segmentation | Finding 003, 031 | Ransomware/RaaS — Kill Chain 1 | Protect (PR.IR) | Control 12 |
| GAP-014 | No SIEM/monitoring | billing-srv-01 findings 001,002,006,009,011,026 | Ransomware/RaaS + cryptomining — all kill chains | Detect (DE.CM) | Control 8 / 13 |
| GAP-010 | Backup co-located, single point of failure | None (Breach 1 correlation) | Ransomware/RaaS — all kill chains | Recover (RC.RP) | Control 11 |
| GAP-004 | ad-dc-02 no backup coverage | None (ad-dc-01 findings 007,018,025 as context) | Ransomware/RaaS — Kill Chain 1 | Recover (RC.RP) | Control 11 |
| GAP-002 | PACS excluded from backup | None (1x00 Task 10 matrix) | Ransomware/RaaS — Kill Chain 1/5 | Recover (RC.RP) | Control 11 |
| GAP-001 | Infusion pumps zero controls | BD Alaris CVE (1x00 T7) | Medical Device Pivot — Breach 3 correlation | Protect (PR.PS) | Control 4 |
| GAP-008 | Shared PACS login | None (1x00 Task 10) | Insider (malicious/negligent) | Protect (PR.AA) | Control 5 |
| GAP-005 | Network closet exposure | None (physical, out of scan scope) | Insider / physical intruder | Protect (PR.AA) | Control 12 (closest match — no dedicated physical control provided) |
