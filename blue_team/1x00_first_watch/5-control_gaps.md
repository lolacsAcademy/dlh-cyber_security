# MedDefense — Control Gap Analysis

## Identified Gaps

Gap ID: G-001
Gap Description: No centralized log correlation or alerting exists across any system.
Category x Function Missing: Technical — Detective (present but not actionable)
Affected Asset(s) or Zone: All systems org-wide
Risk if Unaddressed: Compromise can run undetected for weeks — this is exactly why the cryptominer on billing-srv-01 (Task 2) ran for at least 14 days before anyone noticed, discovered only through a performance complaint, not security monitoring.
Evidence: Artifact 8 states directly: "No centralized log management system exists. No automated alerting on security events."

Gap ID: G-002
Gap Description: No administrative process reviews access, logs, or policy compliance on a recurring basis.
Category x Function Missing: Administrative — Detective
Affected Asset(s) or Zone: Org-wide (account access, policy compliance)
Risk if Unaddressed: Marcus's notes (Task 0) document a shared PACS login ("raduser/radiology1") that was reported and never addressed. Without any periodic access review process, an issue like this — already flagged once and ignored — has no mechanism that would ever catch it again.
Evidence: This cell is empty in the Task 4 Control Summary Matrix; no artifact describes any periodic review or audit process.

Gap ID: G-003
Gap Description: No formal incident response plan exists to guide recovery after a security incident.
Category x Function Missing: Administrative — Corrective
Affected Asset(s) or Zone: Org-wide, all incident types
Risk if Unaddressed: The January ransomware response was a 4-day improvised effort by James, Sarah, and Marcus, with no documented plan to follow. That specific incident already shows what happens without one — response time and consistency depend entirely on who happens to be available.
Evidence: Matrix cell empty; Marcus's notes confirm no formal incident response plan exists.

Gap ID: G-004
Gap Description: Antivirus protection does not cover Windows servers, Linux servers, or mobile devices.
Category x Function Missing: Technical — Preventive (partial coverage)
Affected Asset(s) or Zone: 15 Windows servers, all Linux servers (including billing-srv-01, ehr-srv-01/db-01), ~25 physician iPads
Risk if Unaddressed: This is not a hypothetical — it already happened. The cryptominer on billing-srv-01 (Task 2) ran undisturbed specifically because Sophos does not cover Linux servers at all (Artifact 4).
Evidence: Artifact 4 explicitly lists Windows servers and Linux servers as "NOT covered"; directly explains the Task 2 finding.

Gap ID: G-005
Gap Description: Backup recovery has never been fully tested, and the only backup copy is co-located with production systems.
Category x Function Missing: Technical — Corrective (unreliable)
Affected Asset(s) or Zone: All backed-up systems; PACS, secondary DC, Westside server, medical device configs, and O365 are entirely excluded
Risk if Unaddressed: The only recovery test ever performed was a partial restore of a single server (file-srv-01), which took 6 hours (Artifact 5). A full recovery across all 6 backed-up systems has never been attempted, so the real recovery time in an actual incident is unknown. This risk is compounded by the NAS sitting in the same room and on the same network as the servers it backs up.
Evidence: Artifact 5: "Full DR test: Never performed"; single-server partial restore took 6 hours; NAS is in the same server room, same rack row as production.

Gap ID: G-006
Gap Description: Westside Clinic and Corporate HQ have little to no physical security coverage.
Category x Function Missing: Physical — Preventive and Detective
Affected Asset(s) or Zone: Westside Clinic (handles patient imaging and blood work per Task 0), Corporate HQ
Risk if Unaddressed: Westside has one camera that overwrites itself after 48 hours and no guard at all. HQ's cameras are entirely controlled by the building landlord, and MedDefense has no access to that footage at all (Artifact 6). For HQ specifically, there is no mechanism by which MedDefense could review footage even if an incident were suspected.
Evidence: Artifact 6: guard contract covers Central only; Westside camera overwrites after 48 hours; HQ cameras are landlord-controlled with no MedDefense access.

Gap ID: G-007
Gap Description: No camera coverage exists over the server room, network closets, or administrative wing at Central.
Category x Function Missing: Physical — Detective
Affected Asset(s) or Zone: Server room, network closets, administrative wing at Central
Risk if Unaddressed: These are the zones housing every core server and network device, and the Task 3 walk-through already found both the server room and the network closet with no meaningful access restriction. With zero camera coverage of either zone, an intrusion of exactly the kind already observed would leave no evidence and go undetected.
Evidence: Artifact 6 states directly: "No cameras in server room area, network closets or administrative wing." Corroborated by Task 3, Observations 1 and 2.

## Pattern Analysis

The Task 4 matrix shows 7 Preventive controls and 7 Detective controls — numerically balanced, which on the surface looks fine. But quality, not count, is what matters: every Detective control identified is passive. None of them alert, none are centralized (Artifact 8), and they are only reviewed manually "when something breaks" (Tom Reeves' own description). Preventive controls, by contrast, actually block something the moment it happens — a firewall rule, an account lockout, an antivirus signature — even where their coverage is incomplete.

Corrective capability is the real outlier: only 1 control exists in the entire registry (the backup job), and it is untested and co-located with production (Task 5, G-005). Compensating and Deterrent controls are entirely absent — 0 in each category.

This produces a specific, dangerous pattern: MedDefense can sometimes block an attack, and can occasionally notice one days or weeks later if someone happens to look, but has almost no ability to contain or recover from one once prevention fails. That is exactly what happened with billing-srv-01 twice — prevention failed both times, detection took at least 14 days on the second occasion (Task 2), and recovery in January relied on a 4-day improvised effort with no plan to follow (Task 5, G-003), not a tested process.
