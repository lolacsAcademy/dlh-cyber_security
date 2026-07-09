# MedDefense — Control Gap Analysis

## Identified Gaps

Gap ID: G-001
Gap Description: No centralized log correlation or alerting exists across any system.
Category x Function Missing: Technical — Detective (present but not actionable)
Affected Asset(s) or Zone: All systems org-wide
Risk if Unaddressed: Compromise can run undetected for weeks, since no system flags suspicious activity automatically — this is exactly why the cryptominer on billing-srv-01 (Task 2) ran for at least 14 days before anyone noticed, discovered only through a performance complaint, not security monitoring. Confidentiality, Integrity, and Availability are all extended in duration when detection is this slow.
Evidence: Artifact 8 states directly: "No centralized log management system exists. No automated alerting on security events."

Gap ID: G-002
Gap Description: No administrative process reviews access, logs, or policy compliance on a recurring basis.
Category x Function Missing: Administrative — Detective
Affected Asset(s) or Zone: Org-wide (account access, policy compliance)
Risk if Unaddressed: Without periodic access reviews or compliance audits, issues like the radiology department's shared PACS login or dormant accounts can persist indefinitely unnoticed — a Confidentiality and Integrity risk.
Evidence: This cell is empty in the Task 4 Control Summary Matrix; no artifact describes any periodic review or audit process.

Gap ID: G-003
Gap Description: No formal incident response plan exists to guide recovery after a security incident.
Category x Function Missing: Administrative — Corrective
Affected Asset(s) or Zone: Org-wide, all incident types
Risk if Unaddressed: The January ransomware response was a 4-day improvised effort by James, Sarah, and Marcus. Without a documented plan, response quality depends entirely on who is available at the time, extending Availability and Integrity damage during any future incident.
Evidence: Matrix cell empty; Marcus's notes confirm no formal incident response plan exists.

Gap ID: G-004
Gap Description: Antivirus protection does not cover Windows servers, Linux servers, or mobile devices.
Category x Function Missing: Technical — Preventive (partial coverage)
Affected Asset(s) or Zone: 15 Windows servers, all Linux servers (including billing-srv-01, ehr-srv-01/db-01), ~25 physician iPads
Risk if Unaddressed: Malware on these systems is neither blocked nor flagged — this directly explains why the cryptominer on billing-srv-01 was never caught by endpoint protection. The most critical servers in the environment are the least protected.
Evidence: Artifact 4 explicitly lists Windows servers and Linux servers as "NOT covered"; connects directly to the Task 2 finding.

Gap ID: G-005
Gap Description: Backup recovery has never been fully tested, and the only backup copy is co-located with production systems.
Category x Function Missing: Technical — Corrective (unreliable)
Affected Asset(s) or Zone: All backed-up systems; PACS, secondary DC, Westside server, medical device configs, and O365 are entirely excluded
Risk if Unaddressed: A full recovery has never been tested, and the only backup copy sits in the same room and network as production. A fire, flood, or laterally-spreading ransomware could destroy both simultaneously — total, unrecoverable Availability loss.
Evidence: Artifact 5: "Full DR test: Never performed"; NAS is in the same server room, same rack row; offsite/cloud backup was requested and denied.

Gap ID: G-006
Gap Description: Westside Clinic and Corporate HQ have little to no physical security coverage.
Category x Function Missing: Physical — Preventive and Detective
Affected Asset(s) or Zone: Westside Clinic (handles patient imaging and blood work), Corporate HQ
Risk if Unaddressed: No guard presence at either site, only a 48-hour camera at Westside, and no camera access at all at HQ mean unauthorized physical access would likely go both unprevented and unnoticed — a direct Confidentiality risk to patient data at Westside.
Evidence: Artifact 6: guard contract covers Central only; Westside camera overwrites after 48 hours; HQ cameras are landlord-controlled with no MedDefense access.

Gap ID: G-007
Gap Description: No camera coverage exists over the server room, network closets, or administrative wing at Central.
Category x Function Missing: Physical — Detective
Affected Asset(s) or Zone: Server room, network closets, administrative wing at Central
Risk if Unaddressed: These are the most sensitive physical zones in the organization, housing every core server and network device, yet none of them are monitored. An intrusion like the ones observed in Task 3 (unrestricted server room, unlocked network closet) would leave no evidence and go completely undetected.
Evidence: Artifact 6 states directly: "No cameras in server room area, network closets or administrative wing." Corroborated by Task 3, Observations 1 and 2.

## Pattern Analysis

MedDefense's posture is prevention-oriented, but only on paper: several preventive controls exist (firewall, SSH keys, password policy, antivirus, a guard) while almost every detective control is passive and uncorrelated, and corrective capability is nearly absent outside of an untested backup job. Even prevention has real holes — the antivirus doesn't cover the servers that actually got compromised, and physical prevention barely reaches Westside and HQ.

This means that when a threat bypasses prevention, as it
