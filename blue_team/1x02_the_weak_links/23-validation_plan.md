# Task 23 — The Validation Plan

## 1. Post-Patch Verification (3 Immediate Remediations)

**Finding 031 (Ghostcat, AJP connector disabled):** Re-scan port 8009 on ehr-srv-01 and confirm it no longer responds, or confirm the AJP connector configuration now requires a secret. Re-run the specific Ghostcat file-read technique against the host and confirm it fails.

**Finding 004 (MRI network segmentation):** From a workstation on a different VLAN, attempt to reach WS-RAD-01 directly and confirm the connection is blocked by the firewall. From the PACS server specifically, confirm the permitted channel still works, so the control hasn't broken legitimate clinical function.

**Finding 010 (BD Alaris default credentials):** Attempt to log into each of the 7 pump web management interfaces using admin/admin and confirm access is denied on all of them. Confirm the new credentials are documented in the password manager, not just changed and forgotten.

## 2. Compensating Control Validation (MRI, Medical IoT)

For the MRI's dedicated VLAN and the medical IoT network isolation, validation means actively testing the boundary, not just confirming the rule exists in a config file: attempt lateral connections from an unrelated subnet to the protected devices and confirm they're refused, and separately confirm the specific permitted traffic (PACS communication, HL7 monitor data) still flows correctly. A control that blocks everything, including legitimate clinical traffic, is a different kind of failure that needs to be caught in testing, not discovered during patient care.

## 3. Rescan Schedule

MedDefense should adopt a **monthly full internal vulnerability scan**, with **weekly scans of internet-facing assets** (the patient portal, the FortiGate firewall) given their larger attacker population. This differs from a single annual assessment because new CVEs are disclosed continuously — this project alone found a Critical CVE (CVE-2026-24858 on the firewall) that didn't exist when the original scan was run. Monthly is frequent enough to catch newly disclosed vulnerabilities within a reasonable window without overwhelming the team with re-triage work every week for internal assets that change less often.

## 4. Continuous Intelligence

CISA KEV should be checked against MedDefense's asset inventory on every new KEV addition, not just during scheduled scans — this report itself found that the original scan's KEV claim for Ghostcat was already outdated by the time it was reviewed. Vendor advisories for MedDefense's specific technology stack (Fortinet, Synology, Microsoft, BD, Philips) should be subscribed to directly rather than discovered incidentally, since this project's OSINT findings (Task 9) only surfaced because someone went looking manually. These feeds should route into the same triage process used for scan findings, so a KEV alert or vendor advisory gets the same Actionable Critical / Standard / Informational treatment as a scan result, rather than sitting in an inbox unactioned.

## 5. Lifecycle Diagram

**Scan → Triage → Prioritize → Remediate → Validate → Repeat**

- **Scan** (Security Analyst): Run the scheduled vulnerability scan and pull in KEV/vendor advisory alerts.
- **Triage** (Security Analyst): Sort findings into Actionable Critical / Standard / Informational / False Positive, as in Task 16.
- **Prioritize** (Security Analyst, with Management sign-off on budget-heavy items): Apply asset criticality, kill chain position, and exploit availability to set the final order, as in Task 17.
- **Remediate** (IT Ops for patches/config changes; Vendor for firmware fixes MedDefense can't apply itself; Management for budget approval on larger items): Execute the fix within its assigned time horizon.
- **Validate** (Security Analyst): Confirm the fix worked using the specific checks in Section 1 and 2 above, not just that the remediation ticket was closed.
- **Repeat**: The cycle restarts on the next scheduled scan, with lessons from validation (e.g., a control that broke clinical traffic) feeding back into how future remediations are planned.
