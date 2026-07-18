# Task 2 — The CIS Controls Audit

MedDefense Health Systems — scored against the CIS Controls v8 Top 18, using 1x00/1x01/1x02 findings as evidence.

## CIS Control 1: Inventory and Control of Enterprise Assets
**Score:** Partial
**Evidence:** No asset inventory existed before 1x00; the 31-asset registry (A-01–A-31) was built as a one-time deliverable, and the 1x02 network scan still found two unidentified devices.

## CIS Control 2: Inventory and Control of Software Assets
**Score:** Not Implemented
**Evidence:** No software inventory surfaced in any project; billing-srv-01 (Ubuntu 18.04) and print-srv-01 were both found end-of-life only through the 1x02 scan, not a tracked software list.

## CIS Control 3: Data Protection
**Score:** Partial
**Evidence:** 1x00 produced a data classification/data map, but the 1x02 scan confirmed ehr-db-01's PostgreSQL port exposed network-wide — a data access control gap the map alone didn't prevent.

## CIS Control 4: Secure Configuration of Enterprise Assets and Software
**Score:** Not Implemented
**Evidence:** 14 of the 31 findings in the 1x02 vulnerability scan were misconfigurations, the single largest finding category.

## CIS Control 5: Account Management
**Score:** Partial
**Evidence:** GAP-012 bundles missing MFA with offboarding failures, indicating former-employee accounts were not consistently disabled.

## CIS Control 6: Access Control Management
**Score:** Not Implemented
**Evidence:** GAP-012 confirms no MFA anywhere in the environment — not on remote access, not on administrative access.

## CIS Control 7: Continuous Vulnerability Management
**Score:** Partial
**Evidence:** The 1x02 OpenVAS scan happened once and produced 31 findings, but no ongoing patch process is evidenced — EOL systems (billing-srv-01, print-srv-01) had gone unpatched for years before the scan caught them.

## CIS Control 8: Audit Log Management
**Score:** Not Implemented
**Evidence:** GAP-014 confirms no centralized logging or SIEM; the billing-srv-01 cryptominer ran undetected for 2+ weeks with no log trail identified.

## CIS Control 9: Email and Web Browser Protections
**Score:** Not Implemented
**Evidence:** No finding in 1x00, 1x01, or 1x02 specifically evaluates email or browser client protections — scored Not Implemented by absence of evidence, flagged for verification rather than assumed.

## CIS Control 10: Malware Defenses
**Score:** Partial
**Evidence:** A Sophos AV vendor contract confirms malware defenses are deployed, but the billing-srv-01 cryptominer still ran undetected for 2+ weeks, showing the defense is not fully effective or monitored.

## CIS Control 11: Data Recovery
**Score:** Not Implemented
**Evidence:** GAP-010 confirms the backup is co-located with production, with no isolated recovery instance.

## CIS Control 12: Network Infrastructure Management
**Score:** Not Implemented
**Evidence:** GAP-011 confirms a completely flat network with zero segmentation, and 1x01 identified an unpatched VPN/firewall endpoint as the primary ransomware entry vector.

## CIS Control 13: Network Monitoring and Defense
**Score:** Not Implemented
**Evidence:** Same root cause as Control 8 (GAP-014) — no intrusion detection or network alerting, confirmed by the undetected cryptominer incident.

## CIS Control 14: Security Awareness and Skills Training
**Score:** Not Implemented
**Evidence:** No training program appears anywhere in the 1x00–1x02 gap list, despite credential/VPN-based vectors being named as the top threat path in 1x01.

## CIS Control 15: Service Provider Management
**Score:** Partial
**Evidence:** Vendor contracts (MedTech, Microsoft, Sophos, Siemens, Greenfield) were reviewed in 1x00, showing a provider list exists, but no formal service-provider risk management policy is evidenced.

## CIS Control 16: Application Software Security
**Score:** Not Implemented
**Evidence:** No secure development process is evidenced; the public patient portal (web-srv-01) carried 4 scan findings with no secure-SDLC control identified.

## CIS Control 17: Incident Response Management
**Score:** Partial
**Evidence:** James Chen is a named point of contact for security issues, but the January ransomware and the cryptominer incidents were both handled reactively with no documented enterprise reporting process.

## CIS Control 18: Penetration Testing
**Score:** Not Implemented
**Evidence:** 1x02 was a vulnerability scan (OpenVAS), not a penetration test; no exploitation-based testing program is evidenced anywhere in the three prior projects.

---

## Scorecard Summary

| Score | Count |
|---|---|
| Implemented | 0 |
| Partial | 7 |
| Not Implemented | 11 |
| **Total** | **18** |

## Top 5 Priority Controls

1. **Control 6 — Access Control Management (MFA).** Breaks the confirmed ransomware entry vector (1x01 Kill Chain 1) at its first step, before lateral movement is even possible.
2. **Control 12 — Network Infrastructure Management (Segmentation).** GAP-011's flat network is the root cause amplifying nearly every other Critical/High finding; fixing it limits blast radius on every other control's failure.
3. **Control 11 — Data Recovery (Backup Isolation).** Closes GAP-010 directly — without it, MedDefense has no way to recover from the exact ransomware scenario it already survived once.
4. **Control 8 — Audit Log Management.** Directly addresses GAP-014; the cryptominer's 2+ week undetected dwell time is a direct consequence of this control's absence.
5. **Control 4 — Secure Configuration.** Misconfigurations are the single largest finding category in the 1x02 scan (14 of 31); this control has the broadest immediate impact on the existing finding set.
