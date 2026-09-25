# 13. HEALTHBANE Intelligence Brief

## Executive Summary

HEALTHBANE is a multi-stage campaign targeting US healthcare organizations through credential harvesting, malware delivery and data exfiltration. MedDefense received three phishing emails, and one employee clicked a malicious link and likely submitted credentials, although the original 4x00 investigation did not confirm the submitted password through packet evidence. Across HC3-visible organizations, Stage 1 affected all six observed organizations, while two progressed through malware delivery and DNS-based exfiltration. MedDefense's current posture provides useful IOC and network visibility, but important endpoint, email-attachment and persistence detection gaps remain. ATT&CK analysis identified 20 techniques: 18 OBSERVED and 2 INFERRED. The tested HEALTHBANE phishing-PDF YARA rule achieved 100% detection and precision on the supplied corpus with no false positives. The three highest-priority actions are to deploy Stage 2 endpoint/email detections, operationalize DNS tunneling and beaconing analytics, and strengthen identity monitoring for compromised-account activity. Attribution remains unresolved, and the labels HEALTHBANE, VITALSCORE and APT-MEDAGENT must not be treated as confirmed actor equivalents.

## Adversary Profile

No validated standalone Task 12 adversary-profile output is present in the supplied project outputs, so actor identity is not asserted beyond the available source evidence.

HC3 uses HEALTHBANE as the campaign name but does not confirm a named threat actor. The commercial feed associates overlapping activity with `VITALSCORE`. The researcher tracks the operator as `APT-MEDAGENT` with MEDIUM confidence based on tooling and infrastructure overlap with earlier healthcare campaigns. MedDefense 4x00 does not make an actor attribution.

The available evidence supports an operator focused on healthcare organizations, using healthcare-themed phishing infrastructure, credential harvesting, follow-up malware delivery and data exfiltration. Attribution remains lower confidence than the technical campaign findings.

## Campaign Analysis

### Timeline

- 2026-04-14: Earliest known campaign activity and MedDefense Stage 1 phishing activity.
- 2026-04-14 to 2026-04-16: Primary credential-harvesting activity.
- 2026-04-16 to 2026-04-22: Stage 2 malware-delivery window.
- 2026-04-18: Researcher received a HEALTHBANE phishing email from a Midwest hospital contact.
- Around 2026-04-22: Researcher reports the exposed phishing kit was taken down.
- 2026-04-23 to 2026-04-26: Stage 3 exfiltration window.
- 2026-04-25: HC3 advisory published.
- 2026-04-26: Most recent activity in the reported Stage 3 window.

### Stage 1 — Credential Harvesting

Healthcare-themed spearphishing links directed victims to credential-harvesting portals. HC3 reported at least 14 targeted healthcare organizations and direct or partner visibility on six. Stage 1 occurred at all six visible organizations.

MedDefense investigated three phishing emails. One employee clicked a campaign link and reported entering a password. The researcher independently recovered a PHP phishing kit using PHPMailer 6.6.0 and identified infrastructure linking the credential harvester to later campaign stages.

**Confidence: HIGH** for phishing and credential-harvesting activity; exact campaign-wide credential compromise rate remains unknown.

### Stage 2 — Malware Delivery

Stage 2 occurred at two of six HC3-visible organizations. Follow-up activity used compromised accounts and a macro-enabled document, `HEALTHBANE_S2_invoice.docm`, which downloaded `svchost_update.exe`. Associated tooling included `sync_healthdata.ps1`.

Persistence included the `HealthSync Update Service` scheduled task and a Registry Run key.

**Confidence: HIGH** for the observed HC3 victim environments; broader victim prevalence is unknown.

### Stage 3 — Data Exfiltration

Stage 3 was observed at two HC3-visible organizations. Patient and insurance information was targeted, with data encoded into DNS labels and transmitted using DNS TXT traffic associated with campaign infrastructure.

4x01 independently documented repeated encoded TXT queries and approximately 3,914 bytes of estimated raw tunnel payload in the analyzed capture.

**Confidence: HIGH** for observed DNS tunneling; complete data contents, total volume and total victim count remain unknown.

## ATT&CK Mapping

Task 7 identified **20 ATT&CK techniques: 18 OBSERVED and 2 INFERRED**, producing a 90% observed / 10% inferred split.

Key OBSERVED techniques include:

- T1566.002 — Phishing: Spearphishing Link
- T1566.001 — Phishing: Spearphishing Attachment
- T1056.003 — Input Capture: Web Portal Capture
- T1059.005 — Command and Scripting Interpreter: Visual Basic
- T1059.001 — Command and Scripting Interpreter: PowerShell
- T1053.005 — Scheduled Task/Job: Scheduled Task
- T1547.001 — Registry Run Keys / Startup Folder
- T1071.004 — Application Layer Protocol: DNS
- T1048.003 — Exfiltration Over Alternative Protocol

T1078 Valid Accounts and T1021 Remote Services remain INFERRED in the Task 7 mapping and should be used as hunting hypotheses rather than represented as confirmed campaign observations.

For detection planning, phishing, script execution, persistence, C2 and DNS-exfiltration techniques provide the highest operational value.

## Detection Gap Assessment

The Task 8 assessment identified the most serious gaps around Stage 2 execution and persistence.

### Priority 1 — OBSERVED and NOT DETECTED

- T1566.001 — Spearphishing Attachment
- T1204.002 — User Execution: Malicious File
- T1059.005 — Visual Basic
- T1059.001 — PowerShell
- T1053.005 — Scheduled Task
- T1547.001 — Registry Run Keys
- T1589.002 — Gather Victim Identity: Email Addresses
- T1585.002 — Establish Accounts: Email Accounts
- T1587.001 — Develop Capabilities: Malware

These gaps matter because IOC-only controls can fail when adversaries rotate infrastructure while retaining the same behavioral sequence.

Partially detected areas include phishing links, credential harvesting, valid-account activity, remote services, web C2, DNS C2 and DNS exfiltration. The 4x01 investigation provides useful network evidence and detection logic, but recommended analytics should not be treated as deployed controls until implementation is documented.

## Indicator of Compromise Table

No standalone Task 5 IOC output is present in the available project files. The following operational shortlist therefore uses the validated indicator-triage and campaign findings rather than claiming a nonexistent Task 5 deliverable.

| Phase | Indicator | Type | Confidence | Recommended Action |
|---|---|---|---|---|
| Stage 1 | `meddefense-portal.com` | Domain | HIGH | Detect/block where operationally appropriate |
| Stage 1 | `medequip-supplies.net` | Domain | HIGH | Detect/block |
| Stage 1 | `meddefense-benefits.org` | Domain | HIGH | Detect/block |
| Stage 1 | `outlook-protection.com` | Domain | HIGH | Detect and investigate related mail activity |
| Stage 1 | `91.234.99.107` | IP | HIGH | Detect/block campaign traffic |
| Stage 1 | `185.176.43.22` | IP | HIGH | Detect/block campaign traffic |
| Stage 1 | `164.90.218.73` | IP | HIGH | Detect/block campaign traffic |
| Stage 2/3 | `healthbane-c2.net` | Domain | HIGH | Block and hunt historical traffic |
| Stage 2/3 | `51.38.42.191` | IP | HIGH | Block and investigate connections |
| Stage 3 | `data-sync.healthbane-c2.net` | Domain | HIGH | Detect/block and hunt DNS activity |

Shared-hosting addresses, weak ML-similarity clusters, historical indicators and uncorroborated commercial-feed artifacts should not automatically be blocked.

## YARA Rule Summary

`9-yara_phishing_pdf.yar` defines `HEALTHBANE_Phishing_PDF`, detecting the campaign PDF pattern through PDF magic, `wkhtmltopdf 0.12.6` and multiple credential-harvesting URL characteristics.

Local testing produced:

- TP: 2
- FP: 0
- FN: 0
- Detection rate: 100%
- False positive rate: 0%
- Precision: 100%
- Recommendation: DEPLOY

The supplied corpus correctly matched `phishing_sample.pdf` and `healthbane_lure_02.pdf`.

No `10-yara_arsenal.yar` exists in the provided project structure. Task 11 therefore reports that Task 10 rules were not tested rather than fabricating results.

## Recommendations

### Immediate — 48 Hours

1. Block and hunt confirmed high-confidence HEALTHBANE infrastructure where operationally appropriate.
2. Deploy the validated HEALTHBANE phishing-PDF YARA rule in an appropriate monitoring/detection workflow.
3. Preserve and review email, authentication, DNS, VPN and endpoint telemetry for campaign indicators and behaviors.
4. Reset or investigate credentials associated with suspected credential submission.

### Short-Term — 2 Weeks

1. Implement detection for macro-enabled phishing attachments, Office child processes, PowerShell, scheduled tasks and Registry Run-key persistence.
2. Operationalize 4x01 DNS tunneling and periodic-beaconing analytics.
3. Implement anomalous-login monitoring using identity, VPN, GeoIP and expected-access context.
4. Add newly registered healthcare-lookalike domain monitoring.

### Medium-Term — 30 Days

1. Establish behavioral detections that remain effective when campaign infrastructure changes.
2. Baseline RDP and SMB activity using identity and asset-role context.
3. Integrate CTI confidence and indicator lifecycle controls into detection engineering.
4. Re-test YARA and network analytics against expanded malicious and benign corpora before broader production deployment.

## Intelligence Gaps and Collection Priorities

| Intelligence Gap | Collection Needed | Owner / Source |
|---|---|---|
| Exact number of compromised accounts | Authentication and cloud-email audit logs | Identity / Email |
| Whether MedDefense credentials were successfully submitted | Identity logs, password-reset history, endpoint/browser evidence | SOC / Identity |
| Stage 2 activity at additional victims | EDR, Office, PowerShell and email telemetry | Endpoint / Partners |
| Full Stage 3 data volume and contents | DNS, server, application and endpoint evidence | Network / IR |
| Additional affected healthcare organizations | Partner and sector reporting | CTI / Healthcare partners |
| Relationship between HEALTHBANE, VITALSCORE and APT-MEDAGENT | Independent telemetry and additional source corroboration | CTI |
| Infrastructure rotation | Passive DNS, domain-registration and certificate monitoring | CTI / Network |
| Remote-service use after credential theft | VPN, RDP, SMB and authentication logs | Identity / Network |

Collection should prioritize endpoint and identity evidence because those sources would resolve the largest gaps between confirmed network activity and inferred attacker actions.
