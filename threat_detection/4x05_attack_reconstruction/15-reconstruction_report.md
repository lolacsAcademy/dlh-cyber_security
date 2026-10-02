# HEALTHBANE Attack Reconstruction Report

**Organization:** MedDefense  
**Incident:** HEALTHBANE  
**Assessment period:** 2026-04-14 through 2026-05-15  
**Classification:** Internal Incident Reconstruction

---

## 1. Executive Summary

MedDefense experienced a multi-stage HEALTHBANE intrusion beginning with targeted phishing against records-department user Diane Marsh on 14 April 2026. Her credentials were submitted to an attacker-controlled portal, followed the next day by a second-wave malicious document that delivered `svchost_update.exe` to WS-RECV-03. The malware established persistent HTTPS command-and-control (C2), and the attacker later obtained the `svc_healthsync` service-account credential through LSASS dumping. That credential was used for lateral movement to SRV-HEALTH-DB, SRV-INS-DB and SRV-DC-01 using PsExec, WMI and PowerShell Remoting.

The compromise progressed beyond access and staging. Forensic disk and firewall evidence confirms the extraction and external transmission of 47,138 patient records, 51,002 insurance records and an Active Directory export containing 1,184 user/service-account records. Three recovered staging artifacts correlate exactly with 34,441,660 outbound bytes transmitted to the known HEALTHBANE C2 infrastructure. The evidence therefore supports confirmed data exfiltration rather than attempted or interrupted staging.

WS-RECV-03 was isolated on 15 May 2026 at 13:42 CDT, blocking further C2 communication. Reconstruction demonstrates that behavioral anomalies, forensic evidence and cross-source correlation were necessary to expose activity that individually resembled legitimate administrative behavior.

Key remediation priorities are service-account credential rotation and restriction, improved monitoring of privileged administrative tools, stronger endpoint and cross-VLAN telemetry, detection of persistence and anti-forensics activity, and improved forensic readiness.

### Key Metrics

- Total dwell time: approximately 31 days
- Breakout time: approximately 21 days 18 hours
- Time to first persistence: approximately 7 days
- Time to first confirmed data staging: approximately 23 days 23 hours
- Confirmed patient/insurance records exfiltrated: 98,140
- Confirmed outbound staged data: 34,441,660 bytes
- ATT&CK coverage evolution: approximately 40% -> 55% -> 80%, followed by final reconstruction reassessment

---

## 2. Methodology

### Evidence Sources

The reconstruction used evidence indexed and analyzed during the investigation, including:

- 4x00 phishing investigation findings
- 4x01 network timeline and PCAP findings
- 4x02 intelligence and ATT&CK mapping
- 4x03 malware analysis
- 4x04 threat-hunting findings
- Incident-response volatile-memory artifacts
- Incident-response disk-forensics report
- Firewall session evidence
- IR team working notes
- HEALTHBANE IOC reference data
- MedDefense asset inventory

### Analytical Approach

The investigation used cross-evidence correlation rather than treating individual telemetry sources independently. Email, network, malware, hunting, memory, disk and firewall evidence were aligned chronologically and compared for common hosts, accounts, IOCs, artifacts and ATT&CK behaviors.

Events were assessed as CONFIRMED, PROBABLE or POSSIBLE according to the directness and convergence of supporting evidence. Where independent evidence sources supported the same event, the reconstruction treated the finding as converged evidence.

Timestamp differences were preserved where relevant. Firewall connection-start timestamps were observed four seconds ahead of PCAP/Wazuh timestamps and were treated as authoritative for connection initiation.

### Limitations and Assumptions

IR memory and disk evidence primarily cover WS-RECV-03. Firewall evidence is an abridged session export. The available evidence confirms DNS-exfiltration capability but does not establish high-volume operational DNS exfiltration at MedDefense.

The supplied evidence also contains an unresolved chronology conflict concerning the documented 4x04 hunt-initiation date and the earlier IR isolation date. Consequently, a reliable detection-to-containment duration cannot be calculated without additional authoritative records.

---

## 3. Attack Reconstruction

### Stage 1 — Initial Access

On 2026-04-14 at 13:18:05 UTC, Diane Marsh (`dmarsh`) clicked a credential-harvesting link from WS-RECV-03. Browser history and the phishing investigation confirmed access to:

`meddefense-portal.com/login.aspx`

The malicious email exhibited SPF hardfail and missing DKIM authentication. At 13:18:42 UTC, Diane submitted domain credentials to the attacker-controlled portal. The credential submission was supported by the 4x00 investigation and the 4x01 PCAP POST evidence.

**ATT&CK:** T1566.001, T1078  
**Confidence:** CONFIRMED / CONVERGED

The `dmarsh` password was rapidly rotated and the session revoked. Later attacker persistence was therefore not attributed to continued use of Diane's credential.

### Stage 2 — C2 Establishment

On 2026-04-15 at 08:43:18 UTC, a second-wave email delivered `April-Invoice-MD2026.docm`.

At 08:51:09 UTC, WS-RECV-03 queried `update.healthbane-c2.net`, resolving to `185.220.101.45`. Two seconds later, the host downloaded `svchost_update.exe`.

At 08:51:38 UTC, the first canonical HEALTHBANE C2 beacon was observed:

- Source: WS-RECV-03 / 10.10.3.21
- Destination: 185.220.101.45:443
- SNI: `sync.healthbane-c2.net`
- URI: `POST /api/v1/checkin`
- Beacon interval: 300 +/- 10 seconds
- Mean observed interval: 304 seconds
- Payload protection: RC4-wrapped JSON over TLS

**ATT&CK:** T1071.001, T1573.001  
**Confidence:** CONVERGED

A secondary/fallback C2 at `203.0.113.47:8443` appeared later in the operation and was not active during initial Stage 2 establishment.

### Stage 3 — Malware Deployment and Persistence

Malware analysis established execution of the malicious Office/VBA delivery chain, PowerShell functionality, payload decoding and C2 functionality. The RAT subsequently established Run-key persistence on WS-RECV-03.

On 2026-04-22 at 06:14:47 UTC, HealthSync Run-key persistence was established.

The combined evidence upgraded several techniques that had previously been inferred, including user execution, PowerShell, VBA execution, Run-key persistence and payload obfuscation.

**ATT&CK:** T1204.002, T1059.001, T1059.005, T1547.001, T1027, T1140, T1105  
**Confidence:** CONFIRMED / CONVERGED

### Stage 4 — Credential Access, Lateral Movement and Data Staging

On 2026-05-04, the attacker added a Defender exclusion for `C:\Windows\Temp`.

On 2026-05-05 at 03:22 CDT, `debug_tool.exe`, identified as a Mimikatz-class LSASS dumper, accessed LSASS on WS-RECV-03. Recovered disk artifacts identified `svc_healthsync` as the harvested service-account credential.

**ATT&CK:** T1003.001  
**Confidence:** CONFIRMED

The account was then used for lateral movement:

- 2026-05-06 02:12 CDT — WS-RECV-03 -> SRV-HEALTH-DB
- 2026-05-09 03:40 CDT — WS-RECV-03 -> SRV-INS-DB
- 2026-05-13 01:56 CDT — WS-RECV-03 -> SRV-DC-01

PsExec, WMI and PowerShell Remoting were observed. The use of `svc_healthsync` through NTLM correlated with prior LSASS dumping and supported the pass-the-hash reconstruction.

**ATT&CK:** T1021.002, T1021.006, T1047, T1078.002, T1550.002  
**Confidence:** CONFIRMED / CONVERGED

A scheduled task named HealthSync Update Service was created on 2026-05-07 with a daily 02:00 trigger.

**ATT&CK:** T1053.005  
**Confidence:** CONFIRMED

Data was pulled from target systems to WS-RECV-03 before outbound transfer. Recovered staging artifacts demonstrated collection, local staging and archive creation.

The attacker also cleared the Security event log and deleted staging artifacts after use.

**ATT&CK:** T1005, T1074.001, T1560.001, T1070.001, T1070.004  
**Confidence:** CONFIRMED

---

## 4. Unified Timeline

| Date/Time | Event | ATT&CK | Evidence | Confidence |
|---|---|---|---|---|
| 2026-04-14 13:18:05 UTC | Credential-phishing link clicked | T1566.001 | 4x00 | CONFIRMED |
| 2026-04-14 13:18:42 UTC | Credentials submitted | T1078 | 4x00, 4x01 | CONVERGED |
| 2026-04-15 08:43:18 UTC | Second-wave malicious document delivered | T1566.001 | 4x01 | CONFIRMED |
| 2026-04-15 08:51:09 UTC | HEALTHBANE C2 domain resolved | — | 4x01 | CONFIRMED |
| 2026-04-15 08:51:11 UTC | RAT downloaded | T1105 | 4x01, 4x03 | CONFIRMED |
| 2026-04-15 08:51:38 UTC | First canonical C2 beacon | T1071.001, T1573.001 | 4x01, IR | CONVERGED |
| 2026-04-22 06:14:47 UTC | Run-key persistence | T1547.001 | 4x03, IR | CONVERGED |
| 2026-05-04 18:11:08 CDT | Defender exclusion added | Defense Evasion | IR | CONVERGED |
| 2026-05-05 03:22 CDT | LSASS dumped; service credential harvested | T1003.001 | 4x04, IR | CONVERGED |
| 2026-05-06 02:12 CDT | Lateral movement to SRV-HEALTH-DB | T1021.002 | 4x04, IR | CONVERGED |
| 2026-05-07 01:47:33 CDT | Scheduled persistence created | T1053.005 | IR | CONVERGED |
| 2026-05-07 | Secondary C2 observed | T1071.001 | IR | PROBABLE |
| 2026-05-08 02:36 CDT | Patient records staged | T1005, T1074.001, T1560.001 | IR | CONVERGED |
| 2026-05-08 | Patient dataset exfiltrated | T1041 | IR disk/firewall | CONVERGED |
| 2026-05-09 03:01:42 CDT | Security event log cleared | T1070.001 | IR | CONVERGED |
| 2026-05-09 03:40 CDT | Lateral movement to SRV-INS-DB | T1021.002 | 4x04, IR | CONVERGED |
| 2026-05-11 03:14 CDT | Insurance records staged | T1005, T1074.001, T1560.001 | IR | CONVERGED |
| 2026-05-11 | Insurance dataset exfiltrated | T1041 | IR disk/firewall | CONVERGED |
| 2026-05-12 02:45 CDT | Second LSASS dump | T1003.001 | 4x04, IR | CONVERGED |
| 2026-05-13 01:56 CDT | Lateral movement to SRV-DC-01 | T1021.002 | 4x04, IR | CONVERGED |
| 2026-05-13 02:31 CDT | AD enumeration staged | T1074.001 | IR disk | CONFIRMED |
| 2026-05-13 | AD enumeration exfiltrated | T1041 | IR disk/firewall | CONVERGED |
| 2026-05-15 02:00 CDT | Final observed exfiltration attempt | — | IR notes | CONFIRMED |
| 2026-05-15 13:42 CDT | WS-RECV-03 isolated | — | IR notes | CONFIRMED |

### Temporal Metrics

- Total dwell time: approximately 31 days
- Breakout time: approximately 21 days 18 hours
- Time to Run-key persistence: approximately 7 days
- Time to first data staging: approximately 23 days 23 hours
- Detection-to-containment: unresolved because supplied hunt/IR dates conflict
- Operational pattern: intensive Stage 4 activity occurred predominantly during off-hours

### Timeline Gaps

Three material visibility gaps remain:

1. C2 establishment on 15 April through Run-key persistence on 22 April.
2. Run-key persistence on 22 April through renewed operator activity on 4 May.
3. 14 May, characterized in IR notes as a quiet day without a confirmed attacker action.

Persistent access existed during portions of these intervals, but the supplied evidence does not continuously establish operator activity.

---

## 5. ATT&CK Analysis

The final reconstruction reassessed the full ATT&CK baseline using phishing, network, malware, hunting and IR evidence.

### Coverage Evolution

- Post-4x02 intelligence assessment: approximately 40%
- Post-4x03 malware analysis: approximately 55%
- Post-4x04 threat hunting: approximately 80% (23/29)
- Final reconstruction: 28 techniques CONFIRMED and 2 PROBABLE across the expanded 30-technique inventory

The reconstruction added or confirmed IR-visible behaviors that earlier investigations could not establish, including scheduled-task persistence, local data staging, archive collection, event-log clearing and file deletion.

Important upgrades included successful C2 exfiltration (T1041), collection from compromised systems (T1005), PsExec/SMB lateral movement (T1021.002), PowerShell Remoting (T1021.006), WMI (T1047), domain service-account abuse (T1078.002) and pass-the-hash behavior (T1550.002).

### Remaining ATT&CK Gap

DNS C2/exfiltration functionality was confirmed in malware analysis. Test queries were observed, but high-volume DNS exfiltration at MedDefense was not established.

Accordingly:

- T1071.004 — PROBABLE
- T1048.003 — PROBABLE

No supplied evidence supports a correction or downgrade of the confirmed primary attack chain.

### Blind Spots

The investigation exposed several visibility weaknesses:

- Cross-VLAN lateral movement was incompletely visible to the original network capture.
- Administrative tools could resemble legitimate Robert Kim maintenance without behavioral baselining.
- Firewall visibility was required to identify the secondary C2.
- Endpoint forensics were required to prove staging, credential harvesting and anti-forensics.
- Detection of individual events did not automatically provide attack-chain context.

---

## 6. Impact Assessment

### Confirmed Data Exposure

**Patient health records**

- Source: SRV-HEALTH-DB
- Records: 47,138
- Contents included patient ID, names, DOB, SSN and diagnosis codes
- Status: CONFIRMED ACCESSED, STAGED AND EXFILTRATED

**Insurance and billing data**

- Source: SRV-INS-DB
- Records: 51,002
- Contents included policy/member IDs, names, SSNs and coverage data
- Status: CONFIRMED ACCESSED, STAGED AND EXFILTRATED

**Domain identity information**

- Source: SRV-DC-01
- Records: 1,184 domain users/service accounts
- Status: CONFIRMED ACCESSED, STAGED AND EXFILTRATED

No evidence establishes compromise of the separate HR dataset.

### Exfiltration Determination

Three recovered artifacts correlate with firewall EXFIL_BURST records:

| Artifact | Size |
|---|---:|
| `staging_export_001.zip` | 14,219,484 bytes |
| `staging_export_002.zip` | 11,802,944 bytes |
| `query_results.csv` | 8,419,232 bytes |
| **Total** | **34,441,660 bytes** |

The byte-for-byte correlation between recovered staging artifacts and outbound firewall sessions supports **CONFIRMED EXFILTRATION**.

The primary observed destination was `185.220.101.45:443`.

### Regulatory Implications

The evidence supports treating the incident as a reportable breach because PHI containing direct identifiers and diagnosis information was both extracted and externally transmitted.

Current evidence-based patient/insurance notification scope: **98,140 records**, subject to legal and compliance review.

Mitigating factors include eventual isolation of WS-RECV-03, blocking of further C2 communication and the absence of evidence establishing access to additional inventoried servers outside the confirmed chain. These factors limit further exposure but do not negate the confirmed transmission.

---

## 7. Defensive Posture Evaluation

### What Worked

- PCAP evidence established the initial C2 behavior and beacon pattern.
- Malware analysis identified payload capabilities and ATT&CK behaviors.
- Threat hunting distinguished anomalous administrative-tool usage from Robert Kim's legitimate baseline.
- Memory analysis preserved volatile C2 and credential-access evidence.
- Disk forensics recovered deleted staging artifacts.
- Firewall evidence established outbound transfer volumes and secondary C2 visibility.
- Cross-source correlation converted isolated findings into a defensible attack reconstruction.

### What Failed

- Initial phishing controls did not prevent the malicious workflow from reaching the user.
- A second-wave malicious attachment was released from quarantine.
- Persistence and attacker activity remained present for an extended period.
- Legitimate administrative tools provided effective living-off-the-land cover.
- Cross-VLAN visibility was insufficient during earlier investigation stages.
- Service-account controls permitted `svc_healthsync` to be abused from an unauthorized workstation.
- Anti-forensics and deleted staging artifacts required retrospective forensic recovery.
- Individual detections did not provide sufficient context to expose the complete attack chain.

### Structural Lessons

Detection coverage is not equivalent to understanding an intrusion. A technically valid alert can remain operationally weak when identity, host role, time-of-day, network path and historical baseline are not correlated.

Behavioral baselining was particularly important because PsExec, WMI and PowerShell Remoting are legitimate administrative mechanisms. Their significance emerged from **who used them, from which host, against which targets and when**.

---

## 8. Remediation Plan

The supplied project evidence supports the following evidence-driven priorities. Detailed T13/T14 remediation artifacts are not present in the current project directory; therefore this section is limited to actions directly supported by reconstructed weaknesses.

### Immediate

1. Rotate `svc_healthsync` and other credentials potentially exposed through LSASS.
2. Validate that WS-RECV-03 remains isolated and remove confirmed HEALTHBANE persistence.
3. Block confirmed primary and secondary C2 infrastructure.
4. Hunt enterprise-wide for HEALTHBANE IOCs, persistence artifacts and anomalous service-account use.
5. Preserve forensic evidence required for legal, regulatory and insurance processes.
6. Begin breach-response and notification workflows using the confirmed exposure scope.

### Short Term

1. Restrict service accounts to authorized hosts, protocols and required logon types.
2. Alert on service-account authentication from user workstations.
3. Improve detection of LSASS access, PsExec, WMI and PowerShell Remoting anomalies.
4. Monitor scheduled-task creation, Run-key changes, Defender exclusions and event-log clearing.
5. Improve cross-VLAN network and firewall telemetry retention.
6. Review quarantine-release procedures for suspicious email attachments.
7. Correlate administrative-tool detections with administrator baselines and approved maintenance windows.

### Medium Term

1. Strengthen privileged-access architecture and service-account governance.
2. Expand behavioral threat-hunting coverage across server and workstation segments.
3. Improve endpoint forensic readiness and evidence-retention capability.
4. Integrate email, endpoint, identity, network and firewall telemetry into cross-source detection workflows.
5. Exercise incident-reconstruction procedures so evidence can be rapidly assembled into a unified timeline.

### Prioritization Rationale

Actions that prevent credential reuse and lateral movement take priority because the attacker's progression depended on harvested privileged credentials and legitimate remote-administration mechanisms. Visibility improvements follow closely because the incident demonstrated that individual telemetry sources could not independently reconstruct the attack.

---

## 9. Conclusions

The HEALTHBANE investigation demonstrates the operational difference between **detecting events** and **understanding an attack**. Phishing telemetry explained initial access. Network evidence established C2. Malware analysis explained capability. Threat hunting exposed anomalous lateral movement. Memory and disk forensics established credential access, persistence, staging and anti-forensics. Firewall evidence proved external transmission. Only correlation across those sources reconstructed the complete intrusion.

Investigation in isolated pieces creates blind spots. A PsExec event can look administrative. A C2 session can resemble ordinary HTTPS. A deleted archive can disappear from normal host visibility. When identity, endpoint, network, firewall and forensic evidence are aligned chronologically, those isolated observations become a coherent attack chain.

Proactive hunting and forensic readiness are therefore operational requirements rather than optional enhancements. Hunting provided behavioral context that signature-only detection lacked, while forensic preservation allowed deleted and volatile evidence to survive long enough to answer the most consequential question: whether sensitive data actually left the network.

Important uncertainties remain. High-volume DNS exfiltration was not demonstrated. Some intervals contain persistent access without observable operator actions. The supplied hunt and IR records also contain an unresolved detection/isolation chronology conflict. Resolving these issues would require complete firewall/DNS telemetry, authoritative SOC case timestamps and broader forensic acquisition beyond WS-RECV-03.

Despite those limitations, the central reconstruction is strongly supported: HEALTHBANE obtained an initial foothold through phishing, established persistent C2, harvested a service-account credential, moved laterally to critical systems, collected and staged sensitive datasets, exfiltrated those datasets and employed anti-forensic techniques before containment.

---

## Appendix A — IOC Summary

| IOC | Type | Source | Status |
|---|---|---|---|
| `meddefense-portal.com` | Domain | 4x00 | KNOWN |
| `update.healthbane-c2.net` | Domain | 4x01/4x03 | KNOWN |
| `sync.healthbane-c2.net` | Domain | 4x01/4x03 | KNOWN |
| `data-sync.healthbane-c2.net` | Domain | 4x01/4x03 | KNOWN |
| `185.220.101.45` | IPv4 | 4x01/4x03/IR | CONVERGED |
| `203.0.113.47:8443` | IPv4/Port | IR memory/firewall | NEW / CONVERGED |
| `svchost_update.exe` | File | 4x03/IR | CONVERGED |
| `sync_healthdata.ps1` | File | 4x03/IR | CONVERGED |
| `debug_tool.exe` | File | 4x04/IR | CONVERGED |
| `PsExec64.exe` | File/Tool | 4x04/IR | CONVERGED |
| `svc_healthsync` | Account | 4x04/IR | COMPROMISED |

No conflicted IOC was identified in the correlation matrix.

---

## Appendix B — Evidence Citation Index

| Evidence | Contribution |
|---|---|
| `previous_findings/4x00_phishing_summary.txt` | Phishing, credential exposure, email authentication |
| `previous_findings/4x01_network_timeline.txt` | RAT delivery, DNS, primary C2, beaconing |
| `previous_findings/4x02_attack_mapping.json` | Intelligence-driven ATT&CK mapping |
| `previous_findings/4x03_malware_summary.txt` | Malware execution, persistence and capability |
| `previous_findings/4x04_hunting_report.txt` | Credential access and lateral movement |
| `ir_evidence/memory_artifacts.txt` | Volatile processes, C2, LSASS and scheduled-task evidence |
| `ir_evidence/disk_forensics_report.txt` | Staging, collection, deleted artifacts and anti-forensics |
| `ir_evidence/firewall_sessions_ws_recv_03.json` | C2 sessions and exfiltration volumes |
| `ir_evidence/ir_team_notes.txt` | Containment and IR chronology |
| `reference/healthbane_ioc_master.json` | IOC reference |
| `reference/meddefense_asset_inventory.txt` | Asset roles and data sensitivity |
| `reference/attck_navigator_80pct.json` | ATT&CK baseline |

---

## Appendix C — ATT&CK Navigator Layer Reference

Baseline Navigator layer:

`reference/attck_navigator_80pct.json`

The baseline represents the approximately 80% post-hunting view. The final reconstruction reassessed that mapping using IR memory, disk and firewall evidence, resulting in an expanded 30-technique inventory with 28 CONFIRMED and 2 PROBABLE techniques.

The final inventory is produced by:

`9-attack_techniques.sh`

---

**End of Report**
