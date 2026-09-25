# 7. ATT&CK Navigator

## HEALTHBANE ATT&CK Mapping

OBSERVED means the technique is supported by direct campaign evidence. INFERRED means the technique is assessed as likely but is not confirmed.

### Reconnaissance

| ID | Technique | Status | Evidence / Reasoning | Source | Phase |
|---|---|---|---|---|---|
| T1589.002 | Gather Victim Identity: Email Addresses | OBSERVED | Victim email identities were gathered for healthcare phishing targets. | HC3 | Stage 1 |

### Resource Development

| ID | Technique | Status | Evidence / Reasoning | Source | Phase |
|---|---|---|---|---|---|
| T1583.001 | Acquire Infrastructure: Domains | OBSERVED | Lookalike campaign domains were registered before phishing activity. | HC3; MedDefense 4x00 | Stage 1 |
| T1585.002 | Establish Accounts: Email Accounts | OBSERVED | Campaign email accounts were established for phishing activity. | HC3; MedDefense 4x00 | Stage 1 |
| T1587.001 | Develop Capabilities: Malware | OBSERVED | Stage 2 malware was developed and deployed in visible victim environments. | HC3 | Stage 2 |
| T1608.005 | Stage Capabilities: Link Target | OBSERVED | Phishing infrastructure hosted links used against targets. | HC3; MedDefense 4x00 | Stage 1 |

### Initial Access

| ID | Technique | Status | Evidence / Reasoning | Source | Phase |
|---|---|---|---|---|---|
| T1566.002 | Phishing: Spearphishing Link | OBSERVED | Stage 1 emails directed users to credential-harvesting pages. | HC3; MedDefense 4x00 | Stage 1 |
| T1566.001 | Phishing: Spearphishing Attachment | OBSERVED | Stage 2 follow-up emails contained a macro-enabled DOCM attachment. | HC3 | Stage 2 |
| T1078 | Valid Accounts | INFERRED | HC3 assesses use of stolen credentials as likely but does not include the technique in its observed table. | HC3 | Stage 2 |

### Execution

| ID | Technique | Status | Evidence / Reasoning | Source | Phase |
|---|---|---|---|---|---|
| T1204.001 | User Execution: Malicious Link | OBSERVED | A MedDefense user clicked a Stage 1 phishing link. | HC3; MedDefense 4x00 | Stage 1 |
| T1204.002 | User Execution: Malicious File | OBSERVED | Stage 2 involved execution of a malicious macro-enabled document. | HC3 | Stage 2 |
| T1059.005 | Command and Scripting Interpreter: Visual Basic | OBSERVED | The Stage 2 DOCM used a VBA macro. | HC3 | Stage 2 |
| T1059.001 | Command and Scripting Interpreter: PowerShell | OBSERVED | PowerShell activity was observed as part of Stage 2 tooling. | HC3 | Stage 2 |

### Persistence

| ID | Technique | Status | Evidence / Reasoning | Source | Phase |
|---|---|---|---|---|---|
| T1053.005 | Scheduled Task/Job: Scheduled Task | OBSERVED | Malware created the `HealthSync Update Service` scheduled task. | HC3 | Stage 2 |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | OBSERVED | Stage 2 malware established persistence using a Registry Run key. | HC3 | Stage 2 |

### Credential Access

| ID | Technique | Status | Evidence / Reasoning | Source | Phase |
|---|---|---|---|---|---|
| T1056.003 | Input Capture: Web Portal Capture | OBSERVED | Credential-harvesting forms captured usernames and passwords. | HC3; MedDefense 4x00 | Stage 1 |

### Lateral Movement

| ID | Technique | Status | Evidence / Reasoning | Source | Phase |
|---|---|---|---|---|---|
| T1021 | Remote Services | INFERRED | HC3 assesses Remote Services as likely but states confirmation is pending. | HC3 | Stage 2 |

### Command and Control

| ID | Technique | Status | Evidence / Reasoning | Source | Phase |
|---|---|---|---|---|---|
| T1071.004 | Application Layer Protocol: DNS | OBSERVED | Stage 3 used DNS TXT queries and responses for communication. | HC3 | Stage 3 |
| T1071.001 | Application Layer Protocol: Web Protocols | OBSERVED | Campaign infrastructure used web protocols for malicious communication. | HC3 | Stage 1/2 |

### Exfiltration

| ID | Technique | Status | Evidence / Reasoning | Source | Phase |
|---|---|---|---|---|---|
| T1048.003 | Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol | OBSERVED | Patient and insurance data were encoded into DNS queries. | HC3 | Stage 3 |
| T1041 | Exfiltration Over C2 Channel | OBSERVED | HC3 observed exfiltration using campaign C2 infrastructure. | HC3 | Stage 3 |

## Summary

- Total techniques identified: 20
- OBSERVED: 18
- INFERRED: 2
- Observed vs inferred ratio: 18:2 (90% observed, 10% inferred)
- Most coverage: Resource Development and Execution, with 4 techniques each.
- Least coverage: Reconnaissance, Credential Access and Lateral Movement, with 1 technique each.
- Detection priorities: T1566.002 Spearphishing Link, T1056.003 Web Portal Capture, T1059.005 VBA, T1059.001 PowerShell, T1053.005 Scheduled Task, T1547.001 Registry Run Keys, T1071.004 DNS and the Stage 3 exfiltration techniques.
- T1078 and T1021 remain hunting hypotheses and must not be represented as confirmed observations.
