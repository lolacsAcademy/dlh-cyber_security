# 8. Detection Gap Analysis

## Method

This analysis compares the 20 techniques in Task 7 with documented MedDefense detection capability from 4x00 and 4x01.

- DETECTED: documented detection or analytic directly covers the technique.
- PARTIALLY DETECTED: relevant telemetry or indicators exist, but coverage is incomplete.
- NOT DETECTED: no documented reliable detection covers the technique.

Tasks 5, 9 and 10 are not included because their local outputs have not yet been created.

## Technique Assessment

| ATT&CK ID | Technique | Status | Detection | Evidence | Gap | Recommendation |
|---|---|---|---|---|---|---|
| T1589.002 | Gather Victim Identity: Email Addresses | OBSERVED | NOT DETECTED | No documented collection detection | External reconnaissance occurs outside current visibility | Add identity exposure and phishing-target monitoring |
| T1583.001 | Acquire Infrastructure: Domains | OBSERVED | PARTIALLY DETECTED | 4x00 IOC rules; 4x01 lookalike TLS recommendation | Known domains covered, newly rotated domains may evade IOC matching | Detect newly registered healthcare lookalike domains |
| T1585.002 | Establish Accounts: Email Accounts | OBSERVED | NOT DETECTED | No documented analytic for attacker-created email accounts | External account creation is outside current telemetry | Use email reputation and sender-age enrichment |
| T1587.001 | Develop Capabilities: Malware | OBSERVED | NOT DETECTED | No documented local malware-development detection | Capability development occurs outside MedDefense | Consume malware intelligence and deploy artifact detections |
| T1608.005 | Stage Capabilities: Link Target | OBSERVED | PARTIALLY DETECTED | 4x00 domain rules and 4x01 TLS SNI recommendation | IOC coverage is infrastructure-specific | Add URL/domain-age and lookalike analytics |
| T1566.002 | Phishing: Spearphishing Link | OBSERVED | DETECTED | 4x00 rule 100080 detects campaign-domain email; 4x01 recommends campaign-lookalike TLS detection | Current IOC rule depends on known domains | Add behavioral phishing and newly registered domain detection |
| T1566.001 | Phishing: Spearphishing Attachment | OBSERVED | NOT DETECTED | No documented attachment analytic | Macro attachment delivery may bypass domain-only rules | Add mail attachment and macro-enabled document detection |
| T1078 | Valid Accounts | INFERRED | PARTIALLY DETECTED | 4x00 rule 100082 monitors dmarsh authentication from external IPs; 4x01 recommends VPN geo-anomaly detection | Rule is account-specific and geo-analysis is recommended, not deployed | Generalize anomalous-login detection across accounts |
| T1204.001 | User Execution: Malicious Link | OBSERVED | PARTIALLY DETECTED | 4x01 confirms phishing infrastructure contact through DNS/TLS | Network evidence sees contact but not user execution directly | Correlate email click, proxy and endpoint telemetry |
| T1204.002 | User Execution: Malicious File | OBSERVED | NOT DETECTED | No documented endpoint execution detection | Network evidence cannot confirm file execution | Collect EDR process and Office child-process telemetry |
| T1059.005 | Command and Scripting Interpreter: Visual Basic | OBSERVED | NOT DETECTED | No documented VBA analytic | Macro execution lacks endpoint visibility | Alert on Office macro and suspicious child-process activity |
| T1059.001 | Command and Scripting Interpreter: PowerShell | OBSERVED | NOT DETECTED | No documented PowerShell analytic | No endpoint/script telemetry documented | Enable PowerShell logging and behavioral detection |
| T1053.005 | Scheduled Task/Job: Scheduled Task | OBSERVED | NOT DETECTED | No documented scheduled-task analytic | Persistence may remain unseen without endpoint telemetry | Monitor scheduled-task creation and suspicious task names |
| T1547.001 | Registry Run Keys / Startup Folder | OBSERVED | NOT DETECTED | No documented Registry Run-key analytic | Registry persistence lacks documented monitoring | Collect registry telemetry and alert on abnormal Run-key changes |
| T1056.003 | Input Capture: Web Portal Capture | OBSERVED | PARTIALLY DETECTED | 4x01 identifies encrypted exchange with phishing infrastructure | Exact submitted credentials are not visible in PCAP | Correlate phishing sessions with identity and endpoint evidence |
| T1021 | Remote Services | INFERRED | PARTIALLY DETECTED | 4x01 observed RDP and SMB traffic and recommends cross-role monitoring | Transport is visible but authentication/actions are incomplete | Baseline remote-service use with identity and asset context |
| T1071.004 | Application Layer Protocol: DNS | OBSERVED | PARTIALLY DETECTED | 4x01 identified TXT tunneling and recommends DNS anomaly analytics | Behavior is visible, but recommended analytic is not documented as deployed | Deploy encoded-label and TXT-frequency detection |
| T1071.001 | Application Layer Protocol: Web Protocols | OBSERVED | PARTIALLY DETECTED | 4x00 rule 100081 covers known campaign destinations; 4x01 identified beaconing | IOC matching may miss rotated C2 infrastructure | Deploy periodic beaconing analytics |
| T1048.003 | Exfiltration Over Unencrypted Non-C2 Protocol | OBSERVED | PARTIALLY DETECTED | 4x01 confirmed DNS tunneling behavior and provides detection logic | Detection is recommended rather than documented as deployed | Deploy DNS query-length and encoded-label analytics |
| T1041 | Exfiltration Over C2 Channel | OBSERVED | PARTIALLY DETECTED | 4x00 rule 100081 covers outbound traffic to listed campaign domains; 4x01 identifies repeated C2 communication | Known-IOC coverage does not reliably detect changed infrastructure | Add behavioral beaconing and egress-volume analytics |

## Priority Rules

- Priority 1: OBSERVED and NOT DETECTED
- Priority 2: INFERRED and NOT DETECTED
- Priority 3: PARTIALLY DETECTED

## Prioritized Gaps

| Priority | Gap | Why It Matters | Detection Idea | Required Data | Owner / Path |
|---|---|---|---|---|---|
| P1 | T1566.001 Spearphishing Attachment | Stage 2 malware arrives through a malicious DOCM | Detect macro-enabled attachments and known malicious hashes | Email gateway, attachment metadata | Email/SOC |
| P1 | T1204.002 Malicious File | User execution enables Stage 2 | Detect Office spawning suspicious processes | EDR, process telemetry | Endpoint/SOC |
| P1 | T1059.005 VBA | Macro executes Stage 2 activity | Detect suspicious VBA execution | Office and EDR telemetry | Endpoint |
| P1 | T1059.001 PowerShell | PowerShell is part of observed Stage 2 tooling | Detect encoded or unusual PowerShell | PowerShell logs, EDR | Endpoint/SOC |
| P1 | T1053.005 Scheduled Task | Provides observed persistence | Detect suspicious task creation | Windows event logs, EDR | Endpoint |
| P1 | T1547.001 Registry Run Keys | Provides observed persistence | Detect abnormal Run-key modification | Registry/EDR telemetry | Endpoint |
| P1 | T1589.002 Victim Email Discovery | Supports phishing targeting | Monitor exposed identities and targeting patterns | Email/security intelligence | CTI/SOC |
| P1 | T1585.002 Email Accounts | Enables campaign delivery | Reputation and sender-age enrichment | Email gateway, CTI | Email/CTI |
| P1 | T1587.001 Malware Development | Supports Stage 2 capability | Consume malware intelligence and artifact detections | CTI, EDR | CTI/Endpoint |
| P3 | T1071.004 DNS | Stage 3 uses DNS for C2 | Detect long encoded labels and repeated TXT queries | DNS logs, Zeek | Network/SOC |
| P3 | T1048.003 DNS Exfiltration | Observed data transfer may bypass normal web controls | Query-length and encoded-label analytics | DNS logs, Zeek | Network/SOC |
| P3 | T1071.001 Web Protocols | Rotated C2 can defeat IOC rules | Detect periodic outbound beaconing | Zeek, NetFlow, proxy | Network/SOC |
| P3 | T1021 Remote Services | Supports lateral movement | Detect abnormal cross-role RDP/SMB | RDP/SMB, identity, asset context | SOC/Identity |
| P3 | T1078 Valid Accounts | Stolen credentials enable follow-on access | Detect anomalous VPN and account use | VPN, authentication, GeoIP | Identity/SOC |

## Summary

- Total ATT&CK techniques assessed: 20
- OBSERVED techniques: 18
- INFERRED techniques: 2
- Highest-priority gaps are endpoint and email detections for Stage 2 execution and persistence.
- 4x00 provides useful IOC-based coverage, but it is narrow and infrastructure-dependent.
- 4x01 adds strong network evidence and useful behavioral detection ideas, especially for beaconing, RDP/SMB and DNS tunneling.
- Recommended 4x01 analytics are treated as PARTIAL coverage until deployment is documented.
- Tasks 5, 9 and 10 should be incorporated later when their local outputs exist.
