# HEALTHBANE Threat Hunting Report

## 1. Executive Summary

MedDefense conducted a hypothesis-driven threat hunt to determine whether HEALTHBANE Stage 4 activity occurred in the environment and whether existing detection coverage could identify it.

The hunt found **high-confidence evidence of Stage 4 credential access and lateral movement**. The compromised pivot host was `WS-RECV-03`. An anomalous process accessed LSASS, after which the `svc_healthsync` service account was used from the workstation with NTLM authentication. PsExec and PowerShell Remoting were then used to reach `SRV-HEALTH-DB`, `SRV-INS-DB`, and `SRV-DC-01`.

The evidence confirms access to sensitive server systems. The available hunt data does **not establish actual database data theft or exfiltration**, so the precise data exposure remains unknown.

Before the hunt, the HEALTHBANE ATT&CK threat model contained 29 techniques, with 16 observed techniques, representing **55% observed coverage**. This hunt newly confirmed PsExec/SMB lateral movement, LSASS credential access, PowerShell Remoting, and domain service-account abuse. This raises evidence-confirmed observed coverage to approximately **69% (20/29)**. The project specifies an **80% improved-coverage objective**, but the available artifacts do not establish 80% as a measured observed-coverage result.

Task 13 produced local detection-rule drafts for the identified gaps. These rules have **not been deployed to a live SIEM** as part of this self-contained project.

## 2. Hunt Methodology

The hunt followed a hypothesis-driven process:

1. Reviewed HEALTHBANE intelligence and existing ATT&CK coverage.
2. Established legitimate administrative behavior using Robert Kim's baseline and authorized administration schedule.
3. Profiled the complete 14-day SIEM dataset.
4. Tested targeted Stage 4 hypotheses against Wazuh, Windows, and Sysmon telemetry.
5. Compared suspicious activity against administrative and service-account baselines.
6. Correlated credential access, authentication, and lateral-movement evidence.
7. Identified detection gaps and drafted new detection logic.

### Data Sources

- `siem_export/wazuh_alerts_14d.json`
- `siem_export/wazuh_raw_sysmon_14d.json`
- `baseline/robert_kim_activity.json`
- `reference/admin_schedule.txt`
- `reference/service_accounts.txt`
- `reference/4x03_attack_mapping.json`

The SIEM export contained **9,800 events** covering approximately 14 days. Relevant telemetry included Sysmon process creation, process access and network activity, Windows authentication events, and PowerShell-related process activity.

## 3. Findings per Hypothesis

### H1 - PsExec Lateral Movement

**Status:** POSITIVE  
**Confidence:** HIGH

Three anomalous PsExec executions originated from `WS-RECV-03` using `svc_healthsync`:

- 2026-05-06 -> `SRV-HEALTH-DB`
- 2026-05-09 -> `SRV-INS-DB`
- 2026-05-13 -> `SRV-DC-01`

The activity violated the administrative baseline because it originated from a non-admin workstation, used a service account, and occurred outside the authorized baseline.

### H2 - LSASS Credential Access

**Status:** POSITIVE  
**Confidence:** HIGH

`C:\Windows\Temp\debug_tool.exe` accessed `lsass.exe` on `WS-RECV-03` with access mask `0x1010` on:

- 2026-05-05 08:22:17 UTC
- 2026-05-12 07:45:35 UTC

The first event preceded unauthorized `svc_healthsync` authentication and lateral movement, strongly supporting credential theft followed by account abuse.

### H3 - WMI Remote Execution

**Status:** NOT CONFIRMED  
**Confidence:** HIGH that no malicious WMI activity was identified from the confirmed pivot host in the tested data.

The hunt did not identify malicious WMI execution originating from `WS-RECV-03`. WMI remains a detection coverage requirement because the pre-hunt ATT&CK mapping identified it as a Stage 4 gap.

### H4 - PowerShell Remoting

**Status:** POSITIVE  
**Confidence:** HIGH

Confirmed `Enter-PSSession` activity using `svc_healthsync` originated from `WS-RECV-03`:

- 2026-05-06 -> `SRV-HEALTH-DB`
- 2026-05-09 -> `SRV-INS-DB`

On 2026-05-13, PsExec targeting `SRV-DC-01` also launched PowerShell.

No `Copy-Item` staging evidence was identified.

### H5 - Service Account Abuse

**Status:** POSITIVE  
**Confidence:** CRITICAL

`svc_healthsync` generated 846 authentication events:

- 840 Kerberos events matching the normal authentication pattern
- 6 unauthorized NTLM events originating from `WS-RECV-03`

All six anomalous events were Logon Type 3. No interactive Type 2, 10, or 11 service-account logons were observed.

The unauthorized events correlated directly with the PsExec lateral-movement sequence.

## 4. Reconstructed Attack Timeline

### 2026-05-05 - Credential Access

`debug_tool.exe` accessed LSASS memory on `WS-RECV-03` using access mask `0x1010`.

### 2026-05-06 - First Lateral Movement

`svc_healthsync` authenticated using NTLM from `WS-RECV-03`.

PsExec was then executed from `WS-RECV-03` against `SRV-HEALTH-DB`.

Later, `Enter-PSSession` established PowerShell Remoting access to `SRV-HEALTH-DB`.

### 2026-05-09 - Expansion

Unauthorized `svc_healthsync` NTLM activity occurred again.

PsExec targeted `SRV-INS-DB`, followed by PowerShell Remoting through `Enter-PSSession`.

### 2026-05-12 - Additional Credential Access

A second anomalous `debug_tool.exe` access to LSASS occurred on `WS-RECV-03`.

### 2026-05-13 - Expansion to Domain Controller

`svc_healthsync` authenticated using NTLM from `WS-RECV-03` toward `SRV-DC-01`.

PsExec then targeted `SRV-DC-01` and launched PowerShell.

### Dwell Time

First confirmed anomalous event:

`2026-05-05 08:22:17 UTC`

Last confirmed correlated event:

`2026-05-13 06:58:45 UTC`

**Confirmed dwell time: 7 days 22:36:28**

## 5. ATT&CK Update

### Before Hunt

- Threat-model techniques: 29
- Observed: 16
- Inferred: 3
- Not covered: 10
- Observed coverage: **55%**
- Mapped coverage: **66%**

### Newly Confirmed by Hunt

- `T1021.002` - SMB/Windows Admin Shares (PsExec)
- `T1021.006` - WinRM / PowerShell Remoting
- `T1003.001` - LSASS Memory
- `T1078.002` - Domain Accounts / service-account abuse

These four confirmations increase evidence-confirmed observed coverage from **16/29 (55%) to 20/29 (approximately 69%)**.

The project identifies **80% as the improved detection-coverage objective**. That figure should not be interpreted as measured observed ATT&CK coverage until the remaining controls are implemented and validated.

## 6. Detection Improvements

The hunt showed that relevant telemetry was generally present, but behavioral detection logic was missing.

Task 13 drafted the following detections:

- PsExec execution from unauthorized sources or times
- Non-system LSASS memory access
- Service-account authentication from unauthorized hosts
- WMI child-process anomalies
- Unauthorized service-account NTLM authentication
- Network-level SMB/PsExec lateral-movement behavior

### Detection Posture

**Before hunt:** Generic telemetry existed, but Stage 4 behavioral baselines and authorization checks were insufficient.

**After hunt:** Detection logic has been drafted for the newly identified behaviors and gaps.

Because this project does not include live SIEM deployment, these controls remain **rule drafts pending implementation, testing, tuning, and validation**.

## 7. Remaining Gaps and Recommendations

### Remaining Unknowns

The hunt does not establish:

- malicious WMI execution from the confirmed pivot host
- `Copy-Item` staging
- whether database records were accessed, copied, or exfiltrated
- the complete scope of activity outside the 14-day dataset
- whether additional persistence mechanisms remain
- whether the stolen credential was used outside the observed environment

The remaining uncovered portion of the HEALTHBANE threat model therefore requires continued investigation and detection engineering.

### Immediate

Initiate incident-response handling for `WS-RECV-03` and preserve relevant forensic evidence. Investigate the three reached servers for follow-on activity.

### Short-Term

Rotate `svc_healthsync` credentials and review other privileged/service accounts for unauthorized use. Review NTLM authentication and restrict service-account use to documented hosts and contexts.

Implement, test, and tune the Task 13 detection drafts before production deployment.

### Medium-Term

Expand consistent Sysmon visibility across endpoints and servers. Implement behavioral analytics using administrative and service-account baselines. Continue ATT&CK-aligned detection validation and recurring threat hunts.

## 8. Lessons Learned

The original **55% observed ATT&CK coverage** provided visibility into much of the known HEALTHBANE campaign but left important Stage 4 behaviors uncovered. Generic telemetry alone did not guarantee effective behavioral detection.

The attacker activity relied heavily on legitimate administrative mechanisms including PsExec, PowerShell Remoting, valid accounts, NTLM authentication, and Windows system functionality. Such activity cannot be judged reliably by tool name alone; source host, user, target, authentication method, time, and established baseline are essential context.

Reactive alerting was insufficient because several malicious behaviors appeared only as ordinary process-creation, process-access, or successful-logon events.

Proactive threat hunting therefore must remain a recurring operational discipline:

**hunt -> find -> detect -> validate -> hunt again**

## Conclusion

**Did HEALTHBANE Stage 4 happen to MedDefense?**

**Yes.** The available SIEM evidence strongly supports Stage 4 credential access, service-account abuse, and lateral movement from `WS-RECV-03` to `SRV-HEALTH-DB`, `SRV-INS-DB`, and `SRV-DC-01`.

**What has been done to improve future detection?**

The hunt identified the behavioral gaps that allowed the activity to evade automated detection and produced targeted detection-rule drafts covering PsExec, LSASS access, service-account misuse, NTLM anomalies, WMI child-process behavior, and SMB lateral movement. These drafts now require implementation and validation in the production detection pipeline.
