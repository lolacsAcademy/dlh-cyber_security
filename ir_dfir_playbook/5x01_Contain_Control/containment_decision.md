
# Containment Decision: IR-2026-0414-01

**Incident:** IR-2026-0414-01  
**Severity:** SEV2  
**Affected endpoint:** WST-WS-031, West Campus Laboratory  
**Account:** MEDDEFENSE\dmarsh  
**Decision owner:** James Chen, IR Commander  
**Status:** Proposed — awaiting approval and completion of Task 2 evidence preservation

## Candidate strategies

### A. Network isolation — Quarantine VLAN

- **Action:** Move WST-WS-031 to quarantine VLAN 999. Block ordinary inbound and outbound network traffic, including communication with `185.220.101.47:443`. Permit only authorized forensic access from the IR jumpbox.
- **Attacker effect:** Severs the observed external communication path and prevents further network-based activity from this endpoint. Malicious processes may continue running locally.
- **Evidence effect:** Preserves powered-on memory, processes, files, and persistence mechanisms. Existing network connections may close during isolation.
- **Patient care effect:** One laboratory workstation loses access to clinical systems. Laboratory staff must use an approved alternative workstation. Availability of spare workstations must be confirmed with the laboratory lead.
- **Time to execute:** Approximately 5 minutes after network-team readiness.
- **Reversibility:** Reversible through restoration of the original VLAN and access controls, subject to IR authorization.

### B. Host power-off

- **Action:** Shut down WST-WS-031 immediately and keep it offline for forensic examination.
- **Attacker effect:** Stops running malicious processes and all network communication on the workstation.
- **Evidence effect:** Destroys live memory, active connections, and transient process state. Disk evidence may remain available, but an abrupt shutdown can affect filesystem consistency.
- **Patient care effect:** Immediately removes the workstation from laboratory service. Any unsaved clinical work may be lost.
- **Time to execute:** Approximately 1 minute once authorized.
- **Reversibility:** The workstation can be powered on again, but lost volatile evidence cannot be recovered.

### C. Selective process termination and firewall egress block

- **Action:** Block outbound traffic to `185.220.101.47:443` using endpoint or network firewall controls. After evidence capture, terminate verified malicious processes associated with `update.exe` (PID 7204), `powershell.exe` (PID 7812), and `MSBuild.exe` (PID 8104). Confirm current process identities before termination.
- **Attacker effect:** Interrupts the known execution chain and observed destination. Other malicious processes or alternate destinations could remain active.
- **Evidence effect:** Destroys memory and runtime state of terminated processes. Retains the remainder of the running workstation and its existing files.
- **Patient care effect:** May allow normal laboratory applications and network services to continue, but process termination could have unintended effects.
- **Time to execute:** Approximately 5–10 minutes, including process verification and firewall configuration.
- **Reversibility:** Firewall rules and ordinary process execution can be restored, but terminated process state cannot be recovered.

## Chosen strategy: A — Network isolation

**Rationale:** Network isolation provides the strongest balance between stopping the observed external communication and preserving the workstation for continued forensic examination. Unlike power-off, it retains volatile memory and running processes; unlike selective termination, it does not depend on identifying every malicious process or destination. It is also reversible, although the laboratory workstation will temporarily lose access to clinical systems. Before execution, the laboratory lead must confirm an acceptable patient-care workaround, and the network team must verify that forensic jumpbox access remains available. The strategy is preferred only after Task 2 volatile evidence capture is complete.

## Execution window

- **Evidence preservation completion:** Pending — confirm Task 2 captures and SHA-256 verification.
- **Containment execution start:** Pending — record the actual UTC start time during Task 4.
- **Target handoff interval:** No more than 5 minutes between confirmed evidence preservation and containment initiation, subject to approval and patient-safety requirements.
- **During the interval:** Maintain active monitoring of WST-WS-031 and its external connections. Do not reset credentials, terminate processes, or reboot the host before the preservation handoff.
- **Recordkeeping:** Enter actual UTC preservation completion and containment start timestamps in `incident_timeline.md`. Do not substitute estimated times for observed events.

## Approval

- **Approving authority:** James Chen, SOC Lead and IR Commander.
- **Approval status:** Pending explicit authorization.
- **Approval requirement:** Confirm the proposed quarantine scope, forensic access, laboratory operational impact, and rollback readiness.
- **Documentation:** Record the actual approval time, approver, and decision in the incident timeline before executing Task 4.

## Rollback plan

1. If quarantine unexpectedly disrupts patient care, immediately notify James Chen and the laboratory lead.
2. Verify whether laboratory work can continue on an approved alternative workstation.
3. If clinical operations cannot safely continue, request IR Commander authorization for rollback.
4. Have the network team restore the original VLAN assignment and approved network policies.
5. If the host must reconnect, consider a temporary targeted egress block as an alternative, recognizing that it provides weaker containment.
6. Confirm clinical connectivity and continue enhanced monitoring for suspicious processes and outbound connections.
7. Record the rollback authorization, UTC execution time, reason, and outcome in `incident_timeline.md`.

**Rollback target:** Approximately 5 minutes after authorization, subject to network-team capability. Never restore unrestricted connectivity without approval and explicit acceptance of the residual security risk.
