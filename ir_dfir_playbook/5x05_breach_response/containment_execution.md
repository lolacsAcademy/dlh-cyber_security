
# Containment Execution: IR-2026-0420-01

## Execution Status

- Strategy: B — Phased containment
- Decision reference: containment_decision.md
- Authorization: Pending verification
- IR Commander: James Chen
- Technical Lead: Robert Kim
- Supporting engineer: Mike Torres
- Time standard: UTC
- Record policy: Append-only
- Status: Planned; no completed containment actions independently verified

## Execution Sequence

Actions are prioritized below. Volatile evidence must be preserved before isolation where safely possible. Clinical approval is required before changes affecting patient care.

### STEP-001 — Preserve Pre-Containment Evidence

- UTC timestamp: Pending
- Actor: Robert Kim / Mike Torres
- Action: Verify CS-WS-101 memory acquisition; collect available RAM, processes, network connections, and logs from remaining workstations.
- Expected outcome: Preserve volatile evidence before containment changes system state.
- Observed outcome: Torres acquired CS-WS-101 memory at 19:38Z; acquisition hash was not recorded. Other captures remain unverified.
- Deviation notes: Missing acquisition-time SHA-256; integrity verification pending.
- Status: Partially documented; not verified complete.

### STEP-002 — Block C2 Egress

- UTC timestamp: Pending
- Actor: Robert Kim / Mike Torres
- Action: Configure a deny-and-log firewall egress rule for staging.office365-cdn.net and observed destination 45.152.66.114:443, subject to approved change control.
- Expected outcome: Prevent outbound C2 communication.
- Observed outcome: Not available.
- Deviation notes: Domain resolution and additional attacker destinations require review.
- Status: Planned.

### STEP-003 — Isolate CS-WS-101

- UTC timestamp: Pending
- Actor: Robert Kim
- Action: Isolate CS-WS-101 after evidence preservation and clinical coordination.
- Expected outcome: Prevent attacker communication and lateral movement.
- Observed outcome: Not available.
- Deviation notes: Confirm clinical workstation replacement or approved fallback.
- Status: Planned.

### STEP-004 — Isolate CS-WS-104

- UTC timestamp: Pending
- Actor: Robert Kim
- Action: Capture remaining volatile evidence, then isolate CS-WS-104.
- Expected outcome: Stop suspected beaconing and further lateral movement.
- Observed outcome: Not available.
- Deviation notes: Preserve active connection information before isolation.
- Status: Planned.

### STEP-005 — Isolate CS-WS-107

- UTC timestamp: Pending
- Actor: Robert Kim
- Action: Capture remaining volatile evidence, then isolate CS-WS-107.
- Expected outcome: Stop suspected beaconing and further lateral movement.
- Observed outcome: Not available.
- Deviation notes: Coordinate with clinical staff before disconnecting.
- Status: Planned.

### STEP-006 — Isolate CS-WS-112

- UTC timestamp: Pending
- Actor: Robert Kim
- Action: Capture remaining volatile evidence, then isolate CS-WS-112.
- Expected outcome: Stop suspected beaconing and further lateral movement.
- Observed outcome: Not available.
- Deviation notes: Preserve authentication logs and volatile state.
- Status: Planned.

### STEP-007 — Restrict FILE-SVR-01

- UTC timestamp: Pending
- Actor: Robert Kim
- Action: Preserve patient-file access logs, restrict unauthorized access, and allow only approved essential clinical connections.
- Expected outcome: Prevent additional unauthorized patient-file access without interrupting necessary care.
- Observed outcome: Not available.
- Deviation notes: No active beacon reported on the file server. Full isolation requires clinical impact review and explicit authorization.
- Status: Planned.

### STEP-008 — Revoke Compromised Credentials

- UTC timestamp: Pending
- Actor: Robert Kim / Identity Administration
- Action: Identify accounts from the complete 72-hour authentication evidence, preserve sign-in records, revoke active sessions and tokens, reset compromised passwords, and invalidate unauthorized authentication methods.
- Expected outcome: Prevent reuse of compromised credentials.
- Observed outcome: Not available.
- Deviation notes: Exact compromised account list remains unverified; avoid disabling clinical accounts without approved replacement access.
- Status: Planned.

### STEP-009 — Verify C2 Disruption

- UTC timestamp: Pending
- Actor: Robert Kim / SOC
- Action: Review firewall deny logs, endpoint connection telemetry, and SIEM alerts for the known C2 destination and affected hosts.
- Expected outcome: Blocked outbound attempts and no successful C2 connections after containment.
- Observed outcome: Not available.
- Deviation notes: Absence of alerts alone does not prove containment; correlate firewall and endpoint evidence.
- Status: Pending verification.

### STEP-010 — Confirm Clinical Continuity

- UTC timestamp: Pending
- Actor: IR Commander / Clinical Lead
- Action: Confirm essential patient-care services and patient documentation access remain available.
- Expected outcome: Safe clinical operation under containment restrictions.
- Observed outcome: Not available.
- Deviation notes: Escalate immediately if containment creates unsafe clinical conditions.
- Status: Planned.

## Credential Revocation Order

1. Preserve authentication logs and identify affected accounts.
2. Prioritize confirmed compromised privileged and service credentials.
3. Revoke active sessions, VPN tokens, and cloud sessions.
4. Reset confirmed compromised account passwords and unauthorized authentication methods.
5. Coordinate clinical account replacement before interrupting active care.
6. Verify rejected unauthorized sign-ins and successful approved clinical access.

No credential revocation is represented as completed.

## Containment Verification

| Control | Required proof | Result |
|---|---|---|
| C2 firewall rule | Approved rule ID and firewall deny logs | Pending |
| Four workstation isolations | Endpoint isolation confirmations | Pending |
| FILE-SVR-01 restriction | Access-control records and clinical approval | Pending |
| Credential revocation | Identity audit logs and session invalidation | Pending |
| Beacon severed | No successful C2 connections after controls, corroborated by network and endpoint logs | Not proven |
| Clinical continuity | Clinical lead confirmation | Pending |

## Timeline Integration

Append an ACTION entry to incident_timeline.md only when a step is actually completed and its UTC timestamp, actor, observed result, and evidence source are available.

Required format:

    YYYY-MM-DDTHH:MM:SSZ | ACTION | Actor | Completed action and observed outcome | source=containment_execution.md | certainty=confirmed

Do not append planned steps as completed actions.

## Final Status

Containment strategy documented. Actual execution, authorization, credential revocation, and proof of C2 disruption remain unverified. The incident cannot be declared technically contained on the basis of this record alone.
