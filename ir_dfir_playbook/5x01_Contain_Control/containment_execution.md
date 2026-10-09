# Containment Execution: IR-2026-0414-01

**Endpoint:** WST-WS-031
**Strategy:** A — Quarantine VLAN 999
**Authority:** James Chen, IR Commander
**Record type:** Lab scenario containment execution

## Execution Record

### 1. VLAN Reassignment

- **Timestamp (UTC):** 2026-04-14T03:16:04Z
- **Actor:** Network Operations
- **Console action:** Reassign WST-WS-031 switchport to quarantine VLAN 999.
- **Expected result:** Isolate workstation from production networks while retaining IR jumpbox access.
- **Observed result:** Scenario reports successful jumpbox connectivity and timeout from the user VLAN.
- **Deviation notes:** None reported.

### 2. Firewall Egress Block

- **Timestamp (UTC):** 2026-04-14T03:17:21Z
- **Actor:** Network Operations
- **Console action:** Configure firewall deny rule for outbound traffic to 185.220.101.47.
- **Expected result:** Prevent further communication with the identified C2 destination.
- **Observed result:** Scenario reports zero outbound packets to 185.220.101.47 after 03:17:21Z.
- **Deviation notes:** None reported.

### 3. C2 Communication Verification

- **Timestamp (UTC):** 2026-04-14T03:17:21Z
- **Actor:** SOC Analyst
- **Console action:** Review NetFlow records for WST-WS-031 communicating with 185.220.101.47.
- **Expected result:** No outbound C2 traffic after firewall enforcement.
- **Observed result:** Scenario reports a NetFlow gap beginning at 03:17:21Z, with zero subsequent packets to the destination.
- **Deviation notes:** No separate packet capture identifier supplied.

### 4. Endpoint Containment Flag

- **Timestamp (UTC):** 2026-04-14T03:19:02Z
- **Actor:** Endpoint Security Analyst
- **Console action:** Set device containment flag for WST-WS-031 in the endpoint security console.
- **Expected result:** Restrict endpoint communication to authorized analyst tooling.
- **Observed result:** Scenario reports containment flag SET in the endpoint console.
- **Deviation notes:** None reported.

### 5. Isolation Verification

- **Timestamp (UTC):** 2026-04-14T03:22:04Z
- **Actor:** SOC Analyst
- **Console action:** Test WST-WS-031 connectivity from the production user VLAN and IR jumpbox.
- **Expected result:** User VLAN connection fails; IR jumpbox connection succeeds.
- **Observed result:** Scenario reports timeout from the user VLAN and successful ping from the IR jumpbox.
- **Deviation notes:** None reported.

## Containment Outcome

The supplied lab scenario records successful VLAN isolation, firewall egress blocking, C2 communication interruption, endpoint containment flag activation, and jumpbox-only connectivity.

**Evidence limitation:** These results are taken from the assignment's example execution record. Independent switch, firewall, endpoint-console, and NetFlow artifacts were not supplied. They must not be represented as independently verified live actions.
