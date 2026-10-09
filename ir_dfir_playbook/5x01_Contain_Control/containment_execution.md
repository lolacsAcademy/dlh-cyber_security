# Containment Execution: IR-2026-0414-01

**Endpoint:** WST-WS-031
**Strategy:** A — Quarantine VLAN 999
**Authority:** James Chen, IR Commander
**Execution status:** Simulated exercise; live execution not independently verified.

## Execution Record

### 1. Network isolation
- Timestamp (UTC): 2026-04-14T03:16:04Z (scenario example)
- Actor: Network Operations (simulated)
- Action: Reassign WST-WS-031 switchport to quarantine VLAN 999.
- Expected result: Host isolated from normal network access; IR jumpbox access retained.
- Observed result: Not independently verified.
- Deviation notes: No switch configuration or execution log supplied.

### 2. Firewall egress block
- Timestamp (UTC): 2026-04-14T03:17:21Z (scenario example)
- Actor: Network Operations (simulated)
- Action: Configure outbound firewall deny rule for 185.220.101.47.
- Expected result: No further outbound connections to 185.220.101.47.
- Observed result: Not independently verified.
- Deviation notes: No firewall change log supplied.

### 3. Verify C2 disruption
- Timestamp (UTC): Not established
- Actor: SOC Analyst (simulated)
- Action: Review packet capture or NetFlow for WST-WS-031 to 185.220.101.47.
- Expected result: Zero outbound packets after the firewall rule takes effect.
- Observed result: No Task 4 packet capture or timestamped post-containment NetFlow evidence supplied.
- Deviation notes: C2 disruption remains unverified.

### 4. Endpoint containment flag
- Timestamp (UTC): 2026-04-14T03:19:02Z (scenario example)
- Actor: Endpoint Security Analyst (simulated)
- Action: Set endpoint containment flag for WST-WS-031, if supported.
- Expected result: Only authorized analyst communication permitted.
- Observed result: Not independently verified.
- Deviation notes: Endpoint platform capability and console confirmation unavailable.

### 5. Verify jumpbox-only access
- Timestamp (UTC): 2026-04-14T03:22:04Z (scenario example)
- Actor: SOC Analyst (simulated)
- Action: Test connectivity from the IR jumpbox and ordinary user VLAN.
- Expected result: Jumpbox access succeeds; user VLAN access fails.
- Observed result: Not independently verified.
- Deviation notes: No connectivity test results supplied.

## Execution Assessment

The selected containment strategy and required verification steps are documented. The timestamps above are scenario examples, not independently established execution times.

Actual containment success, approval, network isolation, firewall enforcement, C2 disruption, endpoint containment status, and jumpbox-only connectivity remain unverified.

No live containment action is claimed as completed.
