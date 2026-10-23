
# Containment Decision: IR-2026-0420-01

## Situation

Four clinical workstations (CS-WS-101, 104, 107, 112) are in scope for active Cobalt Strike beaconing. FILE-SVR-01 holds patient documentation but has no reported active beacon. Ransomware staging scripts have not executed. The clinical site remains operational.

## Strategy Comparison

| Criterion | A: Immediate full isolation | B: Phased containment | C: Monitor without isolation |
|---|---|---|---|
| Action | Disconnect all five hosts immediately | Block C2 egress, isolate four workstations in priority order, restrict file-server access | Maintain connections under monitoring |
| Attacker impact | Rapidly disrupts network access | Disrupts C2 and lateral movement while controlling clinical impact | Attacker may retain access |
| Patient care | High risk of disrupting clinical workflows and patient documentation | Moderate, managed disruption; essential file-server access retained where approved | Minimal immediate disruption, but ongoing attack risk |
| Evidence preserved | Existing captures and stored logs | Existing captures, pre-isolation RAM and logs | Live connections and activity remain observable |
| Evidence lost | Uncaptured connections and volatile network state | Live C2 sessions after blocking; uncaptured state if preservation incomplete | Evidence may be altered or destroyed by attacker |
| Execution time | Minutes after approval | Initial egress block in minutes; host isolation in staged intervals | Immediate monitoring; containment delayed |
| Reversibility | Reconnect hosts after clearance | Remove restrictions individually after validation | Monitoring can be stopped; attacker damage may be irreversible |

## Selected Strategy: B — Phased Containment

Phased containment balances immediate disruption of attacker communications against patient safety and forensic preservation. Capture available volatile evidence before isolation, then block the identified C2 destination and isolate the four affected workstations in a clinically approved sequence. Preserve FILE-SVR-01 access only through essential approved clinical paths while restricting suspicious connections. This protects patient documentation availability and reduces the risk of ransomware propagation. The strategy sacrifices live C2 visibility after blocking but preserves prior captures and exported logs. Parallel collection should prevent unnecessary delay.

- Authorizing role: IR Commander James Chen (SEV2); CISO Patricia Morales approves any SEV1-level decision or critical clinical trade-off.
- Technical execution: Robert Kim, Technical Lead, supported by Mike Torres.
- Clinical prerequisite: Confirm safe patient-care alternatives before restricting essential systems.
- Rollback trigger: Clinical leadership reports unsafe interruption of patient care or loss of essential documentation access.
- Rollback authority: IR Commander, with clinical leadership and CISO involvement where required.
- Rollback method: Restore only the minimum approved clinical connectivity while retaining C2 blocks and enhanced monitoring.
- Status: Proposed decision; authorization and execution not independently verified.

## Verification Criteria

Containment is effective only after firewall logs show C2 traffic blocked, endpoint checks show no successful beacon connections, compromised credentials are revoked, and clinical teams confirm essential services remain available.
