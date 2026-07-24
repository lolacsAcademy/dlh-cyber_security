# Task 7 — The Risk Register Update

## Part 1: RISK-003 Update — Ransomware Encrypts EHR

```yaml
Risk Description: "Ransomware encrypts the EHR system via lateral movement on the flat network."
Threat Source: "Crimson Tide (CT) group — was generic Ransomware/RaaS"
Likelihood: "5 (Almost Certain — ARO 0.9, from T5)"
Impact: "5 (Severe)"
Inherent Risk Score: "25 — was 15"
ALE: "$1,112,400 — was $370,800 (T5)"
Treatment Decision: "Mitigate — unchanged"
Treatment Justification: "Still Mitigate, but urgency collapses from the 6-month roadmap to the 72-hour plan (Task 3). Segmentation is still the structural fix; it now depends on the FortiGate patch (RISK-NEW-001) landing first, since that's the entry point."
KRI: "Crimson Tide IOC matches in FortiGate/EDR logs — Tor C2 IP contact, Rclone execution, unscheduled GPO creation"
## Part 2: RISK-NEW-001 — FortiGate CVE-2023-27997

```yaml
Risk Description: "Unauthenticated RCE on the FortiGate via CVE-2023-27997, the confirmed Crimson Tide entry point."
Risk Category: "Operational"
Threat Source: "Crimson Tide (CT) group"
Vulnerability: "CVE-2023-27997 (Task 1)"
Affected Asset(s): "VPN / Remote Access (FortiGate 100F, A-17) — Critical"
Likelihood: "5 (Almost Certain — ARO 0.9, same reasoning as T5: active campaign, matching profile)"
Impact: "5 (Severe — gates every other phase in the chain)"
Inherent Risk Score: "25"
ALE: "$965,700 (SLE $1,073,000 — same FortiGate asset value as RISK-002 — x ARO 0.9)"
Risk Owner: "Deputy CISO (James Chen)"
Treatment Decision: "Mitigate"
Treatment Justification: "See cost-benefit below — patch cost is trivial against the ALE."
Planned Control(s): "Renew FortiGate support contract, patch off FortiOS 7.0.9"
Residual Risk: "$48,285 ALE (5% residual, patched) — Low"
KRI: "FortiOS version vs. latest patched release; support contract status"
Review Date: "Immediate — supersedes quarterly cycle"
```

**Cost-benefit:** ALE before $965,700 − ALE after $48,285 − control cost $2,400 = **Net Benefit $915,015**. Patching is clearly justified; the $2,400 renewal is the cheapest action against the largest single risk in the register.

## Part 3: Register Governance Test

Governance trigger criteria (1x03 T10): "An out-of-cycle review is triggered by any confirmed incident touching a listed asset, a new critical vulnerability disclosed for an affected system, or a KRI breaching its threshold."

The Crimson Tide advisory meets this on two independent grounds: it is a new critical vulnerability disclosure (CVE-2023-27997, CVSS 9.8) affecting a listed asset (FortiGate, tied to RISK-002/RISK-003), and it reports 5 confirmed incidents on similarly-profiled organizations — one 45 miles from MedDefense — which functions as the "confirmed incident" trigger for a closely comparable asset class. Since RISK-003's Inherent Risk Score now rises to 25 (Critical range), the governance note's CEO-briefing condition is also triggered, alongside the standard 48-hour Risk Owner escalation to the Deputy CISO.```
