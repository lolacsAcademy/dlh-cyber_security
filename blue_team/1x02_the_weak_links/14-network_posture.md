# Task 14 — The Network Posture

## Analysis 1: CVE-2021-44790 (billing-srv-01)

CVE: CVE-2021-44790
Host: billing-srv-01, 10.10.2.15
CVSS Base Score: 9.8

Scenario A: Current (flat network):
- Who can reach this vulnerability: Any host on all of 10.10.0.0/16 — clinical workstations, medical IoT, Westside, Corporate HQ, every subnet — since no internal firewall or VLAN separates them.
- What the attacker can reach AFTER exploitation: Everything else on billing-srv-01's own subnet (10.10.2.0/24): ehr-srv-01, ehr-db-01, both domain controllers, NAS-01, pacs-srv-01, backup-srv-01 — effectively the entire core server tier, since that subnet has no internal boundaries either.
- Effective Risk: Critical — a single Apache flaw becomes the pivot point into domain controllers, the EHR database, and backups.

Scenario B: Hypothetical (segmented network):
- Who can reach this vulnerability: Only hosts on a dedicated Billing VLAN, likely a small number of finance workstations and management access points.
- What the attacker can reach AFTER exploitation: Other Billing-tier hosts only, unless a firewall rule permits crossing into another VLAN.
- Effective Risk: Still High (CVSS 9.8 is CVSS 9.8), but contained to a single-department incident.

Risk Amplification Factor: Very high — flat network turns a billing-department bug into a path reaching 6+ Critical-rated core hosts instead of just the billing tier.

## Analysis 2: CVE-2020-1938 "Ghostcat" (ehr-srv-01)

CVE: CVE-2020-1938
Host: ehr-srv-01, 10.10.2.10
CVSS Base Score: 9.8

Scenario A: Current (flat network):
- Who can reach this vulnerability: Any host on all of 10.10.0.0/16.
- What the attacker can reach AFTER exploitation: Direct pivot to ehr-db-01 (same subnet, and Finding 003 already leaves it network-wide reachable), plus every other host on the flat 10.10.2.0/24 tier.
- Effective Risk: Critical — weaponized, KEV-listed, and a direct path to the organization's highest-value data.

Scenario B: Hypothetical (segmented network):
- Who can reach this vulnerability: Hosts on a dedicated EHR/application VLAN and authorized clinical workstations only.
- What the attacker can reach AFTER exploitation: ehr-db-01 remains reachable (the app legitimately needs that connection), but domain controllers, billing, and medical IoT would not be, unless a firewall rule explicitly permitted it.
- Effective Risk: Still Critical for EHR/PHI confidentiality specifically — segmentation can't remove the app-to-database relationship — but the spread beyond the EHR tier is what gets blocked.

Risk Amplification Factor: High — segmentation limits how far this CVE spreads beyond EHR, even though it can't fully eliminate the EHR-to-database exposure itself.

## Analysis 3: CVE-2019-0708 "BlueKeep" (WS-RAD-01, MRI Workstation)

CVE: CVE-2019-0708
Host: WS-RAD-01, 10.10.1.70
CVSS Base Score: 9.8

Scenario A: Current (flat network):
- Who can reach this vulnerability: All of 10.10.0.0/16, including all ~320 clinical/admin workstations sharing the same 10.10.1.0/24 subnet as the MRI.
- What the attacker can reach AFTER exploitation: Because this exploit is wormable, a compromise here isn't contained to one device — it can spread across the entire flat workstation subnet and, with no boundary between subnets, potentially into the server tier as well.
- Effective Risk: Critical — the worst-case combination of a weaponized, wormable, KEV-listed exploit with unrestricted network reachability.

Scenario B: Hypothetical (segmented network):
- Who can reach this vulnerability: Only whatever is permitted onto the MRI's dedicated VLAN — per the 1x00 T6 compensating control, ideally just the PACS server on a defined port.
- What the attacker can reach AFTER exploitation: The MRI itself remains compromised, but the wormable spread outward is blocked by the VLAN firewall rules, containing it to this one device and its permitted PACS channel.
- Effective Risk: Still Critical for the device itself, but the organization-wide worming risk — the primary danger of this specific CVE — is specifically what segmentation removes.

Risk Amplification Factor: Very high, arguably the highest of the three — wormable exploits are exactly the class of vulnerability where network reachability, not exploit sophistication, determines the scale of damage.

## Network Posture Summary

Across all 31 findings, the flat 10.10.0.0/16 architecture means the real-world blast radius of nearly every vulnerability is the entire organization, not the single host or department where it was discovered — this same pattern repeats whether the finding is on billing, EHR, medical IoT, or even an undocumented device at Westside, because no internal boundary exists anywhere to contain a compromise once it starts. Patching any single CVE, even a Critical, KEV-listed one like Ghostcat, only closes that one specific door; network segmentation instead limits what every vulnerability can reach — the ones already found in this scan, the ones missed as false negatives, and whatever gets disclosed tomorrow. That structural, forward-looking effect is why segmentation is arguably more impactful than patching any individual finding: one patch fixes one flaw, while segmentation reduces the consequence of the entire vulnerability population at once, past and future.
