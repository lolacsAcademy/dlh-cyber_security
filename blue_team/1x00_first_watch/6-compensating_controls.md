# MedDefense — Compensating Control Strategy (MRI Workstation)

## 1. Risk Analysis

Windows XP has received no security patches since April 2014, meaning over a decade of publicly known vulnerabilities — including SMB-based exploits like the one used by WannaCry, which specifically targeted healthcare — remain permanently unfixed on this device. Because the MRI workstation sits on the same flat VLAN as ordinary hospital workstations, any compromised device anywhere on that network (a phished nurse's PC, for example) can reach it directly; there is no segmentation to contain the exposure to Radiology. This also works in reverse: if the MRI workstation itself is compromised, it sits on the same broadcast domain as core infrastructure such as the domain controllers and EHR servers, giving an attacker a foothold to move laterally into the most critical systems in the organization. A single unpatchable device on a flat network therefore becomes a risk to the entire hospital, not a contained departmental issue.

## 2. Compensating Control Strategy

### Control 1: Dedicated Network Segment for the MRI Workstation

Description: Place the MRI workstation on its own isolated VLAN with firewall rules that permit only the specific traffic required to communicate with the PACS server (defined IP and port) — nothing else in or out.
Category / Function: Technical / Compensating
Risk Reduction: Contains the exposure in both directions: a compromised hospital workstation elsewhere can no longer reach the MRI, and if the MRI itself is compromised, it cannot reach the EHR, domain controllers, or billing servers. This substitutes for the OS patch that cannot be applied by removing the network path an attacker would need.
Limitations: Does not protect the device if the PACS communication channel itself is exploited or if the PACS server is compromised. Requires disciplined firewall rule maintenance to avoid drifting back toward an open configuration.

### Control 2: Application Whitelisting on the MRI Workstation

Description: Restrict the workstation to run only the specific, pre-approved MRI control software executables; block execution of any unrecognized program.
Category / Function: Technical / Preventive
Risk Reduction: Even without OS patches, this stops unauthorized code — such as the cryptominer or ransomware payloads MedDefense has already encountered — from executing on the device, since only known-good software is allowed to run.
Limitations: Does not stop attacks that exploit an already-running vulnerable service without dropping a new file. Legacy-compatible whitelisting tools for Windows XP Embedded may be difficult to source and must be validated not to interfere with certified MRI functions.

### Control 3: Documented Risk Acceptance and Periodic Review Policy

Description: A written policy that formally documents the MRI's known risk, the compensating controls in place, an assigned owner responsible for monitoring them, and a fixed review cadence (e.g. quarterly) tied to the device's remaining operational lifespan.
Category / Function: Administrative / Compensating
Risk Reduction: Prevents the issue from sitting unaddressed the way it did on Marcus's desk for 6 months. Creates accountability so the technical controls above are verified to still be working, not just assumed, and provides a documented due-diligence trail for regulatory purposes.
Limitations: Paperwork alone stops nothing — this only has value if paired with real technical controls and if leadership actually enforces the review cadence, which has not been MedDefense's track record (e.g. network segmentation was "planned for next fiscal year" more than 4 months ago with no progress).

### Control 4: Restricted Physical Access to the MRI Workstation

Description: Limit physical access to the MRI control workstation and its immediate area to authorized radiology and biomedical engineering staff only.
Category / Function: Physical / Preventive
Risk Reduction: Reduces the risk of local tampering or malware introduction via physical means (e.g. a USB device), similar to the technique already seen with the disguised binary on billing-srv-01.
Limitations: Does not address the network-based attack path, which is the primary risk identified in the Risk Analysis — this control alone is not sufficient on its own.

## 3. Implementation Priority

Control 1: Dedicated Network Segment. It is the only control that fixes the real amplifier of this risk — the flat network — blocking traffic in both directions between the MRI and the rest of the hospital, even while the OS stays unpatched. It also needs no new budget, since MedDefense already owns the firewall required.
