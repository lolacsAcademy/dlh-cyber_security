# Task 15 — The Medical IoT

## 1. BD Alaris Assessment

BD's own security bulletin (November 2020, CVE-2020-25165) describes a network session authentication vulnerability between the BD Alaris PC Unit and the BD Alaris Systems Manager. An attacker able to reach the network session can modify configuration headers in transit and trigger a denial-of-service against the pump's wireless capability. CVSS v3 base score is 6.5 — lower than several other findings in this report, but the consequence isn't data theft, it's the pump losing wireless connectivity and dropping back to manual operation, which also cuts it off from Guardrails/DERS dosage safety checks.

BD's recommended mitigation: keep the Systems Manager on a secured network behind a firewall, separate the PC Unit and Systems Manager with a firewall, disable unnecessary accounts/protocols/services, and restrict what can reach the wireless segment.

Has MedDefense implemented this? No. The Asset Registry (A-19) explicitly notes "vendor-recommended isolation not done," and Finding 010 confirms the pumps sit on the same flat 10.10.3.0/24 subnet as every other medical device with no VLAN. On top of that, Finding 010 also found all 7 scanned pumps still using default credentials (admin/admin) on their web management interface — a separate, self-inflicted gap on top of the unaddressed vendor bulletin.

## 2. Philips IntelliVue Assessment

These monitors carry two types of exposed traffic: the web management interface (ports 80/443) and the HL7 port (2575), which is the protocol used to transmit patient vital-sign data (heart rate, blood pressure, SpO2, ECG readings, alarm events) to other clinical systems like the EHR.

With network access to the flat 10.10.3.0/24 segment, an attacker could reach 13 exposed web interfaces directly, with no authentication beyond simply being on the network. That could mean viewing or altering monitor configuration and alarm thresholds, and intercepting or manipulating HL7 traffic carrying real patient vital signs as it moves between the monitor and the rest of the clinical network.

## 3. Patient Safety Dimension

A compromised IT workstation is fundamentally a confidentiality and business-continuity problem: an attacker steals or destroys data, or knocks a system offline, and the worst outcome is financial, reputational, or operational disruption. A compromised infusion pump is a physical-harm problem: the device directly controls how much of a drug enters a patient's body, so a manipulated dosage or a silently disabled safety alarm can injure or kill someone in real time, not after some downstream investigation. The worst case for a workstation compromise is data loss or downtime; the worst case for a compromised infusion pump is a patient receiving a wrong or unsafe dose with no warning.

## 4. Remediation Challenge

Patching medical devices is harder than patching ordinary IT systems for several reasons specific to this category:

- **Regulatory:** Devices like the MRI and infusion pumps are FDA-certified for a specific configuration; changing the OS, firmware, or even some software components can void that certification and require a new regulatory clearance process before the change can be deployed.
- **Operational:** These devices are in continuous clinical use — an infusion pump or vital-sign monitor can't simply be taken offline for a maintenance window the way a file server can, since doing so directly affects active patient care.
- **Vendor dependency:** Unlike a general-purpose OS, only the device manufacturer can release a validated firmware update; hospitals can't patch these systems themselves even if they have the technical capability, and must wait on the vendor's own release and validation cycle.
