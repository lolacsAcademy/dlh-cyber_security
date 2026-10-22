
# Tabletop Exercise: Nexus Supply Chain Compromise

**Date:** 2026-04-14  
**Classification:** Internal - Exercise Use Only  
**Facilitator:** MedDefense SOC Team  
**Scenario version:** 1.0

## Organization background

MedDefense operates three sites: West Campus, Main, and North Site. All depend on Nexus for approximately 3,500 patient-facing scheduling interactions weekly. MedDefense must protect electronic patient information under HIPAA and maintain safe appointment operations.

## Vendor background

Nexus Patient Scheduling is a cloud-based service provided by Nexus Health Technologies. It processes patient demographics, appointment information, and insurance eligibility data. Staff rostering access is not confirmed in the vendor profile.

MedDefense exchanges scheduling data with Nexus using HL7 FHIR R4 over HTTPS. The profile does not explicitly confirm Epic as the EHR vendor.

Nexus operates under a BAA requiring breach notification to MedDefense within 24 hours of discovery. An operational SLA is not specified in the available material.

The last vendor review identified missing independent update hash validation, no agent dependency inventory, and untested joint incident communications.

## Opening situation

Three days ago, a threat actor compromised Nexus's build infrastructure and distributed a malicious update through its automatic update channel.

The update carried a valid Nexus digital signature. A backdoor has been active on MedDefense Nexus agent hosts across all three sites since deployment.

Today, 45 minutes ago, the SOC detected unusual outbound traffic from the Main campus scheduling server to an unknown external IP address.

## Known facts at exercise start

- SOC alert: unusual outbound traffic to an unidentified external IP.
- Confirmed server name: `SCHED-SVR-01` at Main campus.
- Nexus agent hosts also exist at West Campus and North Site; their hostnames are not provided.
- EDR reports periodic outbound connections every four hours.
- No other technical findings have been confirmed.

## Decisions requiring discussion

**Operational continuity:** Should MedDefense isolate the scheduling servers immediately, risking appointment disruption, or maintain operations while investigating?

**Vendor trust:** Does a valid digital signature justify trusting future Nexus updates when the update channel itself may be compromised?

**Patient safety:** Appointment records may have been modified during the compromise window. How should MedDefense verify appointment accuracy without unnecessarily interrupting patient care?

**HIPAA obligations:** Nexus is a Business Associate. Its compromise may trigger MedDefense's own notification obligations, but the extent of any ePHI exposure remains unknown.

Participants must make decisions using the information available at exercise start. The full compromise scope has not yet been established.
