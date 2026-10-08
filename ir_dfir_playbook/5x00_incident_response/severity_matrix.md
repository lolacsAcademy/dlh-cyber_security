# MedDefense Severity Matrix

## Purpose

Provide a common severity classification for all MedDefense security incidents. Apply it from initial detection through incident closure.

## Severity Matrix

| Level | Patient Safety Impact | Data Exposure | Service Availability | Max Response Time | Decision Authority |
|---|---|---|---|---|---|
| SEV1 | high | confirmed_broad | full_outage | 15 min | CISO |
| SEV2 | moderate | confirmed_limited | partial_outage | 30 min | IR Commander |
| SEV3 | low | suspected | degraded | 60 min | SOC Lead |
| SEV4 | none | none | none | 240 min | SOC Analyst |

## Level Definitions

### SEV1

- Ransomware disrupting Epic across multiple MedDefense sites.
- Confirmed large-scale exfiltration of patient records.
- Critical ICU patient monitoring systems unavailable during active care.

### SEV2

- Confirmed compromise of an account with access to Epic patient records.
- Malware disrupting LIS operations at a single clinical site.
- Confirmed limited exposure of patient records.

### SEV3

- Suspicious login activity involving a West Campus clinical workstation.
- Suspected phishing-related credential exposure under investigation.
- Degraded Nexus Patient Scheduling service without interruption of critical patient care.

### SEV4

- Blocked phishing email with no confirmed compromise.
- Benign Wazuh alert requiring routine analyst review.
- Unsuccessful unauthorized login attempt with no evidence of account compromise.

## Escalation Rule

Severity is reviewed at every incident status update. Raise severity immediately when evidence indicates a higher patient safety, data exposure, or service availability impact. Apply the highest applicable severity criterion. Lower severity only after confirmed containment and IR Commander approval.
