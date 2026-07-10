# MedDefense — Data Map

## Data Map

| Data Category | Classification | At Rest (where) | In Transit (how) | In Use (by whom, on what) | Current Protection | Protection Gaps |
|---|---|---|---|---|---|---|
| Patient Medical Records | Restricted | ehr-db-01 (Central) | Flat internal network | Clinical staff, nurse stations | SSH key-only on ehr-srv-01; password policy | DB port open network-wide; unattended session at nurse station (Task 3); no MFA |
| Medical Imaging (PACS) | Restricted | pacs-srv-01 (Central) | Flat internal network | Radiology staff, Central & Westside | None beyond basic network access | Not backed up at all; shared "raduser" login; MRI feed runs on unpatched XP |
| Financial/Billing Data | Restricted | billing-srv-01 (Central) | MySQL port open network-wide | Finance/billing staff | OS-level access, password policy | Compromised twice already (Task 1, 2); DB exposed to entire network |
| Employee HR Records | Confidential | file-srv-01 / HQ systems | Site-to-site VPN, HQ to Central | HR staff, HQ | AD permissions (assumed); VPN encryption | Intern's laptop sat on HR's segment for 3 weeks undetected (Task 1); VPN ACLs never audited |
| System Credentials | Restricted | AD; laminated sheet in network closet | SSH/AD auth traffic | IT staff, system logins | Key-only SSH on ehr-srv-01 only; lockout policy | Switch admin creds posted on paper in an unlocked closet (Task 3); most servers still allow password SSH |
| Audit/System Logs | Confidential | Scattered per-system, not centralized | Not forwarded anywhere | IT staff, reviewed only when something breaks | Local retention windows only | No centralization, no alerting, no log integrity protection |
| Legal/Corporate Data | Confidential | HQ file shares | Site-to-site VPN | Legal, Finance, Executive staff | VPN encryption; assumed AD restriction | VPN ACLs never audited; HQ network landlord-managed |
| Website/Portal Content | Public | web-srv-01 (DMZ) | Public internet, HTTPS | General public | DMZ isolation, restricted firewall rule | Already defaced once (Task 1) — DMZ alone didn't stop it |

## Data Risk Summary

MedDefense's widest protection gap is System Credentials at rest: the network closet's switch admin username and password are written on a laminated sheet, in an unlocked room, protecting Restricted-level data with effectively zero controls. Unlike the nurse station gap, which exposes one patient record to whoever happens to walk by, this gap grants full administrative control of the network core to anyone who opens the door — the largest mismatch between classification level and actual protection found anywhere in this assessment.
