# MedDefense Health Systems — Acceptable Use Policy (AUP)

**Document Owner:** Deputy CISO (James Chen) · **Approved By:** CEO (Dr. Patricia Morales) · **Effective Date:** [date] · **Review Cycle:** Annual, or upon major incident

## 1. Purpose and Scope

This policy governs the acceptable use of MedDefense Health Systems' computing, network, and data resources. It applies to all employees, contractors, physicians, and volunteers at Central Hospital, Westside Clinic, and Corporate HQ who access MedDefense systems, including the EHR, PACS, billing systems, email, VPN, and any device connected to the MedDefense network. Signing this policy is a condition of system access.

## 2. Acceptable Use of Systems

- Use MedDefense systems for clinical care, administrative work, and other job-related duties.
- Access only the patient, financial, or administrative data required for your role.
- Report suspected security incidents to the Deputy CISO immediately — see Section 7.
- Keep MedDefense-issued devices updated when prompted; do not disable security software.

## 3. Prohibited Activities

The following are prohibited because they map directly to risks already identified in MedDefense's security assessment:

- **Sharing login credentials or using a shared/generic account** (e.g., a shared PACS login) instead of your own — this removes individual accountability and is a named Critical risk (RISK-009).
- **Connecting unauthorized personal devices or cloud storage to the network** — this is how the previously undocumented shadow IT (a personal NAS, an unsanctioned Marketing cloud drive, an orphaned network device) entered the environment.
- **Disabling, bypassing, or attempting to bypass MFA, antivirus, or other security controls.**
- **Storing patient or financial data on personal devices, personal email, or unapproved cloud services.**
- **Leaving systems unlocked or sharing physical access to restricted areas** (server rooms, network closets) with anyone not authorized for that access.
- **Using MedDefense systems for activity unrelated to patient care or job duties**, including installing unauthorized software.

## 4. Personal Devices and Removable Media

- Personal phones and laptops may connect to the guest wireless network only. They may not connect to the clinical, administrative, or server network segments.
- USB drives and other removable media are **not permitted** on clinical workstations or any system with EHR access, unless issued and encrypted by IT. This directly addresses the identified gap of 280 clinical workstations with no USB restriction.
- Any personally owned storage device, server, or cloud account discovered in use for MedDefense data (shadow IT) must be reported to IT for review and, if necessary, decommissioned. This applies even if the intent was work-related convenience.

## 5. Password and Authentication Requirements

- All accounts require a unique password; shared passwords and shared accounts are prohibited (Section 3).
- Multi-factor authentication (MFA) is required for VPN access, all administrative accounts, and any remote access to MedDefense systems, per the organization's MFA rollout.
- Do not write down, share, or store passwords in plain text. Use the approved password manager where provided.
- Report a suspected compromised password to IT immediately; do not wait for a scheduled reset.

## 6. Data Handling

Data must be handled according to its classification:

| Classification | Examples | Handling Requirement |
|---|---|---|
| Restricted | Patient records (EHR/PACS), system credentials | Access limited to job need; never emailed unencrypted or stored on personal devices |
| Confidential | Financial/billing data, employee HR records | Access limited to relevant department; shared only through approved systems |
| Internal | General administrative documents | Shared within MedDefense only |

Patient data must stay within approved clinical systems (EHR, PACS). Financial data must stay within approved billing systems. Any transfer of Restricted or Confidential data outside MedDefense (email, USB, personal cloud) requires prior IT approval.

## 7. Monitoring and Enforcement

MedDefense monitors network activity, system access logs, and account behavior to detect security incidents; this monitoring will expand as centralized logging is deployed. Monitoring is conducted for security purposes, not to track routine clinical work.

Violations are handled proportionally:

- **First, minor violation** (e.g., an unapproved USB drive with no data exposure): documented verbal correction and re-training.
- **Repeated or moderate violation:** written warning, referral to the employee's supervisor.
- **Serious violation** (credential sharing that leads to unauthorized access, unauthorized transfer of Restricted data): formal disciplinary action up to and including termination, and reporting to compliance/legal if patient data is involved.

Every violation is documented against this policy so enforcement is consistent, not discretionary.

## 8. Acknowledgment

By signing below, I confirm that I have read and understood this Acceptable Use Policy, and I agree to comply with it as a condition of accessing MedDefense Health Systems' network and data.

```
Employee Name (printed): _______________________________

Employee Signature: _______________________________  Date: _______________

Department: _______________________________  Supervisor: _______________________________
```
