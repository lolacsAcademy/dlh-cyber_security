# Phishing Campaign Investigation Report

## Executive Summary

MedDefense received eight reported emails during the investigation window, including targeted phishing, spam and legitimate communications. E2, E5 and E7 show strong similarities consistent with a coordinated phishing campaign targeting different business roles. E3 is also phishing but uses a separate Microsoft impersonation theme with correctly configured authentication for its lookalike domain. Diane Marsh is confirmed to have clicked the E2 link, but the available evidence does not establish whether credentials were entered or an account was compromised. Immediate containment and follow-up investigation are recommended.

## Investigation Timeline

- Collection window: April 14–17, 2026.
- April 14: E2 delivered; targeted MedDefense portal-verification lure.
- April 16: E5 delivered; targeted invoice/payment lure.
- April 16: E7 delivered; targeted benefits-enrollment lure.
- Diane Marsh reported click: April 14, 2026 at 15:02:33 CDT from WS-NURSE-04.
- Scope: Eight emails were assessed using the provided email evidence batch, including headers, authentication results, message content, URLs and attachment indicators. No endpoint, SIEM or network telemetry was available.

## Email-by-Email Analysis

| Email | Final Classification | Confidence | Key Evidence |
|---|---|---|---|
| E1 | LEGITIMATE | HIGH | SPF, DKIM and DMARC pass; subscribed newsletter context. |
| E2 | PHISHING-TARGETED | HIGH | Failed SPF/DMARC, no DKIM, MedDefense lookalike domain, targeted portal-verification lure and confirmed click. |
| E3 | PHISHING-TARGETED | HIGH | Microsoft impersonation through outlook-protection.com and urgent verification lure; authentication validates the lookalike domain, not Microsoft. |
| E4 | LEGITIMATE | HIGH | Internal meddefense.com sender with passing SPF, DKIM and DMARC. |
| E5 | PHISHING-TARGETED | HIGH | SPF softfail, no DKIM, DMARC fail, targeted invoice/payment lure, suspicious URLs and PDF attachment indicator. |
| E6 | SPAM | HIGH | Unsolicited pharmaceutical advertising, high spam score and weak/failed authentication. |
| E7 | PHISHING-TARGETED | HIGH | Failed SPF/DMARC, no DKIM, MedDefense HR lookalike domain and urgent benefits lure. |
| E8 | LEGITIMATE | HIGH | Authenticated hhs.gov HC3 healthcare-sector phishing alert. |

## Campaign Analysis

E2, E5 and E7 are likely connected because they occurred within a short time window and share PHPMailer 6.6.0, high-priority headers, urgency and role-specific business-process lures. They target different MedDefense functions: clinical staff, Accounts Payable/finance and HR/benefits.

E8 provides sector-level context consistent with the observed activity, including lookalike domains, PHPMailer-based infrastructure, urgency and role-specific healthcare targeting. These similarities support the campaign hypothesis but do not prove attribution to a specific actor.

E3 should be treated as targeted phishing, but the available evidence does not establish that it belongs to the same campaign as E2, E5 and E7. Its SPF, DKIM and DMARC results pass for outlook-protection.com; however, that domain is not microsoft.com or outlook.com, so successful authentication does not establish Microsoft legitimacy.

## Click Incident Assessment

Diane Marsh is confirmed to have clicked the E2 link from WS-NURSE-04 at 15:02:33 CDT on April 14, 2026.

The evidence batch does not establish whether she entered credentials, downloaded a file, approved MFA or experienced account or endpoint compromise. Therefore, compromise cannot be confirmed or excluded from the available evidence alone.

Recommended follow-up actions include interviewing the user, resetting the password, revoking active sessions, verifying MFA and reviewing available browser, endpoint and identity logs for suspicious activity.

## IOC Summary

### Domains

- meddefense-portal[.]com
- outlook-protection[.]com
- medequip-supplies[.]net
- meddefense-benefits[.]org

### IP Addresses

- 91[.]234[.]99[.]107
- 51[.]38[.]42[.]17
- 185[.]176[.]43[.]22
- 164[.]90[.]218[.]73

### Sender Addresses

- noreply@meddefense-portal[.]com
- security@outlook-protection[.]com
- invoices@medequip-supplies[.]net
- hr-notifications@meddefense-benefits[.]org

### URLs

- hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1
- hxxps://outlook-protection[.]com/verify
- hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891
- hxxps://medequip-supplies[.]net/portal/login
- hxxps://meddefense-benefits[.]org/enroll

### File Indicators

- INV-2026-04891.pdf — suspicious E5 attachment filename.
- No file hash is provided by the evidence batch; no hash is claimed.

## Detection and Control Gaps

The campaign reached user inboxes despite failed or weak authentication on E2, E5 and E7. Lookalike domains and role-specific phishing content also reached targeted recipients, and E2 resulted in a reported user click.

Controls should improve detection of failed DMARC/SPF combined with impersonation, lookalike MedDefense domains, suspicious authentication/verification URLs, urgent role-specific lures and known campaign indicators.

Task 12 detection ideas are not included because Task 12 has not yet been completed in this project. They should be incorporated here after Task 12 is completed rather than inferred or invented.

## Recommendations

### Immediate — Next 24 Hours

- Reset Diane Marsh's password and revoke active sessions.
- Verify MFA status and monitor her account for suspicious authentication.
- Block high-confidence campaign domains, URLs and sender addresses.
- Review available endpoint and identity evidence related to the E2 click.
- Alert relevant MedDefense teams about the identified phishing lures.

### Short-Term — Next 7 Days

- Search available mail records for the identified domains, senders and URLs.
- Review whether other users received or interacted with related messages.
- Improve filtering for MedDefense lookalike domains and failed authentication combined with urgent lures.
- Review Accounts Payable and HR recipients for related campaign activity.

### Medium-Term — Next 30 Days

- Strengthen email impersonation and lookalike-domain controls.
- Improve monitoring for suspicious authentication following phishing reports.
- Provide targeted awareness training for clinical, finance and HR staff.
- Incorporate validated Task 12 detection ideas after that task is completed.
- Review the effectiveness of email filtering and incident-response procedures.
