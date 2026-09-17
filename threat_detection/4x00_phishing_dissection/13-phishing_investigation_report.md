# Phishing Campaign Investigation Report

## Executive Summary

MedDefense received eight reported emails containing legitimate messages, spam and targeted phishing. E2, E5 and E7 show shared patterns consistent with a coordinated phishing campaign targeting different business roles. E3 is targeted phishing using a Microsoft impersonation theme and a lookalike domain. Diane Marsh is confirmed to have clicked the E2 link, but the evidence does not confirm credential entry or compromise. Immediate containment and follow-up investigation are recommended.

## Investigation Timeline

- Collection window: April 14–17, 2026.
- April 14: E2 delivered.
- April 16: E5 delivered.
- April 16: E7 delivered.
- April 14 at 15:02:33 CDT: Diane Marsh reported click on E2 from WS-NURSE-04.
- Scope: All eight emails were assessed using the provided email evidence batch. No endpoint, SIEM or network telemetry was available.

## Email-by-Email Analysis

- E1 — LEGITIMATE — Confidence: HIGH — SPF, DKIM and DMARC pass; subscribed newsletter context.
- E2 — PHISHING-TARGETED — Confidence: HIGH — Failed SPF and DMARC, no DKIM, MedDefense lookalike domain, targeted portal-verification lure and confirmed click.
- E3 — PHISHING-TARGETED — Confidence: HIGH — Microsoft impersonation using outlook-protection.com and an urgent verification lure; authentication validates the lookalike domain, not Microsoft.
- E4 — LEGITIMATE — Confidence: HIGH — Internal meddefense.com sender with passing SPF, DKIM and DMARC.
- E5 — PHISHING-TARGETED — Confidence: HIGH — SPF softfail, no DKIM, DMARC fail, targeted invoice/payment lure, suspicious URLs and PDF attachment indicator.
- E6 — SPAM — Confidence: HIGH — Unsolicited pharmaceutical advertising, high spam score and weak/failed authentication.
- E7 — PHISHING-TARGETED — Confidence: HIGH — Failed SPF and DMARC, no DKIM, MedDefense HR lookalike domain and urgent benefits lure.
- E8 — LEGITIMATE — Confidence: HIGH — Authenticated hhs.gov HC3 healthcare-sector phishing alert.

## Campaign Analysis

- E2, E5 and E7 occurred within a short time window and share PHPMailer 6.6.0, high-priority headers, urgency and role-specific business lures.
- E2 targets clinical staff, E5 targets Accounts Payable/finance and E7 targets HR/benefits.
- E8 describes healthcare phishing patterns consistent with the observed lookalike domains, urgency, PHPMailer and role-specific targeting.
- These similarities support the campaign hypothesis but do not prove attribution to a specific actor.
- E3 is targeted phishing, but the available evidence does not establish that it belongs to the E2/E5/E7 campaign.
- E3 passes SPF, DKIM and DMARC for outlook-protection.com, but that domain is not microsoft.com or outlook.com.

## Click Incident Assessment

- Confirmed: Diane Marsh clicked E2 from WS-NURSE-04 at 15:02:33 CDT on April 14, 2026.
- Unknown: Whether credentials were entered, a file was downloaded, MFA was approved or compromise occurred.
- Conclusion: The click creates credential-exposure risk, but compromise cannot be confirmed or excluded from the evidence batch alone.
- Next actions: Interview the user, reset the password, revoke active sessions, verify MFA and review available endpoint and identity evidence.

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

- INV-2026-04891.pdf — E5 attachment filename.
- No file hash is provided by the evidence batch.

## Detection and Control Gaps

- Failed or weak authentication did not prevent E2, E5 and E7 from reaching recipients.
- Lookalike domains and role-specific phishing lures reached targeted users.
- E2 resulted in a reported user click.
- Improve detection of failed authentication combined with impersonation, lookalike domains, suspicious verification URLs and urgent role-specific lures.
- Task 12 detection ideas are not included because Task 12 has not yet been completed.

## Recommendations

### Immediate — Next 24 Hours

- Reset Diane Marsh's password and revoke active sessions.
- Verify MFA and monitor for suspicious authentication.
- Block high-confidence campaign domains, URLs and sender addresses.
- Review available evidence related to the E2 click.

### Short-Term — Next 7 Days

- Search mail records for identified domains, senders and URLs.
- Identify other recipients of related messages.
- Improve filtering for lookalike domains and failed authentication.
- Review finance and HR recipients for related activity.

### Medium-Term — Next 30 Days

- Strengthen impersonation and lookalike-domain controls.
- Improve monitoring after reported phishing interactions.
- Provide phishing awareness training for clinical, finance and HR staff.
- Incorporate validated Task 12 detection ideas after Task 12 is completed.
- Review email filtering and incident-response procedures.
