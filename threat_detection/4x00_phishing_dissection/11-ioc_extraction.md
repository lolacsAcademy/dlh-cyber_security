## IOC Report

### Structured IOC Table

| IOC Type | IOC Value | Source | Context | Confidence | Recommended Action |
|---|---|---|---|---|---|
| Domain | meddefense-portal[.]com | E2 | MedDefense portal lookalike used in credential-verification lure | HIGH | Block |
| IP | 91[.]234[.]99[.]107 | E2 | External sending IP for E2 | HIGH | Alert |
| Email address | noreply@meddefense-portal[.]com | E2 | Sender address used for portal lure | HIGH | Block |
| URL | hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1 | E2 | Staff verification URL | HIGH | Block |
| Domain | outlook-protection[.]com | E3 | Domain used to impersonate Microsoft Account Protection | HIGH | Block |
| IP | 51[.]38[.]42[.]17 | E3 | External sending IP for E3 | HIGH | Alert |
| Email address | security@outlook-protection[.]com | E3 | Sender used for Microsoft impersonation | HIGH | Block |
| URL | hxxps://outlook-protection[.]com/verify | E3 | Account-verification URL | HIGH | Block |
| Domain | medequip-supplies[.]net | E5 | Domain used in invoice/payment lure | HIGH | Block |
| IP | 185[.]176[.]43[.]22 | E5 | External sending IP for E5 | HIGH | Alert |
| Email address | invoices@medequip-supplies[.]net | E5 | Invoice sender address | HIGH | Block |
| URL | hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891 | E5 | Invoice payment URL | HIGH | Block |
| URL | hxxps://medequip-supplies[.]net/portal/login | E5 | Login URL associated with invoice lure | HIGH | Block |
| Infrastructure note | INV-2026-04891.pdf | E5 | PDF attachment name containing invoice lure metadata | MEDIUM | Alert |
| Domain | meddefense-benefits[.]org | E7 | MedDefense HR benefits lookalike domain | HIGH | Block |
| IP | 164[.]90[.]218[.]73 | E7 | External sending IP for E7 | HIGH | Alert |
| Email address | hr-notifications@meddefense-benefits[.]org | E7 | Sender used for HR benefits lure | HIGH | Block |
| URL | hxxps://meddefense-benefits[.]org/enroll | E7 | Benefits enrollment URL | HIGH | Block |
| Tool | PHPMailer 6.6.0 | E2, E3, E5, E7 | Shared sending software | MEDIUM | Monitor |
| Infrastructure note | Newly registered domains using portal, benefits, supplies or login | E8 | HC3 reported healthcare phishing pattern | MEDIUM | Monitor |
| Infrastructure note | Budget VPS hosting | E8 | HC3 reported campaign infrastructure pattern | LOW | Context only |
| Infrastructure note | Urgency and role-specific healthcare lures | E8 | HC3 reported social-engineering pattern | MEDIUM | Monitor |

## Attack Phase Categories

### Delivery

- noreply@meddefense-portal[.]com — E2
- security@outlook-protection[.]com — E3
- invoices@medequip-supplies[.]net — E5
- hr-notifications@meddefense-benefits[.]org — E7
- PHPMailer 6.6.0 — shared sending tool

### Credential Harvesting

- hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1
- hxxps://outlook-protection[.]com/verify
- hxxps://medequip-supplies[.]net/portal/login
- hxxps://meddefense-benefits[.]org/enroll

### Attachment or Lure Artifact

- INV-2026-04891.pdf
- hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891

### Infrastructure

- 91[.]234[.]99[.]107 — E2
- 51[.]38[.]42[.]17 — E3
- 185[.]176[.]43[.]22 — E5
- 164[.]90[.]218[.]73 — E7
- meddefense-portal[.]com
- outlook-protection[.]com
- medequip-supplies[.]net
- meddefense-benefits[.]org

### Context-Only Indicators

- Budget VPS hosting
- Newly registered domains using healthcare-related terms
- Urgency-based social engineering
- Role-specific targeting
- PHPMailer alone

## IOC Quality

High-confidence phishing domains, sender addresses and campaign URLs are suitable for blocking because they are directly associated with the suspicious emails in this evidence set.

Sending IPs are useful for alerting and investigation, but should be reviewed before broad blocking because infrastructure may be shared.

PHPMailer, budget VPS hosting, urgency, role targeting and generic domain keywords should not be used alone for blocking. Legitimate senders may share these characteristics, creating false positives.

## HC3-Ready Summary

- Domains: meddefense-portal[.]com, outlook-protection[.]com, medequip-supplies[.]net, meddefense-benefits[.]org
- IPs: 91[.]234[.]99[.]107, 51[.]38[.]42[.]17, 185[.]176[.]43[.]22, 164[.]90[.]218[.]73
- Senders: noreply@meddefense-portal[.]com, security@outlook-protection[.]com, invoices@medequip-supplies[.]net, hr-notifications@meddefense-benefits[.]org
- URLs: hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1; hxxps://outlook-protection[.]com/verify; hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891; hxxps://medequip-supplies[.]net/portal/login; hxxps://meddefense-benefits[.]org/enroll
- Shared pattern: PHPMailer-based delivery, urgency and role-specific healthcare lures.
