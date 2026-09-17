## Email 2 — meddefense-portal.com

### Header Evidence

- From: noreply@meddefense-portal.com
- Return-Path: noreply@meddefense-portal.com
- Sending IP: 91.234.99.107
- X-Mailer: PHPMailer 6.6.0
- Message-ID: <PHP-5D7E2F4A@meddefense-portal.com>

### Received Chain Summary

1. Message generated through PHPMailer on mail.meddefense-portal.com.
2. External server 91.234.99.107 sent the message to mx01.meddefense.com.
3. mx01.meddefense.com passed it to the MedDefense inbound relay.

### Anomalies

- [HIGH] SPF and DMARC fail; DKIM is absent.
- [HIGH] Lookalike meddefense-portal.com domain impersonates MedDefense.
- [MEDIUM] PHPMailer used on external infrastructure.

### Conclusion

Headers strongly support a phishing classification. The sender is not authenticated as legitimate MedDefense infrastructure.

## Email 3 — outlook-protection.com

### Header Evidence

- From: security@outlook-protection.com
- Return-Path: security@outlook-protection.com
- Sending IP: 51.38.42.17
- X-Mailer: PHPMailer 6.6.0
- Message-ID: <PHP-9F2D7E1B@outlook-protection.com>

### Received Chain Summary

1. Message generated through PHPMailer on mail.outlook-protection.com.
2. External server 51.38.42.17 sent the message to mx01.meddefense.com.
3. mx01.meddefense.com passed it to the MedDefense inbound relay.

### Anomalies

- [HIGH] Sender claims Microsoft Account Protection but uses outlook-protection.com, not a Microsoft domain.
- [HIGH] Sending infrastructure belongs to the lookalike domain rather than Microsoft.
- [MEDIUM] PHPMailer used despite the message presenting itself as Microsoft communication.
- [MEDIUM] SPF, DKIM and DMARC pass only for outlook-protection.com.

### Conclusion

Authentication passes for the lookalike domain, but it does not prove the sender is Microsoft. The headers support suspicion of impersonation.

## Email 5 — medequip-supplies.net

### Header Evidence

- From: invoices@medequip-supplies.net
- Return-Path: invoices@medequip-supplies.net
- Sending IP: 185.176.43.22
- X-Mailer: PHPMailer 6.6.0
- Message-ID: <PHP-7C2D4E1A@medequip-supplies.net>

### Received Chain Summary

1. Message generated through PHPMailer on mail.medequip-supplies.net.
2. External server 185.176.43.22 sent the message to mx01.meddefense.com.
3. mx01.meddefense.com passed it to the MedDefense inbound relay.

### Anomalies

- [HIGH] DMARC fails and DKIM is absent.
- [MEDIUM] SPF returns softfail for the sending IP.
- [MEDIUM] External PHPMailer infrastructure is used for a payment request.

### Conclusion

The authentication failures and sending infrastructure support a suspicious classification.

## Email 7 — meddefense-benefits.org

### Header Evidence

- From: hr-notifications@meddefense-benefits.org
- Return-Path: hr-notifications@meddefense-benefits.org
- Sending IP: 164.90.218.73
- X-Mailer: PHPMailer 6.6.0
- Message-ID: <PHP-2E4A7B1C@meddefense-benefits.org>

### Received Chain Summary

1. Message generated through PHPMailer on mail.meddefense-benefits.org.
2. External server 164.90.218.73 sent the message to mx01.meddefense.com.
3. mx01.meddefense.com passed it to the MedDefense inbound relay.

### Anomalies

- [HIGH] SPF and DMARC fail; DKIM is absent.
- [HIGH] meddefense-benefits.org is an external lookalike domain impersonating MedDefense HR.
- [MEDIUM] PHPMailer used on external infrastructure.

### Conclusion

The failed authentication and lookalike sending infrastructure strongly support a phishing classification.
