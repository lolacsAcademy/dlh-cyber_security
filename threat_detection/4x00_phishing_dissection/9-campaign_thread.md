## Campaign Thread Analysis

### Shared Indicators

- E2, E5 and E7 use external domains designed around trusted business themes.
- All three were sent using PHPMailer 6.6.0.
- All three use X-Priority: 1 (Highest).
- E2 and E7 use MedDefense-related lookalike domains.
- All three use urgency or consequences to pressure the recipient.
- Each email uses a role-specific business process lure.
- E2 and E7 fail SPF and DMARC with no DKIM; E5 has SPF softfail, no DKIM and DMARC fail.

### Targeting Map

| Email | Target | Lure |
|---|---|---|
| E2 | Clinical staff | Staff portal verification |
| E5 | Accounts Payable / finance | Medical supplies invoice and payment |
| E7 | HR / benefits-related staff | Benefits enrollment |

### Timing Map

| Email | Date | Evidence |
|---|---|---|
| E2 | April 14, 2026 | Delivered to Diane Marsh |
| E5 | April 16, 2026 | Delivered to Angela Rivera |
| E7 | April 16, 2026 | Delivered to Linda Patterson |

The three emails occurred within the same short collection window, with E5 and E7 delivered on April 16.

### Comparison With HC3 Alert

Email 8 reports an active healthcare-sector phishing pattern involving:

- Lookalike domains using terms such as portal, benefits and supplies.
- PHPMailer-based sending infrastructure.
- Urgency-based social engineering.
- Role-specific targeting of clinical, billing and HR recipients.
- Credential harvesting as the reported primary objective.

E2, E5 and E7 match several of these observed patterns: lookalike or business-themed domains, PHPMailer, urgency and role-specific healthcare targeting.

### Attribution Assessment

The similarities support an assessment that E2, E5 and E7 may be related to the same coordinated phishing campaign. Email 8 provides independent sector-level context consistent with these patterns.

However, the available evidence does not prove a specific threat actor or establish that the three emails were operated by the same individual or group. Shared techniques and timing alone are not sufficient for definitive actor attribution.

### Conclusion

The evidence supports with high confidence that E2, E5 and E7 are consistent with a single coordinated healthcare phishing campaign. This conclusion is based on their close timing, shared PHPMailer tooling, urgency, role-specific targeting and related domain themes. Attribution to a specific actor cannot be proven from the available evidence.
