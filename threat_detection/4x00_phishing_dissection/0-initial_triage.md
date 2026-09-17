| Email | From | Subject | SPF | DKIM | DMARC | Class | Priority | Evidence |
|---|---|---|---|---|---|---|---|---|
| E1 | newsletter@healthcare-education-weekly.com | Your April newsletter: Medication reconciliation best practices | pass | pass | pass | LEGITIMATE | P4-LOW | Authentication passes; normal subscribed newsletter. |
| E2 | noreply@meddefense-portal.com | ACTION REQUIRED: Portal re-verification needed within 24 hours | fail | none | fail | SUSPICIOUS | P1-URGENT | Failed authentication, lookalike domain, urgent verification link; user clicked. |
| E3 | security@outlook-protection.com | Unusual sign-in activity detected on your Microsoft 365 account | pass | pass | pass | SUSPICIOUS | P2-HIGH | Lookalike domain, urgent account-verification link and lockout threat. |
| E4 | it-announcements@meddefense.com | Reminder: Quarterly password change window opens April 20 | pass | pass | pass | LEGITIMATE | P4-LOW | Internal sender, authentication passes, directs staff to internal portal. |
| E5 | invoices@medequip-supplies.net | Invoice INV-2026-04891 — Payment required within 7 days | softfail | none | fail | SUSPICIOUS | P2-HIGH | Failed DMARC, no DKIM, payment urgency, links and PDF attachment. |
| E6 | deals@canadian-pharma-discount.org | 90% OFF Viagra, Cialis, Xanax — No prescription needed!!! | softfail | none | fail | SPAM | P4-LOW | Unsolicited bulk drug advertising; high spam score and failed DMARC. |
| E7 | hr-notifications@meddefense-benefits.org | Open Enrollment closes TOMORROW — action required | fail | none | fail | SUSPICIOUS | P2-HIGH | Failed authentication, lookalike domain, urgent enrollment link. |
| E8 | HC3@hhs.gov | [HC3 ALERT — TLP:CLEAR] Active phishing campaign targeting regional healthcare | pass | pass | pass | LEGITIMATE | P3-MEDIUM | Authentication passes; trusted-sector HC3 security alert. |

## Triage Summary

- SPAM: E6
- SUSPICIOUS: E2, E3, E5, E7
- LEGITIMATE: E1, E4, E8
- Highest priority: E2 (P1-URGENT — user clicked the link)
