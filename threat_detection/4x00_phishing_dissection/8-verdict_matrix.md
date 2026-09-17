| Email | Initial Class | Final Class | Confidence | Key Evidence | Recommended Action |
|---|---|---|---|---|---|
| E1 | LEGITIMATE | LEGITIMATE | HIGH | SPF, DKIM and DMARC pass; subscribed newsletter context. | None; allow normal delivery. |
| E2 | SUSPICIOUS | PHISHING-TARGETED | HIGH | SPF and DMARC fail, DKIM absent, MedDefense lookalike domain, targeted portal-verification lure and confirmed click. | Reset password, revoke sessions, verify MFA and monitor account activity. |
| E3 | SUSPICIOUS | PHISHING-TARGETED | HIGH | Microsoft impersonation using outlook-protection.com; urgent account-verification lure. Authentication passes only for the lookalike domain. | Block the domain and alert affected users. |
| E4 | LEGITIMATE | LEGITIMATE | HIGH | Internal meddefense.com sender; SPF, DKIM and DMARC pass; internal password-change guidance. | None; allow normal delivery. |
| E5 | SUSPICIOUS | PHISHING-TARGETED | HIGH | SPF softfail, DKIM absent, DMARC fail, targeted invoice/payment lure, suspicious links and PDF attachment indicator. | Block the domain and investigate the invoice lure. |
| E6 | SPAM | SPAM | HIGH | Unsolicited pharmaceutical advertising, spam score 9.8, SPF softfail, DKIM absent and DMARC fail with quarantine action. | Quarantine or block as spam. |
| E7 | SUSPICIOUS | PHISHING-TARGETED | HIGH | SPF and DMARC fail, DKIM absent, MedDefense HR lookalike domain and targeted benefits-enrollment lure. | Block the domain and alert affected users. |
| E8 | LEGITIMATE | LEGITIMATE | HIGH | hhs.gov sender; SPF, DKIM and DMARC pass; HC3 sector security alert. | None; retain as legitimate security communication. |

## Classification Changes

- E2: SUSPICIOUS → PHISHING-TARGETED. Deeper analysis identified failed authentication, a MedDefense lookalike domain, targeted portal-verification content and a confirmed click.
- E3: SUSPICIOUS → PHISHING-TARGETED. Deeper analysis showed that authentication passes for outlook-protection.com, but the domain is not microsoft.com or outlook.com and is used to impersonate Microsoft.
- E5: SUSPICIOUS → PHISHING-TARGETED. Deeper analysis identified weak/failed authentication and a targeted Accounts Payable invoice/payment lure.
- E7: SUSPICIOUS → PHISHING-TARGETED. Deeper analysis identified failed authentication, a MedDefense HR lookalike domain and a targeted benefits-enrollment lure.

## Triage Accuracy Assessment

- Correct initial classifications: 8 of 8.
- Triage accuracy: 100%.
- E1, E4 and E8 remained legitimate.
- E6 remained spam.
- E2, E3, E5 and E7 were correctly flagged as suspicious during triage and were refined to PHISHING-TARGETED after deeper analysis.
