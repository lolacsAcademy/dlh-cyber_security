## Email 1 — healthcare-education-weekly.com

- SPF: pass — the sending IP is authorized for healthcare-education-weekly.com.
- DKIM: pass — the message has a valid signature from healthcare-education-weekly.com.
- DMARC: pass, action=none — authentication aligns with the visible From domain.
- Authentication verdict: Supports apparent legitimacy.
- Investigation meaning: Authentication passes and is consistent with the newsletter sender. Verdict: LEGITIMATE.

## Email 2 — meddefense-portal.com

- SPF: fail — 91.234.99.107 is not authorized for meddefense-portal.com.
- DKIM: none — the message has no DKIM signature.
- DMARC: fail, action=none — authentication does not validate the visible From domain.
- Authentication verdict: Contradicts apparent legitimacy.
- Investigation meaning: Failed authentication supports the phishing indicators. Verdict: SUSPICIOUS.

## Email 3 — outlook-protection.com

- SPF: pass — 51.38.42.17 is authorized for outlook-protection.com.
- DKIM: pass — the message is signed by outlook-protection.com.
- DMARC: pass, action=none — authentication aligns with outlook-protection.com.
- Authentication verdict: Authentication validates the sending domain, but not the claimed Microsoft identity.
- Investigation meaning: outlook-protection.com is not the same as microsoft.com or outlook.com. A malicious lookalike domain can have correctly configured SPF, DKIM and DMARC. Verdict: SUSPICIOUS.

## Email 4 — meddefense.com

- SPF: pass — the internal sending IP is authorized for meddefense.com.
- DKIM: pass — the message is signed by meddefense.com.
- DMARC: pass, action=none — authentication aligns with the visible From domain.
- Authentication verdict: Supports apparent legitimacy.
- Investigation meaning: Authentication is consistent with legitimate internal MedDefense mail. Verdict: LEGITIMATE.

## Email 5 — medequip-supplies.net

- SPF: softfail — 185.176.43.22 is not clearly authorized for medequip-supplies.net.
- DKIM: none — the message has no DKIM signature.
- DMARC: fail, action=none — authentication does not validate the visible From domain.
- Authentication verdict: Contradicts apparent legitimacy.
- Investigation meaning: Weak and failed authentication supports suspicion of the invoice email. Verdict: SUSPICIOUS.

## Email 6 — canadian-pharma-discount.org

- SPF: softfail — the sender is not clearly authorized for canadian-pharma-discount.org.
- DKIM: none — the message has no DKIM signature.
- DMARC: fail, action=quarantine — DMARC failed and the header indicates quarantine.
- Authentication verdict: Contradicts apparent legitimacy.
- Investigation meaning: Authentication failures support the identification of this unsolicited bulk message as spam. Verdict: SPAM.

## Email 7 — meddefense-benefits.org

- SPF: fail — 164.90.218.73 is not authorized for meddefense-benefits.org.
- DKIM: none — the message has no DKIM signature.
- DMARC: fail, action=none — authentication does not validate the visible From domain.
- Authentication verdict: Contradicts apparent legitimacy.
- Investigation meaning: Failed authentication supports the lookalike-domain phishing indicators. Verdict: SUSPICIOUS.

## Email 8 — hhs.gov

- SPF: pass — 134.174.47.82 is authorized for hhs.gov.
- DKIM: pass — the message is signed by hhs.gov.
- DMARC: pass, action=none — authentication aligns with the visible From domain.
- Authentication verdict: Supports apparent legitimacy.
- Investigation meaning: Authentication is consistent with the claimed HHS/HC3 sender. Verdict: LEGITIMATE.
