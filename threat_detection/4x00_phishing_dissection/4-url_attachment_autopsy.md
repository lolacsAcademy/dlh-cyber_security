## Indicator 1

- Source email: E2
- Original value: https://meddefense-portal.com/verify/staff?id=dmarsh&token=a8f3e2d1
- Defanged value: hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1
- Domain or IP: meddefense-portal.com
- Indicator type: URL / lookalike domain
- Evidence from email: MedDefense impersonation, urgent verification request, SPF fail, DKIM none and DMARC fail.
- Safe investigation method: Passive WHOIS, DNS record review, VirusTotal or urlscan.io reputation lookup using the domain indicator.
- Finding: The evidence shows a lookalike MedDefense domain used for a staff portal verification lure.
- Risk rating: HIGH

## Indicator 2

- Source email: E3
- Original value: https://outlook-protection.com/verify
- Defanged value: hxxps://outlook-protection[.]com/verify
- Domain or IP: outlook-protection.com
- Indicator type: URL / lookalike domain
- Evidence from email: The message impersonates Microsoft Account Protection and requests account verification.
- Safe investigation method: Passive WHOIS, DNS record review, VirusTotal or urlscan.io reputation lookup using the domain indicator.
- Finding: Authentication passes for outlook-protection.com, but the domain is not microsoft.com or outlook.com and is used in a Microsoft impersonation lure.
- Risk rating: HIGH

## Indicator 3

- Source email: E5
- Original value: https://medequip-supplies.net/invoices/pay?id=INV-2026-04891
- Defanged value: hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891
- Domain or IP: medequip-supplies.net
- Indicator type: URL / payment portal
- Evidence from email: Invoice payment request for USD 24,716.38, payment deadline, SPF softfail, DKIM none and DMARC fail.
- Safe investigation method: Passive WHOIS, DNS record review, VirusTotal or urlscan.io reputation lookup using the domain indicator.
- Finding: The domain is used in a suspicious invoice and payment lure.
- Risk rating: HIGH

## Indicator 4

- Source email: E5
- Original value: https://medequip-supplies.net/portal/login
- Defanged value: hxxps://medequip-supplies[.]net/portal/login
- Domain or IP: medequip-supplies.net
- Indicator type: URL / login portal
- Evidence from email: The recipient is directed to a login portal if the invoice cannot be viewed.
- Safe investigation method: Passive WHOIS, DNS record review, VirusTotal or urlscan.io reputation lookup using the domain indicator.
- Finding: The login URL appears within the same suspicious invoice lure.
- Risk rating: HIGH

## Indicator 5

- Source email: E5
- Original value: INV-2026-04891.pdf
- Defanged value: N/A
- Domain or IP: N/A
- Indicator type: PDF attachment
- Evidence from email: The raw evidence contains a base64-encoded PDF named INV-2026-04891.pdf and visible metadata referencing the invoice payment URL.
- Safe investigation method: Offline metadata review and hash/reputation lookup through an isolated analysis service.
- Finding: The attachment indicator supports the suspicious invoice/payment pretext.
- Risk rating: HIGH

## Indicator 6

- Source email: E7
- Original value: https://meddefense-benefits.org/enroll
- Defanged value: hxxps://meddefense-benefits[.]org/enroll
- Domain or IP: meddefense-benefits.org
- Indicator type: URL / lookalike domain
- Evidence from email: MedDefense HR impersonation, enrollment deadline, SPF fail, DKIM none and DMARC fail.
- Safe investigation method: Passive WHOIS, DNS record review, VirusTotal or urlscan.io reputation lookup using the domain indicator.
- Finding: The evidence shows a lookalike MedDefense domain used for an urgent benefits-enrollment lure.
- Risk rating: HIGH

## Indicator 7

- Source email: E6
- Original value: http://203.0.113.228/shop?ref=pwhite
- Defanged value: hxxp://203[.]0[.]113[.]228/shop?ref=pwhite
- Domain or IP: 203.0.113.228
- Indicator type: IP-based URL
- Evidence from email: The URL appears in unsolicited pharmaceutical advertising with SPF softfail, DKIM none, DMARC fail with quarantine action and a spam score of 9.8.
- Safe investigation method: Passive WHOIS and reputation lookup using the IP indicator.
- Finding: The raw-IP URL and email evidence support the SPAM classification.
- Risk rating: MEDIUM
