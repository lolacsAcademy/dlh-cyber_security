## Click Investigation — Diane Marsh / WS-NURSE-04

### Confirmed Facts

- User: Diane Marsh
- Workstation: WS-NURSE-04
- Workstation IP: 10.10.2.15
- Email: E2
- Phishing domain: meddefense-portal.com
- URL: hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1
- Click timestamp: 2026-04-14 15:02:33 CDT
- Related sending IP: 91.234.99.107
- E2 uses a credential-verification pretext and failed SPF and DMARC.

### Key Unknowns

- Whether credentials were entered.
- Whether any file was downloaded.
- Whether any process or script executed.
- Whether the account was used after the click.
- Whether MFA was triggered or approved.

### Risk Assessment

The reported click is high risk because E2 directs the user to a suspicious credential-verification portal. A click alone does not confirm compromise, but credential exposure or further activity may have occurred.

### Endpoint Checks To Perform

If endpoint logs are available, check:

- Browser history around the click timestamp.
- Downloaded files.
- New file creation.
- Process execution after the click.
- PowerShell or cmd activity.

### Account Checks To Perform

If identity logs are available, check:

- Failed and successful logons.
- Logons from unusual IP addresses or locations.
- Unexpected MFA prompts or approvals.
- Password changes.
- New or modified inbox rules.
- Group membership or privilege changes.

### Decision Matrix

| Outcome | Evidence |
|---|---|
| No compromise found | Click confirmed, but no credential entry or suspicious endpoint/account activity found. |
| Possible credential exposure | Credential entry is possible or suspicious authentication activity exists, but compromise is not confirmed. |
| Confirmed compromise | Evidence shows credential use, unauthorized login, malicious execution or unauthorized account changes. |

### Recommended Containment

- Interview the user about what happened after the click.
- Reset the user's password.
- Revoke active sessions and authentication tokens.
- Re-register or verify MFA if credential exposure is suspected.
- Monitor the account for suspicious logins and changes.
- Review the workstation if endpoint evidence becomes available.

### Conclusion

The click on E2 is confirmed, but compromise is not confirmed by the available evidence. Treat the event as high risk and perform endpoint and identity follow-up checks before determining the final outcome.
