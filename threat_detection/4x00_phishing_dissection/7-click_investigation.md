## Click Investigation — Diane Marsh / WS-NURSE-04

### Confirmed Facts

- User: Diane Marsh
- Workstation: WS-NURSE-04
- Workstation IP: 10.10.2.15
- Email: E2
- Domain: meddefense-portal.com
- Click timestamp: 2026-04-14 15:02:33 CDT

### Key Unknowns

- Whether credentials were entered.
- Whether any file was downloaded.
- Whether any process or script executed.
- Whether the account was used after the click.
- Whether MFA was triggered or approved.

### Risk Assessment

E2 contains a portal verification link designed to request account verification. A reported click creates a risk of credential exposure, but the available evidence does not confirm that credentials were entered or that compromise occurred.

### Endpoint Checks To Perform

If endpoint logs become available, check:

- Browser history around the click timestamp.
- Downloaded files.
- File creation.
- Process execution.
- PowerShell or cmd activity.

### Account Checks To Perform

If identity logs become available, check:

- Failed and successful logons.
- Logons from unusual sources.
- Unexpected MFA prompts or approvals.
- Password changes.
- New or modified inbox rules.
- Group membership changes.

### Decision Matrix

| Outcome | Evidence |
|---|---|
| No compromise found | No credential exposure or suspicious endpoint/account activity identified. |
| Possible credential exposure | Evidence suggests credentials may have been entered, but unauthorized use is not confirmed. |
| Confirmed compromise | Unauthorized login, credential use, malicious execution or unauthorized account changes are confirmed. |

### Recommended Containment

- Interview the user about actions taken after the click.
- Reset the user's password.
- Revoke active sessions and authentication tokens.
- Verify or re-register MFA if credential exposure is suspected.
- Monitor for suspicious authentication activity.
- Review the workstation if endpoint evidence becomes available.

### Conclusion

The click on E2 is confirmed. The available evidence does not establish whether credential exposure or account compromise occurred. Endpoint and identity evidence are required for a final determination.
