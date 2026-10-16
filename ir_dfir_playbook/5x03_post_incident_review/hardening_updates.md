
# Hardening Updates: IR-2026-0414-01

## HRD-001: PowerShell Constrained Language Mode

**Control:** Restrict PowerShell scripting capabilities for non-administrative workstation users.

**Configuration:**
- GPO: Computer Configuration > Preferences > Windows Settings > Registry
- Key: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`
- Value: `__PSLockdownPolicy`
- Type: `REG_SZ`
- Data: `4`
- Production enforcement: Use Windows Defender Application Control (WDAC/App Control for Business) with user-mode code integrity enabled. Do not rely on `__PSLockdownPolicy` as a security boundary; it is a testing mechanism.
- Scope: Non-administrative accounts on clinical and administrative workstations. Validate administrative and service-account exceptions.

**Effect:** Constrained Language Mode restricts arbitrary .NET type access and unsupported script-block operations, including `[System.Management.Automation.ScriptBlock]::Create`, reducing PowerShell-based LOLBin abuse. It does not independently prevent MSBuild execution.

**Evidence:** ART-002-M01 confirms `powershell.exe` launched `MSBuild.exe` on WST-WS-031.

**Closes:** GAP-005.

**Validation:** Run `$ExecutionContext.SessionState.LanguageMode` as a standard user; expect `ConstrainedLanguage`. Confirm enforcement remains active after attempts to change the environment variable.

---

## HRD-002: AppLocker Rule Restricting MSBuild.exe

**Control:** Restrict MSBuild execution to authorized administrators and named CI/CD service accounts.

**Configuration:**
- GPO: Computer Configuration > Policies > Windows Settings > Security Settings > Application Control Policies > AppLocker > Executable Rules
- Create explicit Allow rules for `BUILTIN\Administrators` and individually approved CI/CD service accounts.
- Use a publisher or file-hash condition identifying the approved Microsoft-signed `MSBuild.exe`.
- Remove or replace any broad default executable Allow rule that would otherwise permit standard users to execute MSBuild.
- Enable executable rule enforcement rather than audit-only mode.
- Maintain separate rules for each approved MSBuild installation path/version.

**Rule XML structure (illustrative):**

```xml
<RuleCollection Type="Exe" EnforcementMode="Enabled">
  <FilePublisherRule
    Id="11111111-1111-4111-8111-111111111111"
    Name="Allow approved MSBuild - Administrators"
    Description="Restricted MSBuild execution"
    UserOrGroupSid="S-1-5-32-544"
    Action="Allow">
    <Conditions>
      <FilePublisherCondition
        PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US"
        ProductName="*"
        BinaryName="MSBuild.exe">
        <BinaryVersionRange LowSection="0.0.0.0"
                           HighSection="*" />
      </FilePublisherCondition>
    </Conditions>
  </FilePublisherRule>
</RuleCollection>
```

- Add equivalent rules using the actual SIDs of named CI/CD service accounts.
- Generate production XML from verified file publisher metadata; the example is not a deployment-ready policy.
- Test other executable rules to ensure legitimate workstation applications remain permitted.

**Effect:** Prevents unapproved users from executing MSBuild as a trusted developer utility.

**Evidence:** ART-002-M01 confirms PowerShell launched MSBuild; ART-001-E01 confirms MSBuild execution.

**Closes:** GAP-005.

**Validation:** Run `MSBuild.exe` as a standard user and confirm execution is denied; repeat using an approved CI/CD account and confirm execution is permitted.

---

## HRD-003: Conditional Access for VPN Authentication

**Control:** Restrict VPN authentication from unfamiliar or unapproved geographical locations.

**Configuration:**
- Identity platform: Microsoft Entra ID Conditional Access, integrated with the VPN authentication provider.
- Scope: All VPN users, with separately controlled emergency-access exclusions.
- Create named locations for approved countries.
- Block VPN sign-ins originating from countries outside the approved list.
- For unfamiliar but permitted locations, require phishing-resistant MFA or another approved step-up authentication method.
- Evaluate the account's successful sign-in geography over the previous 30 days using identity risk data or a custom policy integration.
- Do not assume standard Entra Conditional Access provides a native per-account 30-day country-history condition.
- Remove any compliant-device exception that suppresses sign-in risk evaluation.
- Enable sign-in risk alerts and review policy results before enforcement.
- Begin in report-only mode, then deploy after confirming legitimate VPN access is unaffected.

**Policy logic:**

1. VPN authentication request received.
2. Determine source IP and associated country.
3. If country is prohibited, block authentication.
4. If country is permitted but absent from the account's previous 30-day successful sign-in history, require step-up MFA.
5. If sign-in risk is high, block or escalate according to organizational policy.
6. Record the decision in authentication and conditional access logs.

**Effect:** Reduces the likelihood of stolen credentials being used for foreign-origin VPN access.

**Evidence:** Suspicious authentication from `45.63.9.88` (RU); forensic open item documents suppressed Azure AD risk signals.

**Closes:** GAP-003, GAP-004.

**Validation:** Simulate a VPN sign-in from an unapproved country and confirm it is blocked; verify an unfamiliar permitted country triggers step-up MFA and appears in sign-in logs.

---

## HRD-004: Windows Credential Guard

**Control:** Enable virtualization-based credential isolation and protect LSASS.

**Configuration:**
- GPO: Computer Configuration > Administrative Templates > System > Device Guard > Turn On Virtualization Based Security
- Enable virtualization-based security.
- Set Credential Guard Configuration to `Enabled with UEFI lock` where operationally appropriate.
- Alternatively, use `Enabled without lock` when remote policy removal is required.
- Registry configuration:
  - `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard`
  - `EnableVirtualizationBasedSecurity` = `1` (`REG_DWORD`)
  - `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`
  - `LsaCfgFlags` = `1` for UEFI lock, or `2` without lock (`REG_DWORD`)
- Enable LSASS protected-process settings as a complementary control.
- Confirm UEFI, Secure Boot, virtualization extensions, and platform compatibility before deployment.

**Supported platforms:** Compatible Windows 10 Enterprise/Education and Windows 11 Enterprise/Education devices, and supported Windows Server editions such as Windows Server 2016 and later, subject to edition, version, hardware, and deployment requirements. Windows 11 Pro support varies by version and configuration.

**Effect:** Credential Guard uses virtualization-based security to isolate supported credential secrets from the normal operating system. It reduces exposure to LSASS credential theft but does not protect every credential type or eliminate all credential-dumping techniques.

**Evidence:** ART-002-M04 confirms NTLM hash material for the compromised account was present in LSASS memory.

**Closes:** GAP-008.

**Validation:** Run `Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard` and confirm Credential Guard is listed among running security services.
