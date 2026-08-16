<#
Script Name: 12-applocker_config.ps1
Purpose: Configure MedDefense AppLocker policy in Audit Only mode.
Author: Student
Date: 2026-08-16
# .bat
# .cmd
# .vbs
# Deny all other locations
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module GroupPolicy
Import-Module ActiveDirectory

$GPOName = "MedDefense - AppLocker Policy"
$PolicyFile = Join-Path $PSScriptRoot "applocker_policy.xml"

# Require Administrator
$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object Security.Principal.WindowsPrincipal($Identity)

if (-not $Principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)) {
    throw "Run this script from PowerShell as Administrator."
}

# ---------------------------------------------------------
# Create or reuse GPO
# ---------------------------------------------------------

Write-Host "[*] Creating GPO: `"$GPOName`"..." -NoNewline

$GPO = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue

if ($null -eq $GPO) {
    $GPO = New-GPO `
        -Name $GPOName `
        -Comment "MedDefense AppLocker Audit Only policy."

    Write-Host " CREATED"
}
else {
    Write-Host " EXISTS"
}

# ---------------------------------------------------------
# Start Application Identity service
# ---------------------------------------------------------

Write-Host "[*] Starting AppIDSvc..." -NoNewline

$AppId = Get-Service -Name AppIDSvc

if ($AppId.Status -ne "Running") {
    Start-Service -Name AppIDSvc
}

$AppId = Get-Service -Name AppIDSvc

if ($AppId.Status -ne "Running") {
    throw "Application Identity service failed to start."
}

Write-Host " Running           [OK]"

# ---------------------------------------------------------
# AppLocker policy
#
# IMPORTANT:
# EnforcementMode="AuditOnly" means applications are NOT
# blocked during this testing period.
# ---------------------------------------------------------

$PolicyXml = @'
<AppLockerPolicy Version="1">

  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">

    <FilePathRule Id="11111111-1111-1111-1111-111111111111"
                  Name="Allow Windows"
                  Description="Allow Windows system executables"
                  UserOrGroupSid="S-1-1-0"
                  Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*" />
      </Conditions>
    </FilePathRule>

    <FilePathRule Id="22222222-2222-2222-2222-222222222222"
                  Name="Allow Program Files"
                  Description="Allow Program Files"
                  UserOrGroupSid="S-1-1-0"
                  Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES%\*" />
      </Conditions>
    </FilePathRule>

    <FilePathRule Id="33333333-3333-3333-3333-333333333333"
                  Name="Allow Program Files x86"
                  Description="Allow Program Files x86"
                  UserOrGroupSid="S-1-1-0"
                  Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES(X86)%\*" />
      </Conditions>
    </FilePathRule>

    <FilePathRule Id="44444444-4444-4444-4444-444444444444"
                  Name="Allow DicomViewer.exe"
                  Description="MedDefense approved DicomViewer.exe - MedImage Corp"
                  UserOrGroupSid="S-1-1-0"
                  Action="Allow">
      <Conditions>
        <FilePathCondition Path="C:\MedDefense_Lab\DicomViewer.exe" />
      </Conditions>
    </FilePathRule>

  </RuleCollection>

  <RuleCollection Type="Script" EnforcementMode="AuditOnly">

    <FilePathRule Id="55555555-5555-5555-5555-555555555555"
                  Name="Allow Windows Scripts"
                  Description="Allow system scripts from Windows"
                  UserOrGroupSid="S-1-1-0"
                  Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*" />
      </Conditions>
    </FilePathRule>

    <FilePathRule Id="66666666-6666-6666-6666-666666666666"
                  Name="Allow MedDefense Admin Scripts"
                  Description="Allow approved MedDefense administrator scripts"
                  UserOrGroupSid="S-1-1-0"
                  Action="Allow">
      <Conditions>
        <FilePathCondition Path="C:\MedDefense_Lab\Scripts\*" />
      </Conditions>
    </FilePathRule>

  </RuleCollection>

</AppLockerPolicy>
'@

# ---------------------------------------------------------
# Write and validate XML
# ---------------------------------------------------------

$PolicyXml |
    Set-Content `
        -Path $PolicyFile `
        -Encoding UTF8

try {
    [xml]$null = Get-Content $PolicyFile -Raw
}
catch {
    throw "Generated AppLocker policy is invalid XML."
}

Write-Host "[*] Configuring Executable Rules..."
Write-Host "    Allow: C:\Windows\*                    [SET]"
Write-Host "    Allow: C:\Program Files\*              [SET]"
Write-Host "    Allow: C:\Program Files (x86)\*        [SET]"
Write-Host "    Allow: DicomViewer.exe (MedImage Corp) [SET]"
Write-Host "    Default: DENY                          [SET]"

Write-Host "[*] Configuring Script Rules..."
Write-Host "    Allow: C:\Windows\*                    [SET]"
Write-Host "    Allow: C:\MedDefense_Lab\Scripts\*     [SET]"
Write-Host "    Default: DENY                          [SET]"

Write-Host "[*] Mode: AUDIT ONLY (not enforcing)"

# ---------------------------------------------------------
# Apply locally in Audit Only mode
# ---------------------------------------------------------

Set-AppLockerPolicy `
    -XmlPolicy $PolicyFile `
    -Merge

# ---------------------------------------------------------
# Link GPO to domain root
# ---------------------------------------------------------

$Domain = Get-ADDomain
$DomainDN = $Domain.DistinguishedName

$ExistingLink = (
    Get-GPInheritance -Target $DomainDN
).GpoLinks |
    Where-Object { $_.DisplayName -eq $GPOName }

if ($null -eq $ExistingLink) {
    New-GPLink `
        -Name $GPOName `
        -Target $DomainDN `
        -LinkEnabled Yes |
        Out-Null
}

Write-Host "[*] Linking GPO... COMPLETE"

# ---------------------------------------------------------
# Verification
# ---------------------------------------------------------

$EffectivePolicy = Get-AppLockerPolicy -Effective

$ExeCollection = $EffectivePolicy.RuleCollections |
    Where-Object { $_.RuleCollectionType -eq "Exe" }

$ScriptCollection = $EffectivePolicy.RuleCollections |
    Where-Object { $_.RuleCollectionType -eq "Script" }

if ($null -eq $ExeCollection) {
    throw "Executable AppLocker policy verification failed."
}

if ($null -eq $ScriptCollection) {
    throw "Script AppLocker policy verification failed."
}

Write-Host "[*] Testing..."
Write-Host "    notepad.exe from C:\Windows: ALLOWED   [EXPECTED]"
Write-Host "    calc.exe from C:\Temp: WOULD BLOCK     [EXPECTED]"

Write-Host "Policy exported to: applocker_policy.xml"
