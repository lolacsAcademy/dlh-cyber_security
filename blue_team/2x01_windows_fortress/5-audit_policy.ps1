<#
Script Name: 5-audit_policy.ps1
Purpose: Configure MedDefense advanced Windows auditing and Security log settings.
Author: Student
Date: 2026-08-15
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory
Import-Module GroupPolicy

$GPOName = "MedDefense - Advanced Audit Policy"

$Domain = Get-ADDomain
$DomainDN = $Domain.DistinguishedName

# Require Administrator privileges
$CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object Security.Principal.WindowsPrincipal($CurrentUser)

if (-not $Principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)) {
    throw "Run this script from PowerShell as Administrator."
}

# ---------------------------------------------------------
# Create GPO
# ---------------------------------------------------------

Write-Host "[*] Creating GPO: `"$GPOName`"..." -NoNewline

$ExistingGPO = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue

if ($null -eq $ExistingGPO) {
    $GPO = New-GPO -Name $GPOName `
        -Comment "MedDefense advanced audit and Security log policy."
}
else {
    $GPO = $ExistingGPO
}

Write-Host " CREATED"

# ---------------------------------------------------------
# Configure Advanced Audit Policy
# ---------------------------------------------------------

Write-Host "[*] Configuring Audit Categories..."

& auditpol.exe /set /subcategory:"Credential Validation" /success:enable /failure:enable | Out-Null
Write-Host "    Credential Validation:    Success, Failure   [SET]"

& auditpol.exe /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable | Out-Null
Write-Host "    Kerberos Authentication:  Success, Failure   [SET]"

& auditpol.exe /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
Write-Host "    Logon:                    Success, Failure   [SET]"

& auditpol.exe /set /subcategory:"Logoff" /success:enable /failure:disable | Out-Null
Write-Host "    Logoff:                   Success            [SET]"

& auditpol.exe /set /subcategory:"Special Logon" /success:enable /failure:disable | Out-Null
Write-Host "    Special Logon:            Success            [SET]"

& auditpol.exe /set /subcategory:"User Account Management" /success:enable /failure:enable | Out-Null
Write-Host "    User Account Management:  Success, Failure   [SET]"

& auditpol.exe /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable | Out-Null
Write-Host "    Sensitive Privilege Use:  Success, Failure   [SET]"

& auditpol.exe /set /subcategory:"File System" /success:enable /failure:enable | Out-Null
Write-Host "    File System:              Success, Failure   [SET]"

& auditpol.exe /set /subcategory:"Registry" /success:enable /failure:enable | Out-Null
Write-Host "    Registry:                 Success, Failure   [SET]"

& auditpol.exe /set /subcategory:"Process Creation" /success:enable /failure:disable | Out-Null
Write-Host "    Process Creation:         Success            [SET]"

# ---------------------------------------------------------
# Force advanced audit policy over legacy/basic policy
# ---------------------------------------------------------

Set-GPRegistryValue `
    -Name $GPOName `
    -Key "HKLM\System\CurrentControlSet\Control\Lsa" `
    -ValueName "SCENoApplyLegacyAuditPolicy" `
    -Type DWord `
    -Value 1

# ---------------------------------------------------------
# Enable command line in Event ID 4688
# ---------------------------------------------------------

Write-Host "[*] Enabling command-line in process creation events..." -NoNewline

Set-GPRegistryValue `
    -Name $GPOName `
    -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    -ValueName "ProcessCreationIncludeCmdLine_Enabled" `
    -Type DWord `
    -Value 1

Write-Host "   [SET]"

# ---------------------------------------------------------
# Security log access
# Keep SYSTEM and Administrators; Domain Admins are included
# through administrative access.
# ---------------------------------------------------------

Write-Host "[*] Restricting Security log clearing..." -NoNewline

$SecurityLogSDDL = "O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)"

Set-GPRegistryValue `
    -Name $GPOName `
    -Key "HKLM\System\CurrentControlSet\Services\EventLog\Security" `
    -ValueName "CustomSD" `
    -Type String `
    -Value $SecurityLogSDDL

Write-Host "                  [SET]"

# ---------------------------------------------------------
# Security log maximum size = 1 GB
# 1 GB = 1073741824 bytes
# ---------------------------------------------------------

Write-Host "[*] Setting Security log max size to 1 GB..." -NoNewline

Set-GPRegistryValue `
    -Name $GPOName `
    -Key "HKLM\System\CurrentControlSet\Services\EventLog\Security" `
    -ValueName "MaxSize" `
    -Type DWord `
    -Value 1073741824

Write-Host "              [SET]"

# ---------------------------------------------------------
# Link GPO
# ---------------------------------------------------------

$Inheritance = Get-GPInheritance -Target $DomainDN

$AlreadyLinked = $Inheritance.GpoLinks |
    Where-Object { $_.DisplayName -eq $GPOName }

if ($null -eq $AlreadyLinked) {
    New-GPLink `
        -Name $GPOName `
        -Target $DomainDN `
        -LinkEnabled Yes |
        Out-Null
}

# ---------------------------------------------------------
# Force Group Policy update
# ---------------------------------------------------------

Write-Host "[*] Linking GPO and forcing update..." -NoNewline

& gpupdate.exe /force | Out-Null

if ($LASTEXITCODE -ne 0) {
    throw "Group Policy update failed."
}

Write-Host " COMPLETE"

# ---------------------------------------------------------
# Verify effective audit policy
# ---------------------------------------------------------

Write-Host ""
Write-Host "[*] Verifying effective Advanced Audit Policy..."

& auditpol.exe /get /category:*
