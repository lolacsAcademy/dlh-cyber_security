<#
Script Name: 7-auth_hardening.ps1
Purpose: Harden Kerberos and Windows authentication for the MedDefense domain.
Author: Student
Date: 2026-08-15
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory

# ---------------------------------------------------------
# Require Administrator
# ---------------------------------------------------------

$CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object Security.Principal.WindowsPrincipal($CurrentUser)

if (-not $Principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)) {
    throw "Run this script from PowerShell as Administrator."
}

# ---------------------------------------------------------
# Current Kerberos configuration
# ---------------------------------------------------------

$KdcPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc"
$KerberosValueName = "DefaultDomainSupportedEncTypes"

Write-Host "[*] Current Kerberos encryption configuration..."

$CurrentEnc = Get-ItemProperty `
    -Path $KdcPath `
    -Name $KerberosValueName `
    -ErrorAction SilentlyContinue

if ($null -eq $CurrentEnc) {
    Write-Host "    Current Kerberos types: system/default configuration"
}
else {
    Write-Host "    DefaultDomainSupportedEncTypes: $($CurrentEnc.$KerberosValueName)"
}

Write-Host "    [!] Checking for DES and RC4 support"

# ---------------------------------------------------------
# Find service accounts and DES flag
# ---------------------------------------------------------

Write-Host "[*] Accounts with DES flag..."

$ServiceAccounts = @(
    Get-ADUser `
        -LDAPFilter "(servicePrincipalName=*)" `
        -Properties ServicePrincipalName,
                    UseDESKeyOnly,
                    msDS-SupportedEncryptionTypes
)

$DESAccounts = @(
    $ServiceAccounts |
        Where-Object { $_.UseDESKeyOnly -eq $true }
)

if ($DESAccounts.Count -eq 0) {
    Write-Host "    No service accounts with UseDESKeyOnly = True"
}
else {
    foreach ($Account in $DESAccounts) {
        Write-Host "    $($Account.SamAccountName): UseDESKeyOnly = True          [!]"
    }
}

# ---------------------------------------------------------
# Display SPNs
# ---------------------------------------------------------

Write-Host "[*] Service Principal Names..."

foreach ($Account in $ServiceAccounts) {

    foreach ($SPN in $Account.ServicePrincipalName) {
        Write-Host "    $($Account.SamAccountName): $SPN"
    }
}

if ($ServiceAccounts.Count -gt 0) {
    Write-Host "    [!] SPN accounts are Kerberoasting targets"
}

# ---------------------------------------------------------
# Remediation
# ---------------------------------------------------------

Write-Host "[*] Remediating..."

foreach ($Account in $DESAccounts) {

    Write-Host "    $($Account.SamAccountName): Clearing DES flag..." -NoNewline

    Set-ADAccountControl `
        -Identity $Account.DistinguishedName `
        -UseDESKeyOnly $false

    Write-Host "              [DONE]"
}

# ---------------------------------------------------------
# Kerberos AES128 + AES256 only
#
# 0x18 = AES128 + AES256
# ---------------------------------------------------------

if (-not (Test-Path $KdcPath)) {
    New-Item -Path $KdcPath -Force | Out-Null
}

New-ItemProperty `
    -Path $KdcPath `
    -Name "DefaultDomainSupportedEncTypes" `
    -PropertyType DWord `
    -Value 0x18 `
    -Force |
    Out-Null

Write-Host "    Supported encryption: AES128 + AES256   [SET]"

# ---------------------------------------------------------
# Disable NTLMv1
#
# LmCompatibilityLevel 5 =
# Send NTLMv2 only; refuse LM and NTLM
# ---------------------------------------------------------

$LsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

New-ItemProperty `
    -Path $LsaPath `
    -Name "LmCompatibilityLevel" `
    -PropertyType DWord `
    -Value 5 `
    -Force |
    Out-Null

Write-Host "    NTLMv1: Refused (LmCompatibilityLevel=5) [SET]"

# ---------------------------------------------------------
# Credential Guard awareness
#
# Check capability/status only.
# Do NOT force VBS/Credential Guard inside the VM.
# ---------------------------------------------------------

Write-Host "[*] Credential Guard awareness..."

try {

    $DeviceGuard = Get-CimInstance `
        -ClassName Win32_DeviceGuard `
        -Namespace root\Microsoft\Windows\DeviceGuard `
        -ErrorAction Stop

    $CredentialGuardRunning =
        $DeviceGuard.SecurityServicesRunning -contains 1

    if ($CredentialGuardRunning) {
        Write-Host "    Credential Guard: Running              [OK]"
    }
    else {
        Write-Host "    Credential Guard: Available/not running [INFO]"
    }
}
catch {
    Write-Host "    Credential Guard status unavailable on this VM [INFO]"
}

# ---------------------------------------------------------
# Verification
# ---------------------------------------------------------

Write-Host "[*] Verifying..."

$VerifiedKerberos = (
    Get-ItemProperty `
        -Path $KdcPath `
        -Name "DefaultDomainSupportedEncTypes"
).DefaultDomainSupportedEncTypes

if ($VerifiedKerberos -eq 0x18) {
    Write-Host "    Kerberos: AES128, AES256 only           [VERIFIED]"
}
else {
    throw "Kerberos encryption verification failed."
}

$VerifiedNTLM = (
    Get-ItemProperty `
        -Path $LsaPath `
        -Name "LmCompatibilityLevel"
).LmCompatibilityLevel

if ($VerifiedNTLM -eq 5) {
    Write-Host "    NTLM: v2 only                           [VERIFIED]"
}
else {
    throw "NTLM configuration verification failed."
}

# Verify DES flags again
$RemainingDES = @(
    Get-ADUser `
        -Filter * `
        -Properties UseDESKeyOnly |
        Where-Object { $_.UseDESKeyOnly -eq $true }
)

if ($RemainingDES.Count -eq 0) {
    Write-Host "    DES account flags: none                 [VERIFIED]"
}
else {
    Write-Host "    DES account flags still detected        [WARNING]"
}
