<#
Script Name: 15-master_validation.ps1
Purpose: Weekly MedDefense Windows hardening compliance validation.
Author: Student
Read-only: This script makes no system changes.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

$CriticalFailures = 0

function PASS($Message) {
    Write-Host "[PASS] $Message"
}

function WARN($Message) {
    Write-Host "[WARN] $Message"
}

function FAIL($Message) {
    Write-Host "[FAIL] $Message"
    $script:CriticalFailures++
}

function Section($Name) {
    Write-Host ""
    Write-Host "--- $Name ---"
}

# =========================================================
# Password & Lockout
# =========================================================

Section "Password & Lockout"

$DomainPolicy = Get-ADDefaultDomainPasswordPolicy

if ($DomainPolicy.MinPasswordLength -ge 14) {
    PASS "Minimum length: $($DomainPolicy.MinPasswordLength)"
}
else {
    FAIL "Minimum length: $($DomainPolicy.MinPasswordLength) (expected >= 14)"
}

if (
    $DomainPolicy.LockoutThreshold -gt 0 -and
    $DomainPolicy.LockoutThreshold -le 5
) {
    PASS "Lockout threshold: $($DomainPolicy.LockoutThreshold)"
}
else {
    FAIL "Lockout threshold: $($DomainPolicy.LockoutThreshold) (expected 1-5)"
}

# =========================================================
# Audit Policy
# =========================================================

Section "Audit Policy"

$Audit = auditpol /get /subcategory:"Process Creation" 2>$null |
    Out-String

if ($Audit -match "Success") {
    PASS "Process Creation: Success"
}
else {
    FAIL "Process Creation auditing not enabled"
}

$CmdLinePath =
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"

$CmdLine = (
    Get-ItemProperty `
        -Path $CmdLinePath `
        -Name ProcessCreationIncludeCmdLine_Enabled `
        -ErrorAction SilentlyContinue
).ProcessCreationIncludeCmdLine_Enabled

if ($CmdLine -eq 1) {
    PASS "Command-line logging: Enabled"
}
else {
    FAIL "Command-line logging: Disabled"
}

$SecurityLog = Get-WinEvent -ListLog Security

if ($SecurityLog.MaximumSizeInBytes -ge 1GB) {
    PASS "Security log: 1 GB"
}
else {
    FAIL "Security log smaller than 1 GB"
}

# =========================================================
# PowerShell
# =========================================================

Section "PowerShell"

$PSBase = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"

$ScriptBlock = (
    Get-ItemProperty `
        "$PSBase\ScriptBlockLogging" `
        -Name EnableScriptBlockLogging `
        -ErrorAction SilentlyContinue
).EnableScriptBlockLogging

if ($ScriptBlock -eq 1) {
    PASS "Script Block Logging: Enabled"
}
else {
    FAIL "Script Block Logging: Disabled"
}

$Transcript = (
    Get-ItemProperty `
        "$PSBase\Transcription" `
        -Name EnableTranscripting `
        -ErrorAction SilentlyContinue
).EnableTranscripting

if ($Transcript -eq 1) {
    PASS "Transcription: Enabled"
}
else {
    FAIL "Transcription: Disabled"
}

# =========================================================
# Sysmon
# =========================================================

Section "Sysmon"

$Sysmon = Get-Service Sysmon64 -ErrorAction SilentlyContinue

if ($Sysmon -and $Sysmon.Status -eq "Running") {
    PASS "Service: Running"
}
else {
    FAIL "Sysmon service not running"
}

$SysmonConfig = Join-Path $PSScriptRoot "sysmonconfig.xml"

if (Test-Path $SysmonConfig) {

    $ConfigText = Get-Content $SysmonConfig -Raw

    $Rules = @(
        "rclone",
        "PsExec",
        "-enc",
        "vssadmin",
        "schtasks"
    )

    $Found = 0

    foreach ($Rule in $Rules) {
        if ($ConfigText -match [regex]::Escape($Rule)) {
            $Found++
        }
    }

    if ($Found -eq 5) {
        PASS "Custom rules: 5 present"
    }
    else {
        FAIL "Custom rules: $Found/5 present"
    }
}
else {
    FAIL "sysmonconfig.xml not found"
}

# =========================================================
# Kerberos
# =========================================================

Section "Kerberos"

# Task 7 stores the domain KDC encryption configuration here.
$KerberosPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc"

$KerberosTypes = (
    Get-ItemProperty `
        -Path $KerberosPath `
        -Name DefaultDomainSupportedEncTypes `
        -ErrorAction SilentlyContinue
).DefaultDomainSupportedEncTypes

# 24 decimal = 0x18 = AES128 + AES256.
# DES and RC4 are therefore disabled.
if ($KerberosTypes -eq 24) {
    PASS "DES: Disabled"
    PASS "RC4: Disabled"
}
else {
    FAIL "Kerberos encryption is not AES-only"
}

# =========================================================
# SMB
# =========================================================

Section "SMB"

$SMBServer = Get-SmbServerConfiguration

if ($SMBServer.EnableSMB1Protocol -eq $false) {
    PASS "SMBv1: Disabled"
}
else {
    FAIL "SMBv1: Enabled"
}

if ($SMBServer.RequireSecuritySignature -eq $true) {
    PASS "Signing: Required"
}
else {
    FAIL "SMB signing not required"
}

# =========================================================
# Firewall
# =========================================================

Section "Firewall"

$Profiles = @(
    Get-NetFirewallProfile -Profile Domain,Private,Public
)

$BadProfiles = @(
    $Profiles |
    Where-Object {
        $_.Enabled -ne $true -or
        $_.DefaultInboundAction -ne "Block"
    }
)

if ($BadProfiles.Count -eq 0) {
    PASS "All profiles: ON, DefaultInbound: Block"
}
else {
    FAIL "One or more firewall profiles are not hardened"
}

# =========================================================
# RDP
# =========================================================

Section "RDP"

$RdpTcp =
    "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"

$NLA = (
    Get-ItemProperty `
        -Path $RdpTcp `
        -Name UserAuthentication `
        -ErrorAction SilentlyContinue
).UserAuthentication

if ($NLA -eq 1) {
    PASS "NLA: Required"
}
else {
    FAIL "NLA: Not required"
}

$RdpMembers = (
    net.exe localgroup "Remote Desktop Users" 2>$null
) -join "`n"

if ($RdpMembers -match "G_IT_Admins") {
    PASS "G_IT_Admins only"
}
else {
    FAIL "G_IT_Admins missing from Remote Desktop Users"
}

# =========================================================
# Service Accounts
# =========================================================

Section "Service Accounts"

$ServiceAccounts = @(
    Get-ADUser `
        -Filter 'SamAccountName -like "svc_*"' `
        -Properties PasswordLastSet,
                    TrustedForDelegation,
                    AccountNotDelegated
)

$DelegationOK = 0

foreach ($Account in $ServiceAccounts) {

    if (
        $Account.TrustedForDelegation -eq $false -and
        $Account.AccountNotDelegated -eq $true
    ) {
        $DelegationOK++
    }

    if ($null -ne $Account.PasswordLastSet) {

        $Age = (
            New-TimeSpan `
                -Start $Account.PasswordLastSet `
                -End (Get-Date)
        ).Days

        if ($Age -gt 90) {
            WARN "$($Account.SamAccountName) password age: $Age days"
        }
        else {
            PASS "$($Account.SamAccountName) password age: $Age days"
        }
    }
}

if (
    $ServiceAccounts.Count -gt 0 -and
    $DelegationOK -eq $ServiceAccounts.Count
) {
    PASS "Delegation restricted: $DelegationOK/$($ServiceAccounts.Count)"
}
else {
    FAIL "Delegation restricted: $DelegationOK/$($ServiceAccounts.Count)"
}

# =========================================================
# Compliance Summary / exit codes
# =========================================================

Write-Host ""
Write-Host "--- Compliance Summary ---"

if ($CriticalFailures -eq 0) {
    Write-Host "[PASS] All critical hardening checks passed."
    exit 0
}
else {
    Write-Host "[FAIL] Critical failures: $CriticalFailures"
    exit 1
}
