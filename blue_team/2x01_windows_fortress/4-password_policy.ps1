<#
Script Name: 4-password_policy.ps1
Purpose: Configure the MedDefense domain password and account lockout policy.
Author: Student
Date: 2026-08-15
# MinimumPasswordLength: 14, Complexity: Enabled, PasswordHistoryCount: 24
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory
Import-Module GroupPolicy

$GPOName = "MedDefense - Password and Lockout Policy"

$Domain = Get-ADDomain
$DomainDNS = $Domain.DNSRoot
$DomainDN = $Domain.DistinguishedName

$CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object Security.Principal.WindowsPrincipal($CurrentUser)

if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from PowerShell as Administrator."
}

$BeforePolicy = Get-ADDefaultDomainPasswordPolicy -Identity $DomainDNS
$BeforePolicy |
    Select-Object MinPasswordLength,ComplexityEnabled,PasswordHistoryCount,MaxPasswordAge,MinPasswordAge,LockoutThreshold,LockoutDuration,LockoutObservationWindow |
    ConvertTo-Json |
    Set-Content -Path "password_policy_before.json" -Encoding UTF8

Write-Host "[*] Creating GPO: `"$GPOName`"..." -NoNewline
$ExistingGPO = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
if ($null -eq $ExistingGPO) {
    $GPO = New-GPO -Name $GPOName -Comment "MedDefense password and account lockout policy."
} else {
    $GPO = $ExistingGPO
}
Write-Host " CREATED"

Write-Host "[*] Configuring Password Policy..."
Set-ADDefaultDomainPasswordPolicy `
    -Identity $DomainDNS `
    -MinPasswordLength 14 `
    -ComplexityEnabled $true `
    -PasswordHistoryCount 24 `
    -MaxPasswordAge ([TimeSpan]::Zero) `
    -MinPasswordAge (New-TimeSpan -Days 1) `
    -LockoutThreshold 5 `
    -LockoutDuration (New-TimeSpan -Minutes 15) `
    -LockoutObservationWindow (New-TimeSpan -Minutes 15)

Write-Host "    Minimum Length: 14            [SET]"
Write-Host "    Complexity: Enabled           [SET]"
Write-Host "    History: 24                   [SET]"
Write-Host "    Maximum Age: 0                [SET]"
Write-Host "    Minimum Age: 1 day            [SET]"

Write-Host "[*] Configuring Account Lockout..."
Write-Host "    Threshold: 5 attempts         [SET]"
Write-Host "    Duration: 15 minutes          [SET]"
Write-Host "    Reset Counter: 15 minutes     [SET]"

Write-Host "[*] Linking GPO to domain root..." -NoNewline
$Inheritance = Get-GPInheritance -Target $DomainDN
$AlreadyLinked = $Inheritance.GpoLinks | Where-Object { $_.DisplayName -eq $GPOName }
if ($null -eq $AlreadyLinked) {
    New-GPLink -Name $GPOName -Target $DomainDN -LinkEnabled Yes | Out-Null
}
Write-Host " LINKED"

Write-Host "[*] Forcing Group Policy update..." -NoNewline
& gpupdate.exe /force | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Group Policy update failed."
}
Write-Host " COMPLETE"

# VERIFY effective policy
$EffectivePolicy = Get-ADDefaultDomainPasswordPolicy -Identity $DomainDNS

$Valid = (
    $EffectivePolicy.MinPasswordLength -eq 14 -and
    $EffectivePolicy.ComplexityEnabled -eq $true -and
    $EffectivePolicy.PasswordHistoryCount -eq 24 -and
    $EffectivePolicy.MaxPasswordAge.TotalDays -eq 0 -and
    $EffectivePolicy.MinPasswordAge.TotalDays -eq 1 -and
    $EffectivePolicy.LockoutThreshold -eq 5 -and
    [Math]::Abs($EffectivePolicy.LockoutDuration.TotalMinutes) -eq 15 -and
    [Math]::Abs($EffectivePolicy.LockoutObservationWindow.TotalMinutes) -eq 15
)

if (-not $Valid) {
    throw "Effective password policy VERIFICATION failed."
}

Write-Host "[*] Effective policy VERIFIED successfully."
