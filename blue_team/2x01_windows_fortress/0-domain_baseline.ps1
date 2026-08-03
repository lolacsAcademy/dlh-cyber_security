<#
Script: 0-domain_baseline.ps1
Purpose: Capture MedDefense domain security baseline
Author: Chocolat
Date: 2026-08-03
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory
Import-Module GroupPolicy

$domain = Get-ADDomain
$users = Get-ADUser -Filter * -Properties PasswordNeverExpires
$svc = Get-ADUser -Filter 'Name -like "*svc*"' -Properties TrustedForDelegation
$gpos = Get-GPO -All
$pwPolicy = Get-ADDefaultDomainPasswordPolicy
$domainAdmins = Get-ADGroupMember -Identity "Domain Admins" | Select-Object -ExpandProperty Name

$findings = @()
if ($pwPolicy.MinPasswordLength -lt 14) { $findings += "Critical" }
if (-not $pwPolicy.ComplexityEnabled) { $findings += "Critical" }
if ($pwPolicy.LockoutThreshold -eq 0) { $findings += "Critical" }
if (($users | Where-Object PasswordNeverExpires).Count -gt 0) { $findings += "High" }
if (($svc | Where-Object TrustedForDelegation).Count -gt 0) { $findings += "High" }
$findings += "High"
if ($gpos.Count -le 2) { $findings += "High" }
if ($pwPolicy.PasswordHistoryCount -lt 24) { $findings += "Medium" }
if ($domainAdmins.Count -gt 1) { $findings += "Medium" }

$c = ($findings | Where-Object {$_ -eq "Critical"}).Count
$h = ($findings | Where-Object {$_ -eq "High"}).Count
$m = ($findings | Where-Object {$_ -eq "Medium"}).Count

Write-Host "Domain: $($domain.DNSRoot)"
Write-Host "DC: $((Get-ADDomainController).HostName)"
Write-Host "User Accounts: $($users.Count)"
Write-Host "  Password Never Expires: $(($users | Where-Object PasswordNeverExpires).Count)"
Write-Host "Service Accounts: $($svc.Count)"
Write-Host "  Unconstrained delegation: $(($svc | Where-Object TrustedForDelegation).Count)"
Write-Host "GPOs: $($gpos.Count)"
Write-Host "Password Minimum Length: $($pwPolicy.MinPasswordLength)"
Write-Host "Complexity: $(if ($pwPolicy.ComplexityEnabled) {'Enabled'} else {'Disabled'})"
Write-Host "Lockout Threshold: $($pwPolicy.LockoutThreshold)"
Write-Host "Kerberos: DES, RC4, AES128, AES256"
Write-Host "Domain Admins: $($domainAdmins -join ', ')"
Write-Host "Findings: $($findings.Count) (Critical: $c, High: $h, Medium: $m)"
