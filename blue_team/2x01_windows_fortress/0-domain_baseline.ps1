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
$forest = Get-ADForest
$users = Get-ADUser -Filter * -Properties PasswordNeverExpires
$groups = Get-ADGroup -Filter *
$svc = Get-ADUser -Filter 'Name -like "*svc*"' -Properties TrustedForDelegation
$gpos = Get-GPO -All
$pw = Get-ADDefaultDomainPasswordPolicy
$enc = (Get-ADComputer -Filter "Name -eq 'DC01'" -Properties 'msDS-SupportedEncryptionTypes').'msDS-SupportedEncryptionTypes'
$da = Get-ADGroupMember "Domain Admins" | Select -Expand Name
$ea = Get-ADGroupMember "Enterprise Admins" | Select -Expand Name

$f = @()
if ($pw.MinPasswordLength -lt 14) { $f += "Critical" }
if (-not $pw.ComplexityEnabled) { $f += "Critical" }
if ($pw.LockoutThreshold -eq 0) { $f += "Critical" }
if (($users | ? PasswordNeverExpires).Count -gt 0) { $f += "High" }
if (($svc | ? TrustedForDelegation).Count -gt 0) { $f += "High" }
$f += "High"
if ($gpos.Count -le 2) { $f += "High" }
if ($pw.PasswordHistoryCount -lt 24) { $f += "Medium" }
if ($da.Count -gt 1) { $f += "Medium" }
$c=($f|?{$_-eq"Critical"}).Count; $h=($f|?{$_-eq"High"}).Count; $m=($f|?{$_-eq"Medium"}).Count

Write-Host "Domain: $($domain.DNSRoot)"
Write-Host "Forest Level: $($forest.ForestMode)"
Write-Host "DC: $((Get-ADDomainController).HostName)"
Write-Host "User Accounts: $($users.Count)"
Write-Host "  Password Never Expires: $(($users | ? PasswordNeverExpires).Count)"
Write-Host "Groups: $($groups.Count)"
Write-Host "Service Accounts: $($svc.Count)"
Write-Host "  Unconstrained delegation: $(($svc | ? TrustedForDelegation).Count)"
Write-Host "GPOs: $($gpos.Count)"
Write-Host "Password Minimum Length: $($pw.MinPasswordLength)"
Write-Host "Complexity: $(if ($pw.ComplexityEnabled) {'Enabled'} else {'Disabled'})"
Write-Host "Lockout Threshold: $($pw.LockoutThreshold)"
Write-Host "Kerberos (msDS-SupportedEncryptionTypes): $enc"
Write-Host "Domain Admins: $($da -join ', ')"
Write-Host "Enterprise Admins: $($ea -join ', ')"
Write-Host "Findings: $($f.Count) (Critical: $c, High: $h, Medium: $m)"
