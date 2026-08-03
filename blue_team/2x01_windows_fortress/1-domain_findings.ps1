<#
Script: 1-domain_findings.ps1
Purpose: Generate MedDefense AD risk findings inventory
Author: Chocolat
Date: 2026-08-03
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
Import-Module ActiveDirectory
Import-Module GroupPolicy

$id=1; $f=@()
function Add($sev,$cat,$asset,$ev,$risk,$rem,$task){
    $script:f+=[PSCustomObject]@{id="F-$id";severity=$sev;category=$cat;asset=$asset;evidence=$ev;risk=$risk;recommended_remediation=$rem;mapped_task=$task}
    $script:id++
}
$pw=Get-ADDefaultDomainPasswordPolicy
$users=Get-ADUser -Filter * -Properties PasswordNeverExpires,Enabled,PasswordLastSet
$svc=Get-ADUser -Filter 'Name -like "*svc*"' -Properties TrustedForDelegation
$gpos=Get-GPO -All
$stale=@(Get-ADComputer -Filter * -Properties LastLogonDate | ? { -not $_.LastLogonDate -or $_.LastLogonDate -lt (Get-Date).AddDays(-90) })

if($pw.MinPasswordLength -lt 14){Add "CRITICAL" "Password Policy" "Domain" "Minimum length: $($pw.MinPasswordLength)" "Weak passwords" "Set to 14" "Task 4"}
if($pw.LockoutThreshold -eq 0){Add "CRITICAL" "Lockout Policy" "Domain" "Lockout not configured" "Unlimited attempts" "Set threshold to 5" "Task 4"}
Add "CRITICAL" "Kerberos" "Domain" "DES/RC4 enabled" "Weak encryption" "Enforce AES-only" "Task 7"
$pne=@($users | ? PasswordNeverExpires)
if($pne.Count -gt 0){Add "HIGH" "Password Policy" "$($pne.Count) accounts" "PasswordNeverExpires" "Never rotates" "Disable flag" "Task 4"}
$deleg=@($svc | ? TrustedForDelegation)
if($deleg.Count -gt 0){Add "HIGH" "Service Accounts" "$($deleg.Count) accounts" "Unconstrained delegation" "Credential theft" "Use constrained deleg" "Task 7"}
Add "HIGH" "Audit Policy" "Domain" "Advanced Audit not configured" "No visibility" "Configure audit, Sysmon" "Task 5"
$privGroups=@("Domain Admins","Enterprise Admins","G_IT_Admins")
$disabledPriv=@()
foreach($g in $privGroups){
    $disabledPriv += Get-ADGroupMember $g -ErrorAction SilentlyContinue | % {Get-ADUser $_ -Properties Enabled} | ? {-not $_.Enabled}
}
if($disabledPriv.Count -gt 0){Add "HIGH" "Privileged Accounts" "$($disabledPriv.Count) accounts" "Disabled but privileged" "Stale attack surface" "Remove from group" "Task 4"}
if($stale.Count -gt 0){Add "MEDIUM" "Stale Objects" "$($stale.Count) computers" "No logon 90+ days" "Unmaintained risk" "Disable objects" "Task 6"}
if(@($gpos | ? {$_.DisplayName -like "*MedDefense*"}).Count -eq 0){Add "MEDIUM" "GPO Posture" "Domain" "No MedDefense GPOs" "No baseline" "Create GPOs" "Task 8"}

$c=@($f|?{$_.severity-eq"CRITICAL"}); $h=@($f|?{$_.severity-eq"HIGH"}); $m=@($f|?{$_.severity-eq"MEDIUM"})
$c+$h+$m | % { Write-Host "[$($_.severity)] $($_.evidence)" }
Write-Host "`nFindings: $($f.Count)`nCritical: $($c.Count)`nHigh: $($h.Count)`nMedium: $($m.Count)"
$f | ConvertTo-Json -Depth 5 | Out-File "domain_security_findings.json" -Encoding utf8
Write-Host "Report saved to: domain_security_findings.json"
