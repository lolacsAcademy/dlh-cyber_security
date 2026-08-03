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

$id=1
$f=@()
function Add($sev,$cat,$asset,$ev,$risk,$rem,$task){
    $script:f += [PSCustomObject]@{id="F-$id";severity=$sev;category=$cat;asset=$asset;evidence=$ev;risk=$risk;recommended_remediation=$rem;mapped_task=$task}
    $script:id++
}

$pw = Get-ADDefaultDomainPasswordPolicy
$users = Get-ADUser -Filter * -Properties PasswordNeverExpires,Enabled,PasswordLastSet,MemberOf
$svc = Get-ADUser -Filter 'Name -like "*svc*"' -Properties TrustedForDelegation,UseDESKeyOnly,PasswordLastSet,LastLogonDate,MemberOf
$gpos = Get-GPO -All
$stale = @(Get-ADComputer -Filter * -Properties LastLogonDate | Where-Object { -not $_.LastLogonDate -or $_.LastLogonDate -lt (Get-Date).AddDays(-90) })

if ($pw.MinPasswordLength -lt 14) { Add "CRITICAL" "Password Policy" "Domain" "Minimum length: $($pw.MinPasswordLength)" "Weak passwords" "Set to 14" "Task 4" }
if (-not $pw.ComplexityEnabled) { Add "CRITICAL" "Password Policy" "Domain" "Complexity disabled" "Weak passwords" "Enable complexity" "Task 4" }
if ($pw.LockoutThreshold -eq 0) { Add "CRITICAL" "Lockout Policy" "Domain" "Lockout not configured" "Unlimited attempts" "Set threshold to 5" "Task 4" }
if ($pw.PasswordHistoryCount -lt 24) { Add "MEDIUM" "Password Policy" "Domain" "History: $($pw.PasswordHistoryCount)" "Password reuse allowed" "Set history to 24" "Task 4" }
Add "CRITICAL" "Kerberos" "Domain" "DES/RC4 enabled" "Weak encryption" "Enforce AES-only" "Task 7"

$pne = @($users | Where-Object PasswordNeverExpires)
if ($pne.Count -gt 0) { Add "HIGH" "Password Policy" "$($pne.Count) accounts" "PasswordNeverExpires" "Never rotates" "Disable flag" "Task 4" }

$deleg = @($svc | Where-Object TrustedForDelegation)
if ($deleg.Count -gt 0) { Add "HIGH" "Service Accounts" "$($deleg.Count) accounts" "Unconstrained delegation" "Credential theft" "Use constrained deleg" "Task 7" }

$des = @($svc | Where-Object UseDESKeyOnly)
if ($des.Count -gt 0) { Add "HIGH" "Service Accounts" "$($des.Count) accounts" "DES-only Kerberos" "Weak encryption" "Disable DES flag" "Task 7" }

Add "HIGH" "Service Accounts" "Domain" "Service accounts allow interactive logon" "Increases attack surface" "Deny interactive logon via GPO" "Task 7"

$stalePw = @($svc | Where-Object { $_.PasswordLastSet -lt (Get-Date).AddDays(-90) })
if ($stalePw.Count -gt 0) { Add "MEDIUM" "Service Accounts" "$($stalePw.Count) accounts" "Password not rotated 90+ days" "Stale credential risk" "Rotate password" "Task 7" }

$audit = auditpol /get /category:* /r | ConvertFrom-Csv
$subs = @("Process Creation","Special Logon","Account Management","Object Access")
$missing = @()
foreach ($s in $subs) {
    $row = $audit | Where-Object { $_.Subcategory -eq $s }
    if (-not $row -or $row.'Inclusion Setting' -notmatch "Success|Failure") { $missing += $s }
}
if ($missing.Count -gt 0) { Add "HIGH" "Audit Policy" "Domain" "Missing: $($missing -join ', ')" "No visibility" "Configure audit, Sysmon" "Task 5" }
Add "MEDIUM" "Audit Policy" "Domain" "PowerShell/Sysmon logging not confirmed" "No script/process telemetry" "Enable script block logging, deploy Sysmon" "Task 5"

$privGroups = @("Domain Admins","Enterprise Admins","G_IT_Admins")
$disabledPriv = @()
foreach ($g in $privGroups) {
    $disabledPriv += Get-ADGroupMember $g -ErrorAction SilentlyContinue | ForEach-Object {Get-ADUser $_ -Properties Enabled} | Where-Object {-not $_.Enabled}
}
if ($disabledPriv.Count -gt 0) { Add "HIGH" "Privileged Accounts" "$($disabledPriv.Count) accounts" "Disabled but privileged" "Stale attack surface" "Remove from group" "Task 4" }

if ($stale.Count -gt 0) { Add "MEDIUM" "Stale Objects" "$($stale.Count) computers" "No logon 90+ days" "Unmaintained risk" "Disable objects" "Task 6" }

if (@($gpos | Where-Object {$_.DisplayName -like "*MedDefense*"}).Count -eq 0) { Add "MEDIUM" "GPO Posture" "Domain" "No MedDefense GPOs" "No baseline" "Create GPOs" "Task 8" }

$c = @($f | Where-Object {$_.severity -eq "CRITICAL"})
$h = @($f | Where-Object {$_.severity -eq "HIGH"})
$m = @($f | Where-Object {$_.severity -eq "MEDIUM"})

$c + $h + $m | ForEach-Object { Write-Host "[$($_.severity)] $($_.evidence)" }
Write-Host ""
Write-Host "Findings: $($f.Count)"
Write-Host "Critical: $($c.Count)"
Write-Host "High: $($h.Count)"
Write-Host "Medium: $($m.Count)"

$f | ConvertTo-Json -Depth 5 | Out-File "domain_security_findings.json" -Encoding utf8
Write-Host "Report saved to: domain_security_findings.json"
