<#
Script Name: 11-firewall_hardening.ps1
Purpose: Harden Windows Firewall for MedDefense with default-deny inbound policy.
Author: Student
Date: 2026-08-16
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$MgmtSubnet = "10.10.3.0/24"
$ServerSubnet = "10.10.1.0/24"
$RuleGroup = "MedDefense Firewall"

# Require Administrator
$CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object Security.Principal.WindowsPrincipal($CurrentUser)

if (-not $Principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)) {
    throw "Run this script from PowerShell as Administrator."
}

# ---------------------------------------------------------
# Capture current firewall state
# ---------------------------------------------------------

Write-Host "[*] Current Firewall State..."

$BeforeProfiles = Get-NetFirewallProfile |
    Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction

foreach ($Profile in $BeforeProfiles) {
    $State = if ($Profile.Enabled) { "ON" } else { "OFF" }

    Write-Host (
        "    {0}: {1}, DefaultInbound: {2}" -f
        $Profile.Name,
        $State,
        $Profile.DefaultInboundAction
    )
}

$BeforeProfiles |
    ConvertTo-Json |
    Set-Content `
        -Path ".\firewall_state_before.json" `
        -Encoding UTF8

# ---------------------------------------------------------
# Remove only previous MedDefense rules on rerun
# ---------------------------------------------------------

Get-NetFirewallRule `
    -Group $RuleGroup `
    -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule `
        -ErrorAction SilentlyContinue

# ---------------------------------------------------------
# IMPORTANT:
# Create allow rules BEFORE enabling all firewall profiles.
# ---------------------------------------------------------

Write-Host "[*] Creating allow rules..."

# RDP - management subnet only
New-NetFirewallRule `
    -DisplayName "MedDef-RDP-Mgmt" `
    -Group $RuleGroup `
    -Direction Inbound `
    -Action Allow `
    -Protocol TCP `
    -LocalPort 3389 `
    -RemoteAddress $MgmtSubnet `
    -Profile Any |
    Out-Null

Write-Host "    MedDef-RDP-Mgmt:  TCP 3389 from 10.10.3.0/24     [CREATED]"

# DNS TCP
New-NetFirewallRule `
    -DisplayName "MedDef-DNS-TCP" `
    -Group $RuleGroup `
    -Direction Inbound `
    -Action Allow `
    -Protocol TCP `
    -LocalPort 53 `
    -Profile Any |
    Out-Null

# DNS UDP
New-NetFirewallRule `
    -DisplayName "MedDef-DNS-UDP" `
    -Group $RuleGroup `
    -Direction Inbound `
    -Action Allow `
    -Protocol UDP `
    -LocalPort 53 `
    -Profile Any |
    Out-Null

Write-Host "    MedDef-DNS:        TCP/UDP 53                    [CREATED]"

# LDAP
New-NetFirewallRule `
    -DisplayName "MedDef-LDAP" `
    -Group $RuleGroup `
    -Direction Inbound `
    -Action Allow `
    -Protocol TCP `
    -LocalPort 389 `
    -Profile Any |
    Out-Null

Write-Host "    MedDef-LDAP:       TCP 389                       [CREATED]"

# Kerberos TCP
New-NetFirewallRule `
    -DisplayName "MedDef-Kerberos-TCP" `
    -Group $RuleGroup `
    -Direction Inbound `
    -Action Allow `
    -Protocol TCP `
    -LocalPort 88 `
    -Profile Any |
    Out-Null

# Kerberos UDP
New-NetFirewallRule `
    -DisplayName "MedDef-Kerberos-UDP" `
    -Group $RuleGroup `
    -Direction Inbound `
    -Action Allow `
    -Protocol UDP `
    -LocalPort 88 `
    -Profile Any |
    Out-Null

Write-Host "    MedDef-Kerberos:   TCP/UDP 88                    [CREATED]"

# SMB - server subnet only
New-NetFirewallRule `
    -DisplayName "MedDef-SMB" `
    -Group $RuleGroup `
    -Direction Inbound `
    -Action Allow `
    -Protocol TCP `
    -LocalPort 445 `
    -RemoteAddress $ServerSubnet `
    -Profile Any |
    Out-Null

Write-Host "    MedDef-SMB:        TCP 445 from 10.10.1.0/24     [CREATED]"

# WinRM HTTP
New-NetFirewallRule `
    -DisplayName "MedDef-WinRM-HTTP" `
    -Group $RuleGroup `
    -Direction Inbound `
    -Action Allow `
    -Protocol TCP `
    -LocalPort 5985 `
    -RemoteAddress $MgmtSubnet `
    -Profile Any |
    Out-Null

# WinRM HTTPS
New-NetFirewallRule `
    -DisplayName "MedDef-WinRM-HTTPS" `
    -Group $RuleGroup `
    -Direction Inbound `
    -Action Allow `
    -Protocol TCP `
    -LocalPort 5986 `
    -RemoteAddress $MgmtSubnet `
    -Profile Any |
    Out-Null

Write-Host "    MedDef-WinRM:      TCP 5985-5986 from 10.10.3.0/24 [CREATED]"

# ---------------------------------------------------------
# Disable only conflicting broad legacy inbound allow rules
# Do NOT disable Windows rules blindly.
# ---------------------------------------------------------

$LegacyRules = @(
    Get-NetFirewallRule `
        -Direction Inbound `
        -Action Allow `
        -Enabled True `
        -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Group -ne $RuleGroup -and
        (
            $_.DisplayName -match "Remote Desktop" -or
            $_.DisplayName -match "Windows Remote Management"
        )
    }
)

$LegacyCount = 0

foreach ($Rule in $LegacyRules) {
    Disable-NetFirewallRule `
        -Name $Rule.Name `
        -ErrorAction SilentlyContinue

    $LegacyCount++
}

# Disable-NetFirewallRule used for conflicting legacy allow rules
Write-Host "[*] Disabling $LegacyCount legacy allow rules...     [DONE]"

# ---------------------------------------------------------
# Enable logging for dropped packets
# ---------------------------------------------------------

Set-NetFirewallProfile `
    -Profile Domain,Private,Public `
    -LogBlocked True `
    -LogFileName "%systemroot%\system32\LogFiles\Firewall\pfirewall.log" `
    -LogMaxSizeKilobytes 16384

Write-Host "[*] Enabling dropped packet logging...     [SET]"

# ---------------------------------------------------------
# Enable all profiles and default-deny inbound
# Do this LAST, after allow rules exist.
# ---------------------------------------------------------

Set-NetFirewallProfile `
    -Profile Domain,Private,Public `
    -Enabled True `
    -DefaultInboundAction Block `
    -DefaultOutboundAction Allow

Write-Host "[*] Setting default-deny on all profiles... [SET]"

# ---------------------------------------------------------
# Verification
# ---------------------------------------------------------

Write-Host "[*] Verification..."

$AfterProfiles = @(
    Get-NetFirewallProfile `
        -Profile Domain,Private,Public
)

$ProfilesOK = (
    @(
        $AfterProfiles |
        Where-Object {
            $_.Enabled -ne $true -or
            $_.DefaultInboundAction -ne "Block"
        }
    ).Count -eq 0
)

if ($ProfilesOK) {
    Write-Host "    All 3 profiles: ON, DefaultInbound: Block  [VERIFIED]"
}
else {
    throw "Firewall profile verification failed."
}

$CustomRules = @(
    Get-NetFirewallRule `
        -Group $RuleGroup `
        -Enabled True `
        -ErrorAction SilentlyContinue
)

if ($CustomRules.Count -ge 9) {
    Write-Host "    Custom service rules active                [VERIFIED]"
}
else {
    throw "Custom firewall rule verification failed."
}

$AfterProfiles |
    Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction |
    ConvertTo-Json |
    Set-Content `
        -Path ".\firewall_state_after.json" `
        -Encoding UTF8

Write-Host "[*] Firewall hardening completed successfully."
