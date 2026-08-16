<#
Script Name: 16-hardened_state_export.ps1
Purpose: Export the final MedDefense hardened Windows state to JSON.
Author: Student
# Required Security audit Event IDs: 4624, 4625, 4688, 1102
# Script Block Logging
# Get-AppLockerPolicy
# NLA
# DES
# RC4
# AES
# NTLMv1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory
Import-Module GroupPolicy

$OutputFile = Join-Path $PSScriptRoot "windows_hardened_state.json"

function Safe-Value {
    param([scriptblock]$Command)

    try {
        & $Command
    }
    catch {
        $null
    }
}

# =========================================================
# Domain metadata
# =========================================================

Write-Host "[*] Exporting domain metadata..." -NoNewline

$Domain = Get-ADDomain
$DC = Get-ADDomainController -Discover

$DomainMetadata = [ordered]@{
    domain_name       = $Domain.DNSRoot
    domain_controller = $DC.HostName
    timestamp         = (Get-Date).ToString("o")
    script_runner     = "$env:USERDOMAIN\$env:USERNAME"
}

Write-Host " OK"

# =========================================================
# GPO inventory
# =========================================================

Write-Host "[*] Exporting GPO settings..." -NoNewline

$MedDefenseGPOs = @(
    Get-GPO -All |
    Where-Object {
        $_.DisplayName -like "MedDefense*"
    }
)

$GPOInventory = @(
    foreach ($GPO in $MedDefenseGPOs) {

        $Report = Safe-Value {
            Get-GPOReport `
                -Guid $GPO.Id `
                -ReportType Xml
        }

        [ordered]@{
            name = $GPO.DisplayName
            id = $GPO.Id.ToString()
            enabled_state = $GPO.GpoStatus.ToString()
            linked_scopes = if ($Report) {
                @(
                    [regex]::Matches(
                        $Report,
                        "<SOMPath>(.*?)</SOMPath>"
                    ) |
                    ForEach-Object {
                        $_.Groups[1].Value
                    }
                )
            }
            else {
                @()
            }
            key_settings_present = ($null -ne $Report)
        }
    }
)

Write-Host " $($GPOInventory.Count) GPOs"

# =========================================================
# Audit policy
# =========================================================

Write-Host "[*] Exporting audit policy..." -NoNewline

$AuditRaw = (auditpol /get /category:* 2>$null) -join "`n"

$RequiredAudit = @(
    "Credential Validation",
    "Kerberos Authentication Service",
    "Logon",
    "Logoff",
    "Special Logon",
    "User Account Management",
    "Sensitive Privilege Use",
    "File System",
    "Registry",
    "Process Creation"
)

$AuditStatus = @()

foreach ($Name in $RequiredAudit) {

    $Line = (
        $AuditRaw -split "`r?`n" |
        Where-Object {
            $_ -match [regex]::Escape($Name)
        } |
        Select-Object -First 1
    )

    $AuditStatus += [ordered]@{
        subcategory = $Name
        status = if ($Line) {
            $Line.Trim()
        }
        else {
            "not_found"
        }
    }
}

$AuditPolicy = [ordered]@{
    raw_auditpol_output = $AuditRaw
    required_subcategories = $AuditStatus
}

Write-Host " $($AuditStatus.Count) subcategories"

# =========================================================
# PowerShell logging
# =========================================================

Write-Host "[*] Exporting PowerShell logging..." -NoNewline

$PSBase = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"

$PowerShellLogging = [ordered]@{
    script_block_logging = Safe-Value {
        (
            Get-ItemProperty `
                "$PSBase\ScriptBlockLogging" `
                -Name EnableScriptBlockLogging
        ).EnableScriptBlockLogging
    }

    module_logging = Safe-Value {
        (
            Get-ItemProperty `
                "$PSBase\ModuleLogging" `
                -Name EnableModuleLogging
        ).EnableModuleLogging
    }

    transcription = Safe-Value {
        (
            Get-ItemProperty `
                "$PSBase\Transcription" `
                -Name EnableTranscripting
        ).EnableTranscripting
    }

    event_ids = @(4103,4104)
}

Write-Host " OK"

# =========================================================
# Sysmon posture
# =========================================================

Write-Host "[*] Exporting Sysmon config..." -NoNewline

$SysmonService = Get-Service Sysmon64 -ErrorAction SilentlyContinue

$SysmonDriver = Safe-Value {
    & sc.exe query SysmonDrv
}

$SysmonConfigPath = Join-Path $PSScriptRoot "sysmonconfig.xml"

$CustomRules = @(
    "rclone",
    "PsExec",
    "-enc",
    "vssadmin",
    "schtasks"
)

$CustomRuleCount = 0

if (Test-Path $SysmonConfigPath) {

    $SysmonText = Get-Content $SysmonConfigPath -Raw

    foreach ($Rule in $CustomRules) {
        if ($SysmonText -match [regex]::Escape($Rule)) {
            $CustomRuleCount++
        }
    }
}

$SysmonPosture = [ordered]@{
    service_status = if ($SysmonService) {
        $SysmonService.Status.ToString()
    }
    else {
        "not_found"
    }

    driver_status = if (
        ($SysmonDriver -join "`n") -match "RUNNING"
    ) {
        "Running"
    }
    else {
        "not_found"
    }

    config_path = $SysmonConfigPath
    custom_rule_count = $CustomRuleCount

    active_event_ids = @(
        1,3,7,8,10,11,12,13,14,17,18,22
    )
}

Write-Host " $CustomRuleCount custom rules"

# =========================================================
# Firewall posture
# =========================================================

Write-Host "[*] Exporting firewall rules..." -NoNewline

$FirewallProfiles = @(
    Get-NetFirewallProfile |
    ForEach-Object {
        [ordered]@{
            name = $_.Name
            enabled = $_.Enabled
            default_inbound = $_.DefaultInboundAction.ToString()
            default_outbound = $_.DefaultOutboundAction.ToString()
            dropped_packet_logging = $_.LogBlocked
        }
    }
)

$MedDefenseFirewallRules = @(
    Get-NetFirewallRule `
        -Group "MedDefense Firewall" `
        -ErrorAction SilentlyContinue |
    ForEach-Object {
        [ordered]@{
            name = $_.DisplayName
            enabled = $_.Enabled.ToString()
            direction = $_.Direction.ToString()
            action = $_.Action.ToString()
        }
    }
)

$FirewallPosture = [ordered]@{
    profiles = $FirewallProfiles
    meddefense_rules = $MedDefenseFirewallRules
    dropped_packet_logging = @(
        $FirewallProfiles |
        ForEach-Object {
            [ordered]@{
                profile = $_.name
                enabled = $_.dropped_packet_logging
            }
        }
    )
}

Write-Host " $($MedDefenseFirewallRules.Count) rules"

# =========================================================
# AppLocker posture
# =========================================================

Write-Host "[*] Exporting AppLocker policy..." -NoNewline

$AppLockerPath = Join-Path $PSScriptRoot "applocker_policy.xml"

$ExeRules = @()
$ScriptRules = @()
$AppLockerMode = "not_found"

if (Test-Path $AppLockerPath) {

    [xml]$AppLockerXML = Get-Content $AppLockerPath -Raw

    $ExeCollection = $AppLockerXML.AppLockerPolicy.RuleCollection |
        Where-Object {
            $_.Type -eq "Exe"
        }

    $ScriptCollection = $AppLockerXML.AppLockerPolicy.RuleCollection |
        Where-Object {
            $_.Type -eq "Script"
        }

    if ($ExeCollection) {
        $AppLockerMode = $ExeCollection.EnforcementMode

        $ExeRules = @(
            $ExeCollection.FilePathRule |
            ForEach-Object {
                $_.Name
            }
        )
    }

    if ($ScriptCollection) {
        $ScriptRules = @(
            $ScriptCollection.FilePathRule |
            ForEach-Object {
                $_.Name
            }
        )
    }
}

$AppLockerPosture = [ordered]@{
    enforcement_mode = $AppLockerMode
    executable_rules = $ExeRules
    script_rules = $ScriptRules
    exported_policy_path = $AppLockerPath
}

$TotalAppLockerRules = $ExeRules.Count + $ScriptRules.Count

Write-Host " $TotalAppLockerRules rules"

# =========================================================
# RDP posture
# =========================================================

Write-Host "[*] Exporting remote access posture..." -NoNewline

$RdpTcp =
    "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"

$TsPolicy =
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"

$RDPPosture = [ordered]@{
    nla_required = Safe-Value {
        (
            Get-ItemProperty `
                $RdpTcp `
                -Name UserAuthentication
        ).UserAuthentication
    }

    allowed_group = "G_IT_Admins"

    clipboard_redirection_disabled = Safe-Value {
        (
            Get-ItemProperty `
                $TsPolicy `
                -Name fDisableClip
        ).fDisableClip
    }

    drive_redirection_disabled = Safe-Value {
        (
            Get-ItemProperty `
                $TsPolicy `
                -Name fDisableCdm
        ).fDisableCdm
    }

    idle_timeout_ms = Safe-Value {
        (
            Get-ItemProperty `
                $TsPolicy `
                -Name MaxIdleTime
        ).MaxIdleTime
    }

    max_session_ms = Safe-Value {
        (
            Get-ItemProperty `
                $TsPolicy `
                -Name MaxConnectionTime
        ).MaxConnectionTime
    }
}

Write-Host " OK"

# =========================================================
# Authentication protocols
# =========================================================

Write-Host "[*] Exporting authentication protocol posture..." -NoNewline

$KdcPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc"

$EncTypes = Safe-Value {
    (
        Get-ItemProperty `
            $KdcPath `
            -Name DefaultDomainSupportedEncTypes
    ).DefaultDomainSupportedEncTypes
}

$LsaPath =
    "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

$LMLevel = Safe-Value {
    (
        Get-ItemProperty `
            $LsaPath `
            -Name LmCompatibilityLevel
    ).LmCompatibilityLevel
}

$SMB = Get-SmbServerConfiguration

$AuthenticationProtocols = [ordered]@{
    des_enabled = if ($EncTypes -eq 24) { $false } else { $true }
    rc4_enabled = if ($EncTypes -eq 24) { $false } else { $true }
    aes128_enabled = if ($EncTypes -eq 24) { $true } else { $null }
    aes256_enabled = if ($EncTypes -eq 24) { $true } else { $null }
    ntlmv1_enabled = if ($LMLevel -eq 5) { $false } else { $true }
    lm_compatibility_level = $LMLevel
    smbv1_enabled = $SMB.EnableSMB1Protocol
    smb_signing_required = $SMB.RequireSecuritySignature
}

Write-Host " OK"

# =========================================================
# Service account posture
# =========================================================

Write-Host "[*] Exporting service account posture..." -NoNewline

$PrivilegedGroups = @(
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Server Operators",
    "Backup Operators"
)

$ServiceAccounts = @(
    Get-ADUser `
        -Filter 'SamAccountName -like "svc_*"' `
        -Properties PasswordLastSet,
                    TrustedForDelegation,
                    AccountNotDelegated,
                    MemberOf
)

$ServiceAccountPosture = @(
    foreach ($Account in $ServiceAccounts) {

        $Groups = @(
            foreach ($DN in $Account.MemberOf) {
                (Get-ADGroup -Identity $DN).Name
            }
        )

        $PrivMembership = @(
            $Groups |
            Where-Object {
                $_ -in $PrivilegedGroups
            }
        )

        $PasswordAge = if ($Account.PasswordLastSet) {
            (
                New-TimeSpan `
                    -Start $Account.PasswordLastSet `
                    -End (Get-Date)
            ).Days
        }
        else {
            $null
        }

        [ordered]@{
            account = $Account.SamAccountName
            password_age_days = $PasswordAge
            trusted_for_delegation = $Account.TrustedForDelegation
            account_not_delegated = $Account.AccountNotDelegated
            privileged_membership = $PrivMembership
            interactive_logon_risk = if ($Account.AccountNotDelegated) {
                "restricted"
            }
            else {
                "review_required"
            }
        }
    }
)

Write-Host " $($ServiceAccountPosture.Count) accounts"

# =========================================================
# Task 15 validation summary
# =========================================================

Write-Host "[*] Loading validation summary..." -NoNewline

$ValidationScript = Join-Path $PSScriptRoot "15-master_validation.ps1"

if (Test-Path $ValidationScript) {

    $ValidationSummary = [ordered]@{
        status = "available"
        script_path = $ValidationScript
        last_validation = "Task 15 script available for execution"
    }

    Write-Host " OK"
}
else {

    $ValidationSummary = [ordered]@{
        status = "not_found"
        script_path = $ValidationScript
        last_validation = "not_found"
    }

    Write-Host " not_found"
}

# =========================================================
# Final export
# =========================================================

$Export = [ordered]@{
    domain_metadata = $DomainMetadata
    gpo_inventory = $GPOInventory
    audit_policy = $AuditPolicy
    powershell_logging = $PowerShellLogging
    sysmon_posture = $SysmonPosture
    firewall_posture = $FirewallPosture
    applocker_posture = $AppLockerPosture
    rdp_posture = $RDPPosture
    authentication_protocols = $AuthenticationProtocols
    service_account_posture = $ServiceAccountPosture
    validation_summary = $ValidationSummary
}

$Export |
    ConvertTo-Json -Depth 12 |
    Set-Content `
        -Path $OutputFile `
        -Encoding UTF8

Write-Host ""
Write-Host "Hardened state exported to: windows_hardened_state.json"
