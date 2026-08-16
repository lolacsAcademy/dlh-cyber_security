<#
Script Name: 14-service_accounts.ps1
Purpose: Audit and harden MedDefense service accounts.
# Author: Student
# excessive
# old
# Suspicious svc_ehr last logon reference: 03:17 AM
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory

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
        -Properties PasswordLastSet,LastLogonDate,
                    TrustedForDelegation,AccountNotDelegated,
                    ServicePrincipalName,MemberOf,UseDESKeyOnly
)

if ($ServiceAccounts.Count -eq 0) {
    throw "No svc_* service accounts were found."
}

Write-Host "[*] Auditing MedDefense service accounts..."

foreach ($Account in $ServiceAccounts) {

    Write-Host ""
    Write-Host "$($Account.SamAccountName):"

    # Password age
    if ($null -ne $Account.PasswordLastSet) {
        $PasswordAge = (
            New-TimeSpan `
                -Start $Account.PasswordLastSet `
                -End (Get-Date)
        ).Days

        if ($PasswordAge -gt 90) {
            Write-Host "  Password age: $PasswordAge days                  [!]"
        }
        else {
            Write-Host "  Password age: $PasswordAge days                  [OK]"
        }
    }
    else {
        Write-Host "  Password age: Unknown                           [!]"
    }

    # Last logon
    if ($null -ne $Account.LastLogonDate) {
        Write-Host "  Last logon: $($Account.LastLogonDate)"
    }
    else {
        Write-Host "  Last logon: Not recorded"
    }

    # Delegation
    if ($Account.TrustedForDelegation) {
        Write-Host "  Delegation: Unconstrained                       [!]"
    }
    elseif ($Account.AccountNotDelegated) {
        Write-Host "  Delegation: Sensitive / cannot be delegated     [OK]"
    }
    else {
        Write-Host "  Delegation: Not unconstrained"
    }

    # DES
    if ($Account.UseDESKeyOnly) {
        Write-Host "  UseDESKeyOnly: True                             [!]"
    }
    else {
        Write-Host "  UseDESKeyOnly: False                            [OK]"
    }

    # SPNs
    if ($Account.ServicePrincipalName.Count -gt 0) {
        Write-Host "  SPN configuration:"
        foreach ($SPN in $Account.ServicePrincipalName) {
            Write-Host "    $SPN"
        }
    }
    else {
        Write-Host "  SPN configuration: None"
    }

    # Group memberships
    $Groups = @(
        foreach ($DN in $Account.MemberOf) {
            (Get-ADGroup -Identity $DN).Name
        }
    )

    if ($Groups.Count -eq 0) {
        Write-Host "  Group memberships: None"
    }
    else {
        Write-Host "  Group memberships: $($Groups -join ', ')"
    }

    # -----------------------------------------------------
    # Remediation 1:
    # Sensitive and cannot be delegated
    # Also remove unconstrained delegation.
    # -----------------------------------------------------

    Set-ADAccountControl `
        -Identity $Account.SamAccountName `
        -TrustedForDelegation $false `
        -AccountNotDelegated $true

    Write-Host "  Account is sensitive and cannot be delegated    [SET]"

    # -----------------------------------------------------
    # Remediation 2:
    # Remove service account from privileged groups.
    # -----------------------------------------------------

    foreach ($GroupName in $PrivilegedGroups) {

        if ($Groups -contains $GroupName) {
            Remove-ADGroupMember `
                -Identity $GroupName `
                -Members $Account.SamAccountName `
                -Confirm:$false

            Write-Host "  Removed from privileged group: $GroupName       [DONE]"
        }
    }
}

# ---------------------------------------------------------
# Remediation 3:
# Deny interactive logon for service accounts.
#
# SeDenyInteractiveLogonRight
# SeDenyRemoteInteractiveLogonRight
#
# Apply through local security policy using SID values.
# ---------------------------------------------------------

Write-Host ""
Write-Host "[*] Configuring deny interactive logon rights..."

$Sids = @(
    foreach ($Account in $ServiceAccounts) {
        (Get-ADUser $Account.SamAccountName).SID.Value
    }
)

$SidList = ($Sids | ForEach-Object { "*$_" }) -join ","

$ExportFile = Join-Path $env:TEMP "meddefense_secpol.cfg"
$DatabaseFile = Join-Path $env:TEMP "meddefense_secpol.sdb"

& secedit.exe /export /cfg $ExportFile /quiet

if (-not (Test-Path $ExportFile)) {
    throw "Could not export local security policy."
}

$Policy = Get-Content $ExportFile

function Set-UserRight {
    param(
        [string[]]$Content,
        [string]$Right,
        [string]$Values
    )

    $Found = $false

    $Updated = foreach ($Line in $Content) {
        if ($Line -match "^$([regex]::Escape($Right))\s*=") {
            $Found = $true
            "$Right = $Values"
        }
        else {
            $Line
        }
    }

    if (-not $Found) {
        $Updated += "$Right = $Values"
    }

    return $Updated
}

$Policy = Set-UserRight `
    -Content $Policy `
    -Right "SeDenyInteractiveLogonRight" `
    -Values $SidList

$Policy = Set-UserRight `
    -Content $Policy `
    -Right "SeDenyRemoteInteractiveLogonRight" `
    -Values $SidList

$Policy |
    Set-Content `
        -Path $ExportFile `
        -Encoding Unicode

& secedit.exe `
    /configure `
    /db $DatabaseFile `
    /cfg $ExportFile `
    /areas USER_RIGHTS `
    /quiet

if ($LASTEXITCODE -ne 0) {
    throw "Failed to configure deny interactive logon rights."
}

Write-Host "    Interactive logon: Denied                     [SET]"
Write-Host "    Remote interactive logon: Denied              [SET]"

# ---------------------------------------------------------
# Verification
# ---------------------------------------------------------

Write-Host "[*] Verification..."

foreach ($Account in $ServiceAccounts) {

    $Check = Get-ADUser `
        -Identity $Account.SamAccountName `
        -Properties TrustedForDelegation,AccountNotDelegated

    if (
        $Check.TrustedForDelegation -eq $true -or
        $Check.AccountNotDelegated -ne $true
    ) {
        throw "Delegation verification failed for $($Account.SamAccountName)."
    }

    Write-Host "    $($Account.SamAccountName): delegation hardened [VERIFIED]"
}

Write-Host "[*] Service account hardening completed successfully."
