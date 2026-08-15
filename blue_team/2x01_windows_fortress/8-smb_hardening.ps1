<#
Script Name: 8-smb_hardening.ps1
Purpose: Harden SMB and legacy Windows network protocols for MedDefense.
Author: Student
Date: 2026-08-15
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module GroupPolicy
Import-Module ActiveDirectory

$GPOName = "MedDefense - SMB and Protocol Hardening"

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
# Current configuration
# ---------------------------------------------------------

Write-Host "[*] Current SMB Configuration..."

$BeforeServer = Get-SmbServerConfiguration
$BeforeClient = Get-SmbClientConfiguration

$BeforeSMB1 = $BeforeServer.EnableSMB1Protocol
$BeforeSigning = $BeforeServer.RequireSecuritySignature
$BeforeEncryption = $BeforeServer.EncryptData

Write-Host "    SMBv1: $BeforeSMB1"
Write-Host "    Signing Required: $BeforeSigning"
Write-Host "    Encryption: $BeforeEncryption"

# ---------------------------------------------------------
# Disable SMBv1 server
# ---------------------------------------------------------

Write-Host "[*] Disabling SMBv1 (server + client)..." -NoNewline

Set-SmbServerConfiguration `
    -EnableSMB1Protocol $false `
    -Force

# Disable/remove SMBv1 Windows feature when present
$SMB1Feature = Get-WindowsOptionalFeature `
    -Online `
    -FeatureName SMB1Protocol `
    -ErrorAction SilentlyContinue

if ($null -ne $SMB1Feature -and $SMB1Feature.State -eq "Enabled") {
    Disable-WindowsOptionalFeature `
        -Online `
        -FeatureName SMB1Protocol `
        -NoRestart |
        Out-Null
}

Write-Host "   [DONE]"

# ---------------------------------------------------------
# Enforce SMB signing
# ---------------------------------------------------------

Write-Host "[*] Enforcing SMB Signing..." -NoNewline

Set-SmbServerConfiguration `
    -RequireSecuritySignature $true `
    -EnableSecuritySignature $true `
    -Force

Set-SmbClientConfiguration `
    -RequireSecuritySignature $true `
    -EnableSecuritySignature $true `
    -Confirm:$false

Write-Host "               [SET]"

# ---------------------------------------------------------
# Enable SMB encryption
# ---------------------------------------------------------

Write-Host "[*] Enabling SMB Encryption..." -NoNewline

Set-SmbServerConfiguration `
    -EncryptData $true `
    -Force

Write-Host "             [SET]"

# ---------------------------------------------------------
# Disable NetBIOS over TCP/IP
# ---------------------------------------------------------

Write-Host "[*] Disabling NetBIOS over TCP/IP..." -NoNewline

$Adapters = Get-CimInstance `
    -ClassName Win32_NetworkAdapterConfiguration |
    Where-Object { $_.IPEnabled -eq $true }

foreach ($Adapter in $Adapters) {
    $Result = Invoke-CimMethod `
        -InputObject $Adapter `
        -MethodName SetTcpipNetbios `
        -Arguments @{ TcpipNetbiosOptions = 2 }

    if ($Result.ReturnValue -ne 0) {
        throw "Failed to disable NetBIOS on adapter $($Adapter.Description)"
    }
}

Write-Host "       [SET]"

# ---------------------------------------------------------
# Create GPO for LLMNR
# ---------------------------------------------------------

$Domain = Get-ADDomain
$DomainDN = $Domain.DistinguishedName

$ExistingGPO = Get-GPO `
    -Name $GPOName `
    -ErrorAction SilentlyContinue

if ($null -eq $ExistingGPO) {
    New-GPO `
        -Name $GPOName `
        -Comment "MedDefense SMB and legacy protocol hardening." |
        Out-Null
}

Write-Host "[*] Disabling LLMNR via GPO..." -NoNewline

Set-GPRegistryValue `
    -Name $GPOName `
    -Key "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" `
    -ValueName "EnableMulticast" `
    -Type DWord `
    -Value 0

Write-Host "             [SET]"

# ---------------------------------------------------------
# Link GPO
# ---------------------------------------------------------

$Inheritance = Get-GPInheritance -Target $DomainDN

$AlreadyLinked = $Inheritance.GpoLinks |
    Where-Object { $_.DisplayName -eq $GPOName }

if ($null -eq $AlreadyLinked) {
    New-GPLink `
        -Name $GPOName `
        -Target $DomainDN `
        -LinkEnabled Yes |
        Out-Null
}

# ---------------------------------------------------------
# Force policy update
# ---------------------------------------------------------

& gpupdate.exe /force | Out-Null

if ($LASTEXITCODE -ne 0) {
    throw "Group Policy update failed."
}

# ---------------------------------------------------------
# Verification
# ---------------------------------------------------------

Write-Host "[*] Verification..."

$AfterServer = Get-SmbServerConfiguration
$AfterClient = Get-SmbClientConfiguration

if ($AfterServer.EnableSMB1Protocol -eq $false) {
    Write-Host "    SMBv1: Disabled                        [VERIFIED]"
}
else {
    throw "SMBv1 verification failed."
}

if (
    $AfterServer.RequireSecuritySignature -eq $true -and
    $AfterClient.RequireSecuritySignature -eq $true
) {
    Write-Host "    Signing: Required                      [VERIFIED]"
}
else {
    throw "SMB signing verification failed."
}

if ($AfterServer.EncryptData -eq $true) {
    Write-Host "    Encryption: Enabled                    [VERIFIED]"
}
else {
    throw "SMB encryption verification failed."
}

$LLMNR = Get-ItemProperty `
    -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" `
    -Name "EnableMulticast" `
    -ErrorAction SilentlyContinue

if ($null -ne $LLMNR -and $LLMNR.EnableMulticast -eq 0) {
    Write-Host "    LLMNR: Disabled                        [VERIFIED]"
}
else {
    throw "LLMNR verification failed."
}

$NetBIOSCheck = @(
    Get-CimInstance Win32_NetworkAdapterConfiguration |
    Where-Object {
        $_.IPEnabled -eq $true -and
        $_.TcpipNetbiosOptions -ne 2
    }
)

if ($NetBIOSCheck.Count -eq 0) {
    Write-Host "    NetBIOS over TCP/IP: Disabled          [VERIFIED]"
}
else {
    throw "NetBIOS verification failed."
}
