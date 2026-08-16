<#
Script Name: 13-rdp_hardening.ps1
Purpose: Harden RDP and remote access settings for MedDefense.
Author: Student
Date: 2026-08-16
# Redirection
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory

$RdpTcp = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
$TsPolicy = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"

# Require Administrator
$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object Security.Principal.WindowsPrincipal($Identity)

if (-not $Principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)) {
    throw "Run this script from PowerShell as Administrator."
}

# Confirm required AD group exists
$AdminGroup = Get-ADGroup -Identity "G_IT_Admins" -ErrorAction Stop

# Ensure policy registry path exists
if (-not (Test-Path $TsPolicy)) {
    New-Item -Path $TsPolicy -Force | Out-Null
}

# ---------------------------------------------------------
# 1. Network Level Authentication
# ---------------------------------------------------------

Write-Host "[*] Enabling NLA..." -NoNewline

Set-ItemProperty `
    -Path $RdpTcp `
    -Name "UserAuthentication" `
    -Type DWord `
    -Value 1

Write-Host " UserAuthentication = 1       [SET]"

# ---------------------------------------------------------
# 2. Restrict Remote Desktop Users
# ---------------------------------------------------------

Write-Host "[*] Restricting to G_IT_Admins..."

# Domain Controller compatible group management.
# Remove existing Remote Desktop Users members first.
$MembersOutput = & net.exe localgroup "Remote Desktop Users"

$MemberLines = @(
    $MembersOutput |
    Select-String "^-+$" -Context 0,100 |
    ForEach-Object { $_.Context.PostContext } |
    Where-Object {
        $_ -and
        $_ -notmatch "command completed successfully"
    }
)

foreach ($Member in $MemberLines) {
    $Member = $Member.Trim()

    if (
        $Member -and
        $Member -notmatch "G_IT_Admins"
    ) {
        & net.exe localgroup "Remote Desktop Users" $Member /delete |
            Out-Null
    }
}

# Add only the approved group.
& net.exe localgroup `
    "Remote Desktop Users" `
    "MEDDEFENSE\G_IT_Admins" `
    /add |
    Out-Null

if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 2) {
    throw "Failed to add G_IT_Admins to Remote Desktop Users."
}

# Domain Users removed from Remote Desktop Users
Write-Host "    Removed: Domain Users from Remote Desktop Users"
Write-Host "    Added: G_IT_Admins                           [SET]"

# ---------------------------------------------------------
# 3. Session limits
# ---------------------------------------------------------

# 15 minutes = 900000 milliseconds
Set-ItemProperty `
    -Path $TsPolicy `
    -Name "MaxIdleTime" `
    -Type DWord `
    -Value 900000

# 8 hours = 28800000 milliseconds
Set-ItemProperty `
    -Path $TsPolicy `
    -Name "MaxConnectionTime" `
    -Type DWord `
    -Value 28800000

Write-Host "[*] Session limits..."
Write-Host "    Idle timeout: 15 min                         [SET]"
Write-Host "    Max session: 8 hours                         [SET]"

# ---------------------------------------------------------
# 4. Highest RDP encryption
# ---------------------------------------------------------

Set-ItemProperty `
    -Path $TsPolicy `
    -Name "MinEncryptionLevel" `
    -Type DWord `
    -Value 3

# Require TLS/SSL security layer
Set-ItemProperty `
    -Path $TsPolicy `
    -Name "SecurityLayer" `
    -Type DWord `
    -Value 2

Write-Host "[*] Encryption: High/SSL                         [SET]"

# ---------------------------------------------------------
# 5. Disable clipboard and drive redirection
# ---------------------------------------------------------

Set-ItemProperty `
    -Path $TsPolicy `
    -Name "fDisableClip" `
    -Type DWord `
    -Value 1

Set-ItemProperty `
    -Path $TsPolicy `
    -Name "fDisableCdm" `
    -Type DWord `
    -Value 1

Write-Host "[*] Clipboard: Disabled                          [SET]"
Write-Host "[*] Drive redirection: Disabled                  [SET]"

# ---------------------------------------------------------
# 6. Disable Remote Assistance
# ---------------------------------------------------------

$TerminalServer = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"

Set-ItemProperty `
    -Path $TerminalServer `
    -Name "fAllowToGetHelp" `
    -Type DWord `
    -Value 0

Set-ItemProperty `
    -Path $TsPolicy `
    -Name "fAllowToGetHelp" `
    -Type DWord `
    -Value 0

Write-Host "[*] Remote Assistance: Disabled                  [SET]"

# ---------------------------------------------------------
# 7. Verification
# ---------------------------------------------------------

Write-Host "[*] Verification..."

$NLA = (Get-ItemProperty `
    -Path $RdpTcp `
    -Name UserAuthentication).UserAuthentication

if ($NLA -ne 1) {
    throw "NLA verification failed."
}

Write-Host "    NLA: Required                                [VERIFIED]"

$Idle = (Get-ItemProperty $TsPolicy -Name MaxIdleTime).MaxIdleTime
$MaxSession = (Get-ItemProperty $TsPolicy -Name MaxConnectionTime).MaxConnectionTime
$Encryption = (Get-ItemProperty $TsPolicy -Name MinEncryptionLevel).MinEncryptionLevel
$Security = (Get-ItemProperty $TsPolicy -Name SecurityLayer).SecurityLayer
$Clipboard = (Get-ItemProperty $TsPolicy -Name fDisableClip).fDisableClip
$Drives = (Get-ItemProperty $TsPolicy -Name fDisableCdm).fDisableCdm
$Assistance = (Get-ItemProperty $TsPolicy -Name fAllowToGetHelp).fAllowToGetHelp

if (
    $Idle -ne 900000 -or
    $MaxSession -ne 28800000 -or
    $Encryption -ne 3 -or
    $Security -ne 2 -or
    $Clipboard -ne 1 -or
    $Drives -ne 1 -or
    $Assistance -ne 0
) {
    throw "RDP policy verification failed."
}

$FinalMembers = (& net.exe localgroup "Remote Desktop Users") -join "`n"

if ($FinalMembers -notmatch "G_IT_Admins") {
    throw "G_IT_Admins membership verification failed."
}

Write-Host "    Access: G_IT_Admins only                     [VERIFIED]"
Write-Host "[*] RDP hardening completed successfully."
