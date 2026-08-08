#!/usr/bin/env pwsh
# name: 9-windows_attack_sim.ps1
# purpose: Controlled Windows attacker simulation
# author: analyst

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$OutputFile = Join-Path $PSScriptRoot "windowsattacklog.json"

$TestUser = "support_update"
$TestPasswordPlain = "TempP@ssw0rd!9x"
$TestPassword = ConvertTo-SecureString $TestPasswordPlain -AsPlainText -Force

$TaskName = "SupportUpdateMaintenance"

$StartupDir = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
$StartupFile = Join-Path $StartupDir "support_update.ps1"

$Actions = @()

function Get-UtcTimestamp {
    return (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
}

function Add-Action {
    param(
        [int]$Number,
        [string]$Description,
        [string]$Timestamp,
        [string]$ExpectedDetectionSource,
        [string]$Technique
    )

    $script:Actions += [ordered]@{
        action_number             = $Number
        description               = $Description
        timestamp                 = $Timestamp
        expected_detection_source = $ExpectedDetectionSource
        mitre_attack_technique    = $Technique
    }
}

Write-Host "[*] Running Windows attacker simulation..."

try {

    # ---------------------------------------------------------
    # 1. Create local user
    # ---------------------------------------------------------

    Write-Host "    [1/6] Creating local user '$TestUser'..." -NoNewline

    $ExistingUser = Get-LocalUser -Name $TestUser -ErrorAction SilentlyContinue

    if (-not $ExistingUser) {
        New-LocalUser `
            -Name $TestUser `
            -Password $TestPassword `
            -Description "Controlled attacker simulation account" `
            -AccountNeverExpires:$true `
            -PasswordNeverExpires:$true `
            -UserMayNotChangePassword:$true | Out-Null
    }

    $Timestamp = Get-UtcTimestamp

    Add-Action `
        1 `
        "Create local user support_update" `
        $Timestamp `
        "Security Event ID 4720; Sysmon Event ID 1" `
        "T1136.001 - Create Account: Local Account"

    Write-Host " $Timestamp"


    # ---------------------------------------------------------
    # 2. Add user to Administrators
    # ---------------------------------------------------------

    Write-Host "    [2/6] Adding to Administrators group..." -NoNewline

    Add-LocalGroupMember `
        -Group "Administrators" `
        -Member $TestUser `
        -ErrorAction SilentlyContinue

    $Timestamp = Get-UtcTimestamp

    Add-Action `
        2 `
        "Add support_update to Administrators group" `
        $Timestamp `
        "Security Event ID 4732" `
        "T1098.007 - Account Manipulation: Additional Local or Domain Groups"

    Write-Host " $Timestamp"


    # ---------------------------------------------------------
    # 3. Encoded PowerShell
    # ---------------------------------------------------------

    Write-Host "    [3/6] Running encoded PowerShell..." -NoNewline

    $Payload = 'Write-Host "C2 beacon"'

    $EncodedPayload = [Convert]::ToBase64String(
        [Text.Encoding]::Unicode.GetBytes($Payload)
    )

    powershell.exe `
        -NoProfile `
        -EncodedCommand $EncodedPayload | Out-Null

    $Timestamp = Get-UtcTimestamp

    Add-Action `
        3 `
        "Run encoded PowerShell harmless payload" `
        $Timestamp `
        "Sysmon Event ID 1; PowerShell Event ID 4104" `
        "T1059.001 - Command and Scripting Interpreter: PowerShell"

    Write-Host " $Timestamp"


    # ---------------------------------------------------------
    # 4. Scheduled task persistence
    # ---------------------------------------------------------

    Write-Host "    [4/6] Creating scheduled task..." -NoNewline

    schtasks.exe /Create `
        /TN $TaskName `
        /TR "cmd.exe /c echo Controlled simulation" `
        /SC ONCE `
        /ST 23:59 `
        /F | Out-Null

    $Timestamp = Get-UtcTimestamp

    Add-Action `
        4 `
        "Create scheduled task for persistence" `
        $Timestamp `
        "Security Event ID 4698; Sysmon Event ID 1" `
        "T1053.005 - Scheduled Task/Job: Scheduled Task"

    Write-Host " $Timestamp"


    # ---------------------------------------------------------
    # 5. Outbound connection
    # ---------------------------------------------------------

    Write-Host "    [5/6] Outbound network connection..." -NoNewline

    Test-NetConnection `
        -ComputerName "1.1.1.1" `
        -Port 443 `
        -InformationLevel Quiet | Out-Null

    $Timestamp = Get-UtcTimestamp

    Add-Action `
        5 `
        "Initiate outbound TCP connection to 1.1.1.1:443" `
        $Timestamp `
        "Sysmon Event ID 3" `
        "T1071.001 - Application Layer Protocol: Web Protocols"

    Write-Host " $Timestamp"


    # ---------------------------------------------------------
    # 6. Startup file
    # ---------------------------------------------------------

    Write-Host "    [6/6] Dropping file in Startup..." -NoNewline

    if (-not (Test-Path $StartupDir)) {
        New-Item `
            -ItemType Directory `
            -Path $StartupDir `
            -Force | Out-Null
    }

    Set-Content `
        -Path $StartupFile `
        -Value "# Controlled attacker simulation artifact" `
        -Encoding UTF8

    $Timestamp = Get-UtcTimestamp

    Add-Action `
        6 `
        "Drop file in Windows Startup directory" `
        $Timestamp `
        "Sysmon Event ID 11" `
        "T1547.001 - Registry Run Keys / Startup Folder"

    Write-Host " $Timestamp"


    # ---------------------------------------------------------
    # Save ground truth BEFORE cleanup
    # ---------------------------------------------------------

    $Report = [ordered]@{
        simulation       = "Windows Attacker Simulation"
        timestamp_format = "UTC ISO 8601"
        actions_executed = $Actions.Count
        actions          = $Actions
    }

    $Report |
        ConvertTo-Json -Depth 5 |
        Set-Content -Path $OutputFile -Encoding UTF8


    # ---------------------------------------------------------
    # Cleanup
    # ---------------------------------------------------------

    Write-Host "[*] Cleaning up artifacts..."

    if (Get-LocalUser -Name $TestUser -ErrorAction SilentlyContinue) {
        Remove-LocalUser -Name $TestUser
    }

    schtasks.exe /Delete /TN $TaskName /F 2>$null | Out-Null

    if (Test-Path $StartupFile) {
        Remove-Item -Path $StartupFile -Force
    }

    Write-Host "    User removed, task deleted, file removed           [CLEAN]"
    Write-Host "Actions executed: $($Actions.Count)"
    Write-Host "Ground truth saved to: $OutputFile"

}
catch {

    Write-Host ""
    Write-Host "[!] Simulation stopped: $($_.Exception.Message)"

    # Best-effort cleanup
    try {
        if (Get-LocalUser -Name $TestUser -ErrorAction SilentlyContinue) {
            Remove-LocalUser -Name $TestUser -ErrorAction SilentlyContinue
        }
    } catch {}

    try {
        schtasks.exe /Delete /TN $TaskName /F 2>$null | Out-Null
    } catch {}

    try {
        if (Test-Path $StartupFile) {
            Remove-Item -Path $StartupFile -Force -ErrorAction SilentlyContinue
        }
    } catch {}

    throw
}
