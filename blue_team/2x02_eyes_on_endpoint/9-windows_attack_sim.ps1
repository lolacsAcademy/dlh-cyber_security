# name: 9-windowsattacksim.ps1
# purpose: Controlled Windows attacker simulation
# author: analyst

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$OutputFile = Join-Path $PSScriptRoot "windows_attack_log.json"
$CompatOutputFile = Join-Path $PSScriptRoot "windowsattacklog.json"

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
        [string]$MITRE
    )

    $script:Actions += [ordered]@{
        action_number = $Number
        description = $Description
        timestamp = $Timestamp
        expected_detection_source = $ExpectedDetectionSource
        MITRE_attack_technique = $MITRE
    }
}

Write-Host "[*] Running Windows attacker simulation..."

try {

    Write-Host "    [1/6] Creating user '$TestUser'..." -NoNewline

    $ExistingUser = Get-ADUser `
        -Filter "SamAccountName -eq '$TestUser'" `
        -ErrorAction SilentlyContinue

    if ($ExistingUser) {
        Remove-ADGroupMember `
            -Identity "Administrators" `
            -Members $TestUser `
            -Confirm:$false `
            -ErrorAction SilentlyContinue

        Remove-ADUser `
            -Identity $ExistingUser `
            -Confirm:$false `
            -ErrorAction SilentlyContinue

        Start-Sleep -Seconds 1
    }

    New-ADUser `
        -Name $TestUser `
        -SamAccountName $TestUser `
        -AccountPassword $TestPassword `
        -Enabled $true `
        -Description "Controlled attacker simulation account"

    $ts = Get-UtcTimestamp

    Add-Action 1 `
        "Create local user support_update" `
        $ts `
        "Security Event ID 4720" `
        "T1136.001 - Create Account: Local Account"

    Write-Host " $ts"


    Write-Host "    [2/6] Adding to Administrators group..." -NoNewline

    Add-ADGroupMember `
        -Identity "Administrators" `
        -Members $TestUser

    $ts = Get-UtcTimestamp

    Add-Action 2 `
        "Add support_update to Administrators group" `
        $ts `
        "Security Event ID 4732" `
        "T1098.007 - Account Manipulation: Additional Local or Domain Groups"

    Write-Host " $ts"


    Write-Host "    [3/6] Running encoded PowerShell..." -NoNewline

    $Payload = 'Write-Host "C2 beacon"'

    $EncodedPayload = [Convert]::ToBase64String(
        [Text.Encoding]::Unicode.GetBytes($Payload)
    )

    powershell.exe -NoProfile -enc $EncodedPayload | Out-Null

    $ts = Get-UtcTimestamp

    Add-Action 3 `
        "Run encoded PowerShell harmless payload" `
        $ts `
        "Sysmon Event ID 1; PowerShell Event ID 4104" `
        "T1059.001 - Command and Scripting Interpreter: PowerShell"

    Write-Host " $ts"


    Write-Host "    [4/6] Creating scheduled task..." -NoNewline

    schtasks.exe /create `
        /TN $TaskName `
        /TR "cmd.exe /c echo Controlled simulation" `
        /SC ONCE `
        /ST 23:59 `
        /F | Out-Null

    $ts = Get-UtcTimestamp

    Add-Action 4 `
        "Create scheduled task for persistence" `
        $ts `
        "Security Event ID 4698; Sysmon Event ID 1" `
        "T1053.005 - Scheduled Task/Job: Scheduled Task"

    Write-Host " $ts"


    Write-Host "    [5/6] Outbound network connection..." -NoNewline

    Test-NetConnection `
        -ComputerName "1.1.1.1" `
        -Port 443 `
        -InformationLevel Quiet | Out-Null

    $ts = Get-UtcTimestamp

    Add-Action 5 `
        "Initiate outbound TCP connection to 1.1.1.1:443" `
        $ts `
        "Sysmon Event ID 3" `
        "T1071.001 - Application Layer Protocol: Web Protocols"

    Write-Host " $ts"


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

    $ts = Get-UtcTimestamp

    Add-Action 6 `
        "Drop file in Windows Startup directory" `
        $ts `
        "Sysmon Event ID 11" `
        "T1547.001 - Registry Run Keys / Startup Folder"

    Write-Host " $ts"


    $Report = [ordered]@{
        simulation = "Windows Attacker Simulation"
        timestamp_format = "UTC ISO 8601"
        actions_executed = $Actions.Count
        actions = $Actions
    }

    $Report |
        ConvertTo-Json -Depth 5 |
        Set-Content `
            -Path $OutputFile `
            -Encoding UTF8

    Copy-Item `
        -Path $OutputFile `
        -Destination $CompatOutputFile `
        -Force


    Write-Host "[*] Cleaning up artifacts..."

    Remove-ADGroupMember `
        -Identity "Administrators" `
        -Members $TestUser `
        -Confirm:$false `
        -ErrorAction SilentlyContinue

    Remove-ADUser `
        -Identity $TestUser `
        -Confirm:$false `
        -ErrorAction SilentlyContinue

    Unregister-ScheduledTask `
        -TaskName $TaskName `
        -Confirm:$false `
        -ErrorAction SilentlyContinue

    if (Test-Path $StartupFile) {
        Remove-Item `
            -Path $StartupFile `
            -Force `
            -ErrorAction SilentlyContinue
    }

    Write-Host "    User removed, task deleted, file removed [CLEAN]"
    Write-Host "Actions executed: $($Actions.Count)"
    Write-Host "Ground truth saved to: $OutputFile"
}

catch {

    Write-Host ""
    Write-Host "[!] Simulation failed: $($_.Exception.Message)"

    try {
        Remove-ADGroupMember `
            -Identity "Administrators" `
            -Members $TestUser `
            -Confirm:$false `
            -ErrorAction SilentlyContinue
    } catch {}

    try {
        Remove-ADUser `
            -Identity $TestUser `
            -Confirm:$false `
            -ErrorAction SilentlyContinue
    } catch {}

    try {
        Unregister-ScheduledTask `
            -TaskName $TaskName `
            -Confirm:$false `
            -ErrorAction SilentlyContinue
    } catch {}

    try {
        if (Test-Path $StartupFile) {
            Remove-Item `
                -Path $StartupFile `
                -Force `
                -ErrorAction SilentlyContinue
        }
    } catch {}

    throw
}
