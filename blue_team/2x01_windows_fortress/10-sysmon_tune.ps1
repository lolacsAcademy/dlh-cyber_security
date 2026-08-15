<#
Script Name: 10-sysmon_tune.ps1
Purpose: Add and validate MedDefense-specific Sysmon detection rules.
Author: Student
Date: 2026-08-15
# -enc
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ConfigPath = Join-Path $PSScriptRoot "sysmonconfig.xml"
$BackupPath = Join-Path $PSScriptRoot "sysmonconfig.pre-tune.xml"
$EventLog = "Microsoft-Windows-Sysmon/Operational"

# ---------------------------------------------------------
# Administrator check
# ---------------------------------------------------------

$CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object Security.Principal.WindowsPrincipal($CurrentUser)

if (-not $Principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)) {
    throw "Run this script from PowerShell as Administrator."
}

# ---------------------------------------------------------
# Find Sysmon executable
# ---------------------------------------------------------

$PossibleSysmon = @(
    (Join-Path $PSScriptRoot "Sysmon\Sysmon64.exe"),
    "C:\Windows\Sysmon64.exe",
    "C:\Windows\Sysmon.exe"
)

$SysmonExe = $PossibleSysmon |
    Where-Object { Test-Path $_ } |
    Select-Object -First 1

if ($null -eq $SysmonExe) {

    $SysmonService = Get-CimInstance Win32_Service |
        Where-Object { $_.Name -in @("Sysmon64", "Sysmon") } |
        Select-Object -First 1

    if ($null -ne $SysmonService) {

        if ($SysmonService.PathName -match '^"([^"]+)"') {
            $SysmonExe = $Matches[1]
        }
        else {
            $SysmonExe = ($SysmonService.PathName -split '\s+')[0]
        }
    }
}

if (
    $null -eq $SysmonExe -or
    -not (Test-Path $SysmonExe)
) {
    throw "Sysmon executable could not be found."
}

# ---------------------------------------------------------
# Load current config
# ---------------------------------------------------------

Write-Host "[*] Loading Sysmon config..." -NoNewline

if (-not (Test-Path $ConfigPath)) {
    throw "sysmonconfig.xml was not found."
}

$ConfigContent = Get-Content `
    -Path $ConfigPath `
    -Raw

# Validate existing XML before modifying it
try {
    [xml]$null = $ConfigContent
}
catch {
    throw "Existing sysmonconfig.xml is not valid XML."
}

Write-Host " OK"

# ---------------------------------------------------------
# Backup original
# ---------------------------------------------------------

Copy-Item `
    -Path $ConfigPath `
    -Destination $BackupPath `
    -Force

# ---------------------------------------------------------
# Remove previous MedDefense block if script is rerun
# ---------------------------------------------------------

$BeginMarker = "<!-- BEGIN MEDDEFENSE CUSTOM RULES -->"
$EndMarker   = "<!-- END MEDDEFENSE CUSTOM RULES -->"

$Pattern =
    "(?s)" +
    [regex]::Escape($BeginMarker) +
    ".*?" +
    [regex]::Escape($EndMarker)

$ConfigContent = [regex]::Replace(
    $ConfigContent,
    $Pattern,
    ""
)

# ---------------------------------------------------------
# Five custom detection rules
# ---------------------------------------------------------

$CustomRules = @'

<!-- BEGIN MEDDEFENSE CUSTOM RULES -->

<!-- Rule 1: Rclone execution -->
<RuleGroup name="MedDefense - Rclone Detection" groupRelation="or">
  <ProcessCreate onmatch="include">
    <Rule name="MedDefense Rclone Execution" groupRelation="or">
      <Image condition="end with">\rclone.exe</Image>
      <CommandLine condition="contains">rclone.exe</CommandLine>
    </Rule>
  </ProcessCreate>
</RuleGroup>

<!-- Rule 2: PsExec service registry modification -->
<RuleGroup name="MedDefense - PsExec Service Installation" groupRelation="or">
  <RegistryEvent onmatch="include">
    <Rule name="MedDefense PsExec Registry" groupRelation="or">
      <TargetObject condition="contains">\Services\PSEXESVC</TargetObject>
    </Rule>
  </RegistryEvent>
</RuleGroup>

<!-- Rule 3: Encoded PowerShell -->
<RuleGroup name="MedDefense - Encoded PowerShell" groupRelation="or">
  <ProcessCreate onmatch="include">
    <Rule name="MedDefense Encoded PowerShell" groupRelation="and">
      <Image condition="end with">\powershell.exe</Image>
      <CommandLine condition="contains">-EncodedCommand</CommandLine>
    </Rule>
  </ProcessCreate>
</RuleGroup>

<!-- Rule 4: VSS shadow deletion -->
<RuleGroup name="MedDefense - Shadow Deletion" groupRelation="or">
  <ProcessCreate onmatch="include">
    <Rule name="MedDefense Vssadmin Delete Shadows" groupRelation="and">
      <Image condition="end with">\vssadmin.exe</Image>
      <CommandLine condition="contains">delete shadows</CommandLine>
    </Rule>
  </ProcessCreate>
</RuleGroup>

<!-- Rule 5: Scheduled task creation -->
<RuleGroup name="MedDefense - Scheduled Task Persistence" groupRelation="or">
  <ProcessCreate onmatch="include">
    <Rule name="MedDefense Scheduled Task Creation" groupRelation="and">
      <Image condition="end with">\schtasks.exe</Image>
      <CommandLine condition="contains">/create</CommandLine>
    </Rule>
  </ProcessCreate>
</RuleGroup>

<!-- END MEDDEFENSE CUSTOM RULES -->

'@

Write-Host "[*] Adding custom rules..."

if ($ConfigContent -notmatch "</EventFiltering>") {
    throw "EventFiltering section was not found."
}

$ConfigContent = $ConfigContent.Replace(
    "</EventFiltering>",
    "$CustomRules`r`n</EventFiltering>"
)

Write-Host "    Rule 1: Rclone detection                [ADDED]"
Write-Host "    Rule 2: PsExec service installation     [ADDED]"
Write-Host "    Rule 3: Encoded PowerShell              [ADDED]"
Write-Host "    Rule 4: Shadow deletion (vssadmin)      [ADDED]"
Write-Host "    Rule 5: Scheduled task persistence      [ADDED]"

# ---------------------------------------------------------
# Validate new XML before applying
# ---------------------------------------------------------

try {
    [xml]$null = $ConfigContent
}
catch {
    Copy-Item $BackupPath $ConfigPath -Force
    throw "Modified Sysmon configuration is invalid XML."
}

Set-Content `
    -Path $ConfigPath `
    -Value $ConfigContent `
    -Encoding UTF8

# ---------------------------------------------------------
# Update running Sysmon configuration
# ---------------------------------------------------------

Write-Host "[*] Updating Sysmon config..." -NoNewline

& $SysmonExe -c $ConfigPath | Out-Null

if ($LASTEXITCODE -ne 0) {
    Copy-Item $BackupPath $ConfigPath -Force
    throw "Sysmon rejected the updated configuration."
}

Write-Host " OK"

Start-Sleep -Seconds 3

# ---------------------------------------------------------
# Event verification helper
# ---------------------------------------------------------

function Test-SysmonEvent {

    param(
        [int]$EventId,
        [datetime]$StartTime,
        [string[]]$Patterns
    )

    for ($Attempt = 1; $Attempt -le 10; $Attempt++) {

        $Events = @(
            Get-WinEvent `
                -FilterHashtable @{
                    LogName   = $EventLog
                    Id        = $EventId
                    StartTime = $StartTime
                } `
                -ErrorAction SilentlyContinue
        )

        foreach ($Event in $Events) {

            $Found = $true

            foreach ($Pattern in $Patterns) {
                if ($Event.Message -notmatch [regex]::Escape($Pattern)) {
                    $Found = $false
                    break
                }
            }

            if ($Found) {
                return $true
            }
        }

        Start-Sleep -Seconds 1
    }

    return $false
}

# ---------------------------------------------------------
# Trigger and verify
# ---------------------------------------------------------

Write-Host "[*] Trigger-and-Verify..."

$PassCount = 0

# =========================================================
# Rule 1 - Rclone
#
# SAFE: copy cmd.exe under test name rclone.exe,
# run it once, then remove it.
# =========================================================

$FakeRclone = "C:\Windows\Temp\rclone.exe"

try {

    Copy-Item `
        "$env:SystemRoot\System32\cmd.exe" `
        $FakeRclone `
        -Force

    $Start = Get-Date

    Start-Process `
        -FilePath $FakeRclone `
        -ArgumentList "/c exit" `
        -Wait `
        -WindowStyle Hidden

    if (Test-SysmonEvent `
        -EventId 1 `
        -StartTime $Start `
        -Patterns @("rclone.exe")) {

        Write-Host "    Rule 1: rclone.exe detection            [PASS]"
        $PassCount++
    }
    else {
        Write-Host "    Rule 1: rclone.exe detection            [FAIL]"
    }
}
finally {

    if (Test-Path $FakeRclone) {
        Remove-Item $FakeRclone -Force
    }
}

# =========================================================
# Rule 2 - PsExec registry pattern
#
# SAFE: uses HKCU test path containing Services\PSEXESVC.
# Does NOT install a real service.
# =========================================================

$PsExecTest =
    "HKCU:\Software\MedDefense\Services\PSEXESVC"

try {

    New-Item `
        -Path $PsExecTest `
        -Force |
        Out-Null

    $Start = Get-Date

    New-ItemProperty `
        -Path $PsExecTest `
        -Name "ImagePath" `
        -Value "MedDefense-Test-Only" `
        -PropertyType String `
        -Force |
        Out-Null

    if (Test-SysmonEvent `
        -EventId 13 `
        -StartTime $Start `
        -Patterns @("Services\PSEXESVC")) {

        Write-Host "    Rule 2: PsExec registry key             [PASS]"
        $PassCount++
    }
    else {
        Write-Host "    Rule 2: PsExec registry key             [FAIL]"
    }
}
finally {

    if (Test-Path "HKCU:\Software\MedDefense") {
        Remove-Item `
            "HKCU:\Software\MedDefense" `
            -Recurse `
            -Force `
            -ErrorAction SilentlyContinue
    }
}

# =========================================================
# Rule 3 - Encoded PowerShell
#
# SAFE encoded command: Write-Output only.
# =========================================================

$PlainCommand = "Write-Output 'MedDefenseEncodedTest'"

$EncodedCommand = [Convert]::ToBase64String(
    [Text.Encoding]::Unicode.GetBytes($PlainCommand)
)

$Start = Get-Date

Start-Process `
    -FilePath "powershell.exe" `
    -ArgumentList @(
        "-NoProfile",
        "-EncodedCommand",
        $EncodedCommand
    ) `
    -Wait `
    -WindowStyle Hidden

if (Test-SysmonEvent `
    -EventId 1 `
    -StartTime $Start `
    -Patterns @(
        "powershell.exe",
        "-EncodedCommand"
    )) {

    Write-Host "    Rule 3: Encoded PowerShell              [PASS]"
    $PassCount++
}
else {
    Write-Host "    Rule 3: Encoded PowerShell              [FAIL]"
}

# =========================================================
# Rule 4 - vssadmin delete shadows
#
# SAFE: /? displays help only.
# NO shadow copies are deleted.
# =========================================================

$Start = Get-Date

Start-Process `
    -FilePath "vssadmin.exe" `
    -ArgumentList @(
        "delete",
        "shadows",
        "/?"
    ) `
    -Wait `
    -WindowStyle Hidden

if (Test-SysmonEvent `
    -EventId 1 `
    -StartTime $Start `
    -Patterns @(
        "vssadmin.exe",
        "delete shadows"
    )) {

    Write-Host "    Rule 4: vssadmin execution              [PASS]"
    $PassCount++
}
else {
    Write-Host "    Rule 4: vssadmin execution              [FAIL]"
}

# =========================================================
# Rule 5 - schtasks /create
#
# SAFE: /? requests help.
# No persistent scheduled task is created.
# =========================================================

$Start = Get-Date

Start-Process `
    -FilePath "schtasks.exe" `
    -ArgumentList @(
        "/create",
        "/?"
    ) `
    -Wait `
    -WindowStyle Hidden

if (Test-SysmonEvent `
    -EventId 1 `
    -StartTime $Start `
    -Patterns @(
        "schtasks.exe",
        "/create"
    )) {

    Write-Host "    Rule 5: schtasks /create                [PASS]"
    $PassCount++
}
else {
    Write-Host "    Rule 5: schtasks /create                [FAIL]"
}

# ---------------------------------------------------------
# Final result
# ---------------------------------------------------------

Write-Host ""
Write-Host "Custom rules: 5 added | Tests: $PassCount/5 PASS"

if ($PassCount -ne 5) {
    throw "One or more Sysmon detection tests failed."
}
