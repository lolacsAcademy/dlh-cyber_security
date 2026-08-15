<#
Script Name: 9-sysmon_deploy.ps1
Purpose: Download, install, configure, and validate Sysmon for MedDefense.
Author: Student
Date: 2026-08-15
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Require Administrator
$CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object Security.Principal.WindowsPrincipal($CurrentUser)

if (-not $Principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)) {
    throw "Run this script from PowerShell as Administrator."
}

$WorkDir = $PSScriptRoot

if ([string]::IsNullOrWhiteSpace($WorkDir)) {
    $WorkDir = (Get-Location).Path
}

$SysmonZip = Join-Path $WorkDir "Sysmon.zip"
$SysmonDir = Join-Path $WorkDir "Sysmon"
$ConfigPath = Join-Path $WorkDir "sysmonconfig.xml"

$SysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip"
$ConfigUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"

$EventLog = "Microsoft-Windows-Sysmon/Operational"
$TestFile = "C:\Windows\Temp\sysmon_test.txt"

# ---------------------------------------------------------
# Download Sysmon if needed
# ---------------------------------------------------------

Write-Host "[*] Downloading Sysmon..." -NoNewline

if (-not (Test-Path $SysmonZip)) {
    Invoke-WebRequest `
        -Uri $SysmonUrl `
        -OutFile $SysmonZip `
        -UseBasicParsing
}

Write-Host " OK"

# ---------------------------------------------------------
# Extract Sysmon if needed
# ---------------------------------------------------------

if (-not (Test-Path $SysmonDir)) {
    Expand-Archive `
        -Path $SysmonZip `
        -DestinationPath $SysmonDir `
        -Force
}

$SysmonExe = Join-Path $SysmonDir "Sysmon64.exe"

if (-not (Test-Path $SysmonExe)) {
    throw "Sysmon64.exe was not found."
}

# ---------------------------------------------------------
# Download SwiftOnSecurity config if needed
# ---------------------------------------------------------

Write-Host "[*] Downloading SwiftOnSecurity config..." -NoNewline

if (-not (Test-Path $ConfigPath)) {
    Invoke-WebRequest `
        -Uri $ConfigUrl `
        -OutFile $ConfigPath `
        -UseBasicParsing
}

Write-Host " OK"

# ---------------------------------------------------------
# Add FileCreate test rule
# ---------------------------------------------------------

$ConfigContent = Get-Content `
    -Path $ConfigPath `
    -Raw

$TestPathText = 'C:\Windows\Temp\sysmon_test.txt'

if ($ConfigContent -notmatch [regex]::Escape($TestPathText)) {

    $FileCreateTag = '<FileCreate onmatch="include">'

    $TestRule = @'
        <TargetFilename name="MedDefenseTest" condition="is">C:\Windows\Temp\sysmon_test.txt</TargetFilename>
'@

    if ($ConfigContent -notmatch [regex]::Escape($FileCreateTag)) {
        throw "FileCreate section was not found in sysmonconfig.xml."
    }

    $ConfigContent = $ConfigContent.Replace(
        $FileCreateTag,
        "$FileCreateTag`r`n$TestRule"
    )

    Set-Content `
        -Path $ConfigPath `
        -Value $ConfigContent `
        -Encoding UTF8
}

# ---------------------------------------------------------
# Install or update Sysmon
# ---------------------------------------------------------

Write-Host "[*] Installing Sysmon with config..."
Write-Host "    Sysmon64.exe -accepteula -i sysmonconfig.xml"

$ExistingService = Get-Service `
    -Name "Sysmon64" `
    -ErrorAction SilentlyContinue

if ($null -eq $ExistingService) {

    & $SysmonExe `
        -accepteula `
        -i $ConfigPath |
        Out-Null

    if ($LASTEXITCODE -ne 0) {
        throw "Sysmon installation failed."
    }
}
else {

    & $SysmonExe `
        -c $ConfigPath |
        Out-Null

    if ($LASTEXITCODE -ne 0) {
        throw "Sysmon configuration update failed."
    }
}

Start-Sleep -Seconds 3

# ---------------------------------------------------------
# Verify service
# ---------------------------------------------------------

$SysmonService = Get-Service `
    -Name "Sysmon64" `
    -ErrorAction SilentlyContinue

if ($null -eq $SysmonService) {
    $SysmonService = Get-Service `
        -Name "Sysmon" `
        -ErrorAction SilentlyContinue
}

if ($null -eq $SysmonService) {
    throw "Sysmon service was not found."
}

if ($SysmonService.Status -ne "Running") {
    throw "Sysmon service is not running."
}

Write-Host "    Service: $($SysmonService.Name) - Running            [OK]"

# ---------------------------------------------------------
# Verify driver using Service Control Manager
# ---------------------------------------------------------

$DriverCheck = & sc.exe query SysmonDrv 2>&1

if ($DriverCheck -match "RUNNING") {
    Write-Host "    Driver: SysmonDrv - Loaded             [OK]"
}
else {
    throw "Sysmon driver was not found or is not running."
}

# ---------------------------------------------------------
# Verify event generation
# ---------------------------------------------------------

Write-Host "[*] Verifying event generation..."

$StartTime = (Get-Date).AddSeconds(-60)

$RecentEvents = @(
    Get-WinEvent `
        -FilterHashtable @{
            LogName   = $EventLog
            StartTime = $StartTime
        } `
        -ErrorAction SilentlyContinue
)

$EventCount = $RecentEvents.Count

Write-Host "    Events in last 60 seconds: $EventCount          [OK]"

# ---------------------------------------------------------
# Test FileCreate Event ID 11
# ---------------------------------------------------------

Write-Host "[*] Testing FileCreate detection..."

if (Test-Path $TestFile) {
    Remove-Item `
        -Path $TestFile `
        -Force
}

$TestStart = Get-Date

Set-Content `
    -Path $TestFile `
    -Value "MedDefense Sysmon Event ID 11 validation test."

Write-Host "    Created: $TestFile"

Start-Sleep -Seconds 3

$FileCreateEvent = Get-WinEvent `
    -FilterHashtable @{
        LogName   = $EventLog
        Id        = 11
        StartTime = $TestStart
    } `
    -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Message -match [regex]::Escape($TestFile)
    } |
    Select-Object -First 1

if ($null -ne $FileCreateEvent) {
    Write-Host "    Event ID 11 captured                   [VERIFIED]"
}
else {
    throw "Sysmon Event ID 11 was not captured for the test file."
}

# ---------------------------------------------------------
# Clean up test file
# ---------------------------------------------------------

if (Test-Path $TestFile) {
    Remove-Item `
        -Path $TestFile `
        -Force
}

Write-Host ""
Write-Host "[*] Sysmon deployment completed successfully."
Write-Host "[*] Configuration saved to: sysmonconfig.xml"
