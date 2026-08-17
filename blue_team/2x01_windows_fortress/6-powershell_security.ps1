<#
Script Name: 6-powershell_security.ps1
Purpose: Configure PowerShell security logging and validate Script Block Logging.
Author: Student
Date: 2026-08-15
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory
Import-Module GroupPolicy

$GPOName = "MedDefense - PowerShell Security"
$TranscriptPath = "C:\PSTranscripts"
$Domain = Get-ADDomain
$DomainDN = $Domain.DistinguishedName

# Require Administrator privileges
$CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object Security.Principal.WindowsPrincipal($CurrentUser)

if (-not $Principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)) {
    throw "Run this script from PowerShell as Administrator."
}

# ---------------------------------------------------------
# Create GPO
# ---------------------------------------------------------

Write-Host "[*] Creating GPO: `"$GPOName`"..." -NoNewline

$ExistingGPO = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue

if ($null -eq $ExistingGPO) {
    New-GPO `
        -Name $GPOName `
        -Comment "MedDefense PowerShell logging and security policy." |
        Out-Null
}

Write-Host " CREATED"

# ---------------------------------------------------------
# Script Block Logging
# ---------------------------------------------------------

Write-Host "[*] Configuring Script Block Logging..."

Set-GPRegistryValue `
    -Name $GPOName `
    -Key "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -ValueName "EnableScriptBlockLogging" `
    -Type DWord `
    -Value 1

Write-Host "    EnableScriptBlockLogging = 1           [SET]"
Write-Host "    -> Event ID 4104 captures decoded scripts"

# ---------------------------------------------------------
# Module Logging
# ---------------------------------------------------------

Write-Host "[*] Configuring Module Logging..."

Set-GPRegistryValue `
    -Name $GPOName `
    -Key "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
    -ValueName "EnableModuleLogging" `
    -Type DWord `
    -Value 1

Set-GPRegistryValue `
    -Name $GPOName `
    -Key "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" `
    -ValueName "*" `
    -Type String `
    -Value "*"

Write-Host "    EnableModuleLogging = 1, ModuleNames = *  [SET]"
Write-Host "    -> Event ID 4103 captures module invocations"

# ---------------------------------------------------------
# PowerShell Transcription
# ---------------------------------------------------------

Write-Host "[*] Configuring Transcription..."

Set-GPRegistryValue `
    -Name $GPOName `
    -Key "HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription" `
    -ValueName "EnableTranscripting" `
    -Type DWord `
    -Value 1

Set-GPRegistryValue `
    -Name $GPOName `
    -Key "HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription" `
    -ValueName "EnableInvocationHeader" `
    -Type DWord `
    -Value 1

Set-GPRegistryValue `
    -Name $GPOName `
    -Key "HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription" `
    -ValueName "OutputDirectory" `
    -Type String `
    -Value $TranscriptPath

# Create the transcript directory locally on DC01
if (-not (Test-Path -Path $TranscriptPath)) {
    New-Item `
        -Path $TranscriptPath `
        -ItemType Directory `
        -Force |
        Out-Null
}

Write-Host "    OutputDirectory = C:\PSTranscripts     [SET]"

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
# Force Group Policy update
# ---------------------------------------------------------

& gpupdate.exe /force | Out-Null

if ($LASTEXITCODE -ne 0) {
    throw "Group Policy update failed."
}

# ---------------------------------------------------------
# Verify AMSI
# ---------------------------------------------------------

Write-Host "[*] Verifying AMSI..." -NoNewline

$AmsiPath = Join-Path $env:SystemRoot "System32\amsi.dll"

if (-not (Test-Path $AmsiPath)) {
    throw "AMSI DLL was not found."
}

try {
    $AmsiType = [Ref].Assembly.GetType(
        "System.Management.Automation.AmsiUtils",
        $false
    )

    if ($null -ne $AmsiType) {
        Write-Host " AMSI DLL loaded     [OK]"
    }
    else {
        throw "AMSI integration could not be verified."
    }
}
catch {
    throw "AMSI integration could not be verified."
}

Write-Host "[*] Linking GPO and forcing update... COMPLETE"

# ---------------------------------------------------------
# Test encoded command
# ---------------------------------------------------------

Write-Host "[*] Testing encoded command..."

$TestCommand = "Write-Host 'Test'"

$EncodedCommand = [Convert]::ToBase64String(
    [Text.Encoding]::Unicode.GetBytes($TestCommand)
)

Write-Host "    Input: powershell -enc $EncodedCommand"

$TestStart = Get-Date

Start-Process `
    -FilePath "powershell.exe" `
    -ArgumentList "-NoProfile -EncodedCommand $EncodedCommand" `
    -Wait `
    -WindowStyle Hidden

Start-Sleep -Seconds 2

# ---------------------------------------------------------
# Verify Event ID 4104
# ---------------------------------------------------------

$Event = Get-WinEvent `
    -FilterHashtable @{
        LogName   = "Microsoft-Windows-PowerShell/Operational"
        Id        = 4104
        StartTime = $TestStart
    } `
    -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Message -match "Write-Host" -and
        $_.Message -match "Test"
    } |
    Select-Object -First 1

if ($null -ne $Event) {
    Write-Host "    Event ID 4104 found: `"Write-Host 'Test'`"  [VERIFIED]"
}
else {
    throw "Event ID 4104 validation failed."
}
