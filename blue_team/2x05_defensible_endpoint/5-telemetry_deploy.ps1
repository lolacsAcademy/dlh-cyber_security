param(
    [switch]$Apply
)

$ErrorActionPreference = 'Stop'

$TelemetryDir = 'capstone\telemetry'
$EventsOut = 'capstone\telemetry\windows_events.json'
$CoverageOut = 'capstone\telemetry\windows_coverage.json'

$TestUser = 'MDTelemetryTest'
$TaskName = 'MedDefense-Telemetry-Test'
$TestService = 'Spooler'

$SysmonLog = 'Microsoft-Windows-Sysmon/Operational'
$PowerShellLog = 'Microsoft-Windows-PowerShell/Operational'
$SecurityLog = 'Security'

# Exit codes:
# 0 = success
# 1 = controlled failure
# 2 = environment error

Write-Output 'Windows telemetry deployment'

# ------------------------------------------------------------
# SAFE DEFAULT
# ------------------------------------------------------------
if (-not $Apply) {
    Write-Output 'SAFE MODE: no Windows telemetry or test changes will be applied.'

    $SysmonService = Get-Service `
        -Name 'Sysmon*' `
        -ErrorAction SilentlyContinue |
        Select-Object -First 1

    if ($null -ne $SysmonService) {
        Write-Output "[OK] Sysmon present: $($SysmonService.Name)"
        Write-Output "     Status: $($SysmonService.Status)"
    }
    else {
        Write-Output '[MISSING] Sysmon service'
    }

    $ScriptBlockPath =
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'

    $ScriptBlock = Get-ItemProperty `
        -Path $ScriptBlockPath `
        -Name EnableScriptBlockLogging `
        -ErrorAction SilentlyContinue

    if (
        $null -ne $ScriptBlock -and
        $ScriptBlock.EnableScriptBlockLogging -eq 1
    ) {
        Write-Output '[OK] Script Block Logging enabled'
    }
    else {
        Write-Output '[INFO] Script Block Logging not enabled'
    }

    Write-Output 'Real deployment/test actions require: .\5-telemetry_deploy.ps1 -Apply'
    exit 0
}

# ------------------------------------------------------------
# APPLY MODE - modifies Windows temporarily
# ------------------------------------------------------------
$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()

$Principal = New-Object `
    Security.Principal.WindowsPrincipal($Identity)

if (
    -not $Principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
) {
    Write-Error '-Apply requires Administrator PowerShell.'
    exit 2
}

if (-not (Test-Path -LiteralPath $TelemetryDir)) {
    New-Item `
        -ItemType Directory `
        -Path $TelemetryDir `
        -Force |
        Out-Null
}

# ------------------------------------------------------------
# Verify Sysmon
# ------------------------------------------------------------
$SysmonService = Get-Service `
    -Name 'Sysmon*' `
    -ErrorAction SilentlyContinue |
    Select-Object -First 1

if ($null -eq $SysmonService) {
    Write-Error 'Sysmon is not installed.'
    exit 1
}

if ($SysmonService.Status -ne 'Running') {
    Write-Error 'Sysmon is installed but not running.'
    exit 1
}

$SysmonChannel = Get-WinEvent `
    -ListLog $SysmonLog `
    -ErrorAction SilentlyContinue

if ($null -eq $SysmonChannel) {
    Write-Error 'Sysmon Operational event channel is unavailable.'
    exit 1
}

# ------------------------------------------------------------
# Verify Script Block Logging
# ------------------------------------------------------------
$ScriptBlockPath =
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'

$ScriptBlock = Get-ItemProperty `
    -Path $ScriptBlockPath `
    -Name EnableScriptBlockLogging `
    -ErrorAction SilentlyContinue

if (
    $null -eq $ScriptBlock -or
    $ScriptBlock.EnableScriptBlockLogging -ne 1
) {
    Write-Error 'PowerShell Script Block Logging is not active.'
    exit 1
}

# Do not overwrite existing test objects.
if (
    Get-LocalUser `
        -Name $TestUser `
        -ErrorAction SilentlyContinue
) {
    Write-Error "Test user already exists: $TestUser"
    exit 1
}

if (
    Get-ScheduledTask `
        -TaskName $TaskName `
        -ErrorAction SilentlyContinue
) {
    Write-Error "Test scheduled task already exists: $TaskName"
    exit 1
}

$StartTime = (Get-Date).AddMinutes(-1)

# ------------------------------------------------------------
# Controlled test sequence
# ------------------------------------------------------------

# 1. Create local user.
$Password = ConvertTo-SecureString `
    'MedDefense-Test-Only-2026!' `
    -AsPlainText `
    -Force

New-LocalUser `
    -Name $TestUser `
    -Password $Password `
    -Description 'Temporary MedDefense telemetry test user' |
    Out-Null

# Remove immediately after the creation event.
Remove-LocalUser -Name $TestUser

# 2. Create and run scheduled task.
$Action = New-ScheduledTaskAction `
    -Execute 'powershell.exe' `
    -Argument '-NoProfile -Command "Write-Output MedDefenseScheduledTask"'

$Trigger = New-ScheduledTaskTrigger `
    -Once `
    -At (Get-Date).AddMinutes(5)

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $Action `
    -Trigger $Trigger `
    -User 'SYSTEM' `
    -Force |
    Out-Null

Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 2

Unregister-ScheduledTask `
    -TaskName $TaskName `
    -Confirm:$false

# 3. Start/stop service action.
$Service = Get-Service `
    -Name $TestService `
    -ErrorAction Stop

$OriginalServiceStatus = $Service.Status

if ($OriginalServiceStatus -eq 'Running') {
    Stop-Service -Name $TestService
    Start-Service -Name $TestService
}
else {
    Start-Service -Name $TestService
    Stop-Service -Name $TestService
}

# Restore original state.
$Service = Get-Service -Name $TestService

if (
    $OriginalServiceStatus -eq 'Running' -and
    $Service.Status -ne 'Running'
) {
    Start-Service -Name $TestService
}

if (
    $OriginalServiceStatus -ne 'Running' -and
    $Service.Status -eq 'Running'
) {
    Stop-Service -Name $TestService
}

# 4. Authorized PowerShell action.
& powershell.exe `
    -NoProfile `
    -Command 'Write-Output "MedDefenseTelemetryAuthorizedTest"' |
    Out-Null

Start-Sleep -Seconds 3

# ------------------------------------------------------------
# Coverage verification - last 10 minutes
# ------------------------------------------------------------
$TenMinutesAgo = (Get-Date).AddMinutes(-10)

$SecurityEvents = @(
    Get-WinEvent `
        -FilterHashtable @{
            LogName = $SecurityLog
            StartTime = $TenMinutesAgo
        } `
        -ErrorAction SilentlyContinue
)

$SysmonEvents = @(
    Get-WinEvent `
        -FilterHashtable @{
            LogName = $SysmonLog
            StartTime = $TenMinutesAgo
        } `
        -ErrorAction SilentlyContinue
)

$PowerShellEvents = @(
    Get-WinEvent `
        -FilterHashtable @{
            LogName = $PowerShellLog
            StartTime = $TenMinutesAgo
        } `
        -ErrorAction SilentlyContinue
)

$Coverage = @()

function Add-CoverageResult {
    param(
        [string]$Action,
        [string]$Channel,
        [bool]$Detected,
        [int]$EvidenceCount
    )

    $script:Coverage += [PSCustomObject]@{
        action = $Action
        expected_source = $Channel
        detected = $Detected
        evidence_count = $EvidenceCount
    }
}

$UserEvents = @(
    $SecurityEvents |
    Where-Object {
        $_.Id -in @(4720, 4726) -and
        $_.Message -match $TestUser
    }
)

Add-CoverageResult `
    -Action 'local_user_create_remove' `
    -Channel 'Security' `
    -Detected ($UserEvents.Count -gt 0) `
    -EvidenceCount $UserEvents.Count

$TaskEvents = @(
    $SysmonEvents |
    Where-Object {
        $_.Message -match 'schtasks|ScheduledTask|powershell'
    }
)

Add-CoverageResult `
    -Action 'scheduled_task_create_run' `
    -Channel 'Sysmon Operational' `
    -Detected ($TaskEvents.Count -gt 0) `
    -EvidenceCount $TaskEvents.Count

$ServiceEvents = @(
    $SysmonEvents |
    Where-Object {
        $_.Message -match 'sc.exe|Stop-Service|Start-Service|Spooler'
    }
)

Add-CoverageResult `
    -Action 'service_start_stop' `
    -Channel 'Sysmon Operational' `
    -Detected ($ServiceEvents.Count -gt 0) `
    -EvidenceCount $ServiceEvents.Count

$ScriptBlockEvents = @(
    $PowerShellEvents |
    Where-Object {
        $_.Id -eq 4104 -and
        $_.Message -match 'MedDefenseTelemetryAuthorizedTest'
    }
)

Add-CoverageResult `
    -Action 'powershell_authorized_command' `
    -Channel 'PowerShell Operational' `
    -Detected ($ScriptBlockEvents.Count -gt 0) `
    -EvidenceCount $ScriptBlockEvents.Count

# ------------------------------------------------------------
# Export last 30 minutes of Sysmon + PowerShell telemetry
# ------------------------------------------------------------
$ThirtyMinutesAgo = (Get-Date).AddMinutes(-30)

$ExportEvents = @()

$ExportEvents += Get-WinEvent `
    -FilterHashtable @{
        LogName = $SysmonLog
        StartTime = $ThirtyMinutesAgo
    } `
    -ErrorAction SilentlyContinue |
    ForEach-Object {
        [PSCustomObject]@{
            timestamp = $_.TimeCreated.ToUniversalTime().ToString(
                'yyyy-MM-ddTHH:mm:ssZ'
            )
            hostname = $env:COMPUTERNAME
            source_type = 'sysmon'
            event_category = 'endpoint'
            event_id = $_.Id
            channel = $_.LogName
            message = $_.Message
        }
    }

$ExportEvents += Get-WinEvent `
    -FilterHashtable @{
        LogName = $PowerShellLog
        StartTime = $ThirtyMinutesAgo
    } `
    -ErrorAction SilentlyContinue |
    ForEach-Object {
        [PSCustomObject]@{
            timestamp = $_.TimeCreated.ToUniversalTime().ToString(
                'yyyy-MM-ddTHH:mm:ssZ'
            )
            hostname = $env:COMPUTERNAME
            source_type = 'powershell'
            event_category = 'script_execution'
            event_id = $_.Id
            channel = $_.LogName
            message = $_.Message
        }
    }

$ExportEvents |
    ConvertTo-Json -Depth 6 |
    Set-Content `
        -LiteralPath $EventsOut `
        -Encoding UTF8

$CoverageResult = [ordered]@{
    timestamp = (Get-Date).ToUniversalTime().ToString(
        'yyyy-MM-ddTHH:mm:ssZ'
    )
    hostname = $env:COMPUTERNAME
    actions = $Coverage
}

$CoverageResult |
    ConvertTo-Json -Depth 6 |
    Set-Content `
        -LiteralPath $CoverageOut `
        -Encoding UTF8

$AllDetected = (
    @(
        $Coverage |
        Where-Object {
            -not $_.detected
        }
    ).Count -eq 0
)

Write-Output "Telemetry export: $EventsOut"
Write-Output "Coverage evidence: $CoverageOut"

if (-not $AllDetected) {
    Write-Error 'One or more authorized actions produced no expected telemetry.'
    exit 1
}

exit 0
