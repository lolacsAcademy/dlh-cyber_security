# name: 10-windows_detection_proof.ps1
# purpose: Windows Detection Proof
# author: analyst
# MITRE ATT&CK detection correlation
# Reads windows_attack_log.json and checks Security, Sysmon, and PowerShell logs.

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

$GroundTruthFile = Join-Path $PSScriptRoot "windows_attack_log.json"
$OutputFile = Join-Path $PSScriptRoot "windows_detection_matrix.json"

$WindowSeconds = 30

if (-not (Test-Path $GroundTruthFile)) {
    Write-Host "ERROR: windows_attack_log.json not found."
    exit 1
}

$GroundTruth = Get-Content -Path $GroundTruthFile -Raw | ConvertFrom-Json
$Actions = @($GroundTruth.actions)

Write-Host "[*] Loading ground truth ($($Actions.Count) actions)..."
Write-Host "[*] Searching telemetry for each action..."

$SecurityEvents = @(
    Get-WinEvent -FilterHashtable @{
        LogName = "Security"
        Id = 4720,4732,4698
    } -ErrorAction SilentlyContinue
)

$SysmonEvents = @(
    Get-WinEvent -FilterHashtable @{
        LogName = "Microsoft-Windows-Sysmon/Operational"
        Id = 1,3,11
    } -ErrorAction SilentlyContinue
)

$PowerShellEvents = @(
    Get-WinEvent -FilterHashtable @{
        LogName = "Microsoft-Windows-PowerShell/Operational"
        Id = 4104
    } -ErrorAction SilentlyContinue
)

function Get-KeyFields {
    param(
        [System.Diagnostics.Eventing.Reader.EventRecord]$Event
    )

    $Fields = @()

    try {
        $Xml = [xml]$Event.ToXml()
        foreach ($Data in $Xml.Event.EventData.Data) {
            if ($null -ne $Data.Name) {
                $Fields += [string]$Data.Name
            }
        }
    }
    catch {
        $Fields = @()
    }

    if ($Fields.Count -eq 0) {
        $Fields = @("Message")
    }

    return @($Fields | Sort-Object -Unique)
}

$DetectionMatrix = @()
$CapturedCount = 0
$MultiSourceCount = 0

foreach ($Action in $Actions) {

    $Description = [string]$Action.description

    $ActionTimeLocal = [DateTime]::Parse(
        [string]$Action.timestamp
    ).ToLocalTime()

    $WindowStart = $ActionTimeLocal.AddSeconds(-30)
    $WindowEnd = $ActionTimeLocal.AddSeconds(30)

    $WindowSecurity = @(
        $SecurityEvents | Where-Object {
            $_.TimeCreated -ge $WindowStart -and
            $_.TimeCreated -le $WindowEnd
        }
    )

    $WindowSysmon = @(
        $SysmonEvents | Where-Object {
            $_.TimeCreated -ge $WindowStart -and
            $_.TimeCreated -le $WindowEnd
        }
    )

    $WindowPowerShell = @(
        $PowerShellEvents | Where-Object {
            $_.TimeCreated -ge $WindowStart -and
            $_.TimeCreated -le $WindowEnd
        }
    )

    $Detections = @()

    if ($Description -match "Create local user") {
        $Event = $WindowSecurity | Where-Object { $_.Id -eq 4720 -and $_.Message -match "support_update" } | Select-Object -First 1
        if ($Event) {
            $Detections += [ordered]@{ source = "Security"; event_id = 4720; detail = "full"; key_fields = @(Get-KeyFields $Event) }
        }
    }
    elseif ($Description -match "Administrators") {
        $Event = $WindowSecurity | Where-Object { $_.Id -eq 4732 -and $_.Message -match "support_update" } | Select-Object -First 1
        if ($Event) {
            $Detections += [ordered]@{ source = "Security"; event_id = 4732; detail = "full"; key_fields = @(Get-KeyFields $Event) }
        }
    }
    elseif ($Description -match "encoded PowerShell") {
        $Event = $WindowPowerShell | Where-Object { $_.Id -eq 4104 } | Select-Object -First 1
        if ($Event) {
            $Detections += [ordered]@{ source = "PS ScriptBlock"; event_id = 4104; detail = "full"; key_fields = @(Get-KeyFields $Event) }
        }
        $Event2 = $WindowSysmon | Where-Object { $_.Id -eq 1 } | Select-Object -First 1
        if ($Event2) {
            $Detections += [ordered]@{ source = "Sysmon"; event_id = 1; detail = "full"; key_fields = @(Get-KeyFields $Event2) }
        }
    }
    elseif ($Description -match "scheduled task") {
        $Event = $WindowSecurity | Where-Object { $_.Id -eq 4698 -and $_.Message -match "SupportUpdateMaintenance" } | Select-Object -First 1
        if ($Event) {
            $Detections += [ordered]@{ source = "Security"; event_id = 4698; detail = "full"; key_fields = @(Get-KeyFields $Event) }
        }
        $Event2 = $WindowSysmon | Where-Object { $_.Id -eq 1 -and $_.Message -match "SupportUpdateMaintenance|schtasks" } | Select-Object -First 1
        if ($Event2) {
            $Detections += [ordered]@{ source = "Sysmon"; event_id = 1; detail = "full"; key_fields = @(Get-KeyFields $Event2) }
        }
    }
    elseif ($Description -match "outbound") {
        $Event = $WindowSysmon | Where-Object { $_.Id -eq 3 } | Select-Object -First 1
        if ($Event) {
            $Detections += [ordered]@{ source = "Sysmon"; event_id = 3; detail = "full"; key_fields = @(Get-KeyFields $Event) }
        }
    }
    elseif ($Description -match "Startup") {
        $Event = $WindowSysmon | Where-Object { $_.Id -eq 11 -and $_.Message -match "support_update|StartUp" } | Select-Object -First 1
        if ($Event) {
            $Detections += [ordered]@{ source = "Sysmon"; event_id = 11; detail = "full"; key_fields = @(Get-KeyFields $Event) }
        }
    }

    $Sources = @($Detections | ForEach-Object { $_.source } | Sort-Object -Unique)

    if ($Detections.Count -gt 0) { $CapturedCount++ }
    if ($Sources.Count -gt 1) { $MultiSourceCount++ }

    $Detail = "missed"
    if ($Detections.Count -gt 0) {
        if (@($Detections | Where-Object { $_.detail -eq "full" }).Count -gt 0) {
            $Detail = "full"
        } else {
            $Detail = "partial"
        }
    }

    $Status = "MISSED"
    if ($Detections.Count -gt 0) { $Status = "CAPTURED" }

    $DetectionMatrix += [ordered]@{
        action_number = [int]$Action.action_number
        description = $Description
        timestamp = $Action.timestamp
        search_window_seconds = 30
        search_window_start = $WindowStart.ToString("o")
        search_window_end = $WindowEnd.ToString("o")
        expected_detection_source = $Action.expected_detection_source
        mitre_attack_technique = $Action.MITRE_attack_technique
        detections = @($Detections)
        detail = $Detail
        status = $Status
    }
}

$CapturePercentage = 0
if ($Actions.Count -gt 0) {
    $CapturePercentage = [math]::Round(($CapturedCount / $Actions.Count) * 100, 1)
}

$Report = [ordered]@{
    report = "Windows Detection Proof"
    ground_truth_file = "windows_attack_log.json"
    telemetry_sources = @("Security", "Sysmon", "PowerShell")
    correlation_window_seconds = 30
    actions = $DetectionMatrix
    summary = [ordered]@{
        actions = $Actions.Count
        captured = $CapturedCount
        captured_percentage = $CapturePercentage
        multi_source = $MultiSourceCount
    }
}

$Report | ConvertTo-Json -Depth 10 | Set-Content -Path $OutputFile -Encoding UTF8

Write-Host ""
Write-Host "Action                     Source         Event ID   Detail    Status"
Write-Host "------                     ------         --------   ------    ------"

foreach ($Result in $DetectionMatrix) {
    if (@($Result.detections).Count -eq 0) {
        Write-Host ("{0,-26} {1,-14} {2,-10} {3,-9} [{4}]" -f $Result.description, "-", "-", $Result.detail, $Result.status)
    } else {
        foreach ($Detection in $Result.detections) {
            Write-Host ("{0,-26} {1,-14} {2,-10} {3,-9} [{4}]" -f $Result.description, $Detection.source, $Detection.event_id, $Detection.detail, $Result.status)
        }
    }
}

Write-Host ""
Write-Host "Actions: $($Actions.Count) | Captured: $CapturedCount/$($Actions.Count) ($CapturePercentage%) | Multi-source: $MultiSourceCount"
Write-Host "Report saved to: windows_detection_matrix.json"
