# Exit codes:
# 0 = success
# 1 = controlled collection failure
# 2 = environment error
# net accounts
# capstone

$ErrorActionPreference = 'Stop'

$OutputFile = 'environment_intake_windows.json'

try {
    $Os = Get-CimInstance -ClassName Win32_OperatingSystem

    $HotFixes = @(
        Get-HotFix -ErrorAction SilentlyContinue |
        Sort-Object InstalledOn
    )

    $LatestPatch = if ($HotFixes.Count -gt 0) {
        ($HotFixes | Select-Object -Last 1).HotFixID
    }
    else {
        $null
    }

    $InstalledFeatureCount = 0
    $FeatureSource = 'unavailable'

    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
        $InstalledFeatureCount = @(
            Get-WindowsFeature |
            Where-Object { $_.Installed }
        ).Count

        $FeatureSource = 'Get-WindowsFeature'
    }
    elseif (Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue) {
        $InstalledFeatureCount = @(
            Get-WindowsOptionalFeature -Online |
            Where-Object { $_.State -eq 'Enabled' }
        ).Count

        $FeatureSource = 'Get-WindowsOptionalFeature'
    }

    $RunningServices = @(
        Get-Service |
        Where-Object { $_.Status -eq 'Running' } |
        Sort-Object Name |
        Select-Object Name, DisplayName, Status
    )

    $LocalUsers = @()

    if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
        $LocalUsers = @(
            Get-LocalUser |
            Sort-Object Name |
            Select-Object Name, Enabled, LastLogon
        )
    }

    $FirewallProfiles = @(
        Get-NetFirewallProfile |
        Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
    )

    $AuditPolicy = @(
        & auditpol.exe /get /category:* 2>$null
    )

    $SysmonPresent = $false
    $SysmonVersion = $null
    $SysmonChannelSize = $null

    $SysmonService = Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue |
        Select-Object -First 1

    if ($null -ne $SysmonService) {
        $SysmonPresent = $true

        $SysmonExecutable = Get-CimInstance Win32_Service |
            Where-Object { $_.Name -eq $SysmonService.Name } |
            Select-Object -First 1

        if ($null -ne $SysmonExecutable) {
            $ExecutablePath = $SysmonExecutable.PathName -replace '"', ''
            $ExecutablePath = ($ExecutablePath -split '\s+-')[0]

            if (Test-Path $ExecutablePath) {
                $SysmonVersion = (
                    Get-Item $ExecutablePath
                ).VersionInfo.FileVersion
            }
        }

        $SysmonLog = Get-WinEvent -ListLog `
            'Microsoft-Windows-Sysmon/Operational' `
            -ErrorAction SilentlyContinue

        if ($null -ne $SysmonLog) {
            $SysmonChannelSize = $SysmonLog.FileSize
        }
    }

    $ScriptBlockLoggingPath =
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'

    $ScriptBlockLogging = Get-ItemProperty `
        -Path $ScriptBlockLoggingPath `
        -ErrorAction SilentlyContinue

    $ScriptBlockEnabled = $false

    if (
        $null -ne $ScriptBlockLogging -and
        $ScriptBlockLogging.EnableScriptBlockLogging -eq 1
    ) {
        $ScriptBlockEnabled = $true
    }

    $NetAccounts = @(
        & net.exe accounts 2>$null
    )

    $Result = [ordered]@{
        captured_at = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        hostname = $env:COMPUTERNAME

        os = [ordered]@{
            caption = $Os.Caption
            version = $Os.Version
            build = $Os.BuildNumber
            patch_level = $LatestPatch
        }

        installed_features = [ordered]@{
            source = $FeatureSource
            count = $InstalledFeatureCount
        }

        running_services = $RunningServices

        local_users = $LocalUsers

        windows_firewall = $FirewallProfiles

        audit_policy_summary = $AuditPolicy

        sysmon = [ordered]@{
            present = $SysmonPresent
            version = $SysmonVersion
            event_channel_size = $SysmonChannelSize
        }

        powershell_logging = [ordered]@{
            script_block_logging_enabled = $ScriptBlockEnabled
            registry_path = $ScriptBlockLoggingPath
        }

        account_policy = $NetAccounts
    }

    $Json = $Result |
        ConvertTo-Json -Depth 8

    [System.IO.File]::WriteAllText(
