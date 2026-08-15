# Exit codes:
# 0 = success
# 1 = controlled audit/parsing failure
# 2 = environment error
$ErrorActionPreference = 'Stop'
$BaseDir = 'capstone\baseline'
$LogPath = Join-Path $BaseDir 'windows_baseline.log'
$OutputPath = Join-Path $BaseDir 'baseline_windows.json'
# Required helper path from project instructions.
$AuditHelper = 'C:\MedDefense_Lab\capstone\win_audit.ps1'
try {
    if (-not (Test-Path -LiteralPath $AuditHelper)) {
        Write-Error "Missing input file: $AuditHelper"
        exit 2
    }
    if (-not (Test-Path -LiteralPath $BaseDir)) {
        New-Item `
            -ItemType Directory `
            -Path $BaseDir `
            -Force | Out-Null
    }
    $Timestamp = (Get-Date).ToUniversalTime().ToString(
        'yyyy-MM-ddTHH:mm:ssZ'
    )
    $HostnameValue = $env:COMPUTERNAME
    # Run provided CIS Level 1 audit helper.
    $AuditOutput = @(
        & $AuditHelper 2>&1 |
        ForEach-Object { $_.ToString() }
    )
    $AuditOutput |
        Set-Content `
            -LiteralPath $LogPath `
            -Encoding UTF8
    $PassCount = @(
        $AuditOutput |
        Where-Object {
            $_ -match '\bPASS\b'
        }
    ).Count
    $FailCount = @(
        $AuditOutput |
        Where-Object {
            $_ -match '\bFAIL\b'
        }
    ).Count
    $NaCount = @(
        $AuditOutput |
        Where-Object {
            $_ -match '\bNOT_APPLICABLE\b'
        }
    ).Count
    $ControlsTotal = (
        $PassCount +
        $FailCount +
        $NaCount
    )
    if ($ControlsTotal -eq 0) {
        Write-Error 'No audit control results were found.'
        exit 1
    }
    # NOT_APPLICABLE controls are excluded from the scored denominator.
    $ScoredControls = $PassCount + $FailCount
    if ($ScoredControls -gt 0) {
        $PassRate = [Math]::Round(
            ($PassCount / $ScoredControls) * 100,
            2
        )
    }
    else {
        $PassRate = 100.00
    }
    $Result = [ordered]@{
        timestamp = $Timestamp
        hostname = $HostnameValue
        controls_total = $ControlsTotal
        pass_count = $PassCount
        fail_count = $FailCount
        na_count = $NaCount
        pass_rate_percent = $PassRate
        log_path = $LogPath
    }
    $Json = $Result |
        ConvertTo-Json -Depth 5
    [System.IO.File]::WriteAllText(
        $OutputPath,
        $Json + [Environment]::NewLine,
        [System.Text.UTF8Encoding]::new($false)
    )
    Write-Output 'Windows baseline complete'
    Write-Output "Pass rate: $PassRate%"
    Write-Output "Report saved to: $OutputPath"
    exit 0
}
catch {
    Write-Error "Baseline audit failed: $($_.Exception.Message)"
    exit 1
}
