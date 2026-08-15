# Exit codes:
# 0 = success
# 1 = controlled failure
# 2 = environment error
# Set-StrictMode

param(
    [switch]$Apply
)

$ErrorActionPreference = 'Stop'

$TargetState = 'capstone\target_state.json'
$BaselineFile = 'capstone\baseline\baseline_windows.json'

$ExecDir = 'capstone\exec'

$LogPath = 'capstone\exec\windows_harden.log'
$OutputPath = 'capstone\exec\windows_harden.json'

$ProvidedAuditHelper = 'C:\MedDefense_Lab\capstone\win_audit.ps1'

if ($env:WIN_AUDIT_HELPER) {
    $AuditHelper = $env:WIN_AUDIT_HELPER
}
elseif (Test-Path -LiteralPath $ProvidedAuditHelper) {
    $AuditHelper = $ProvidedAuditHelper
}
elseif (Test-Path -LiteralPath '.\win_audit.ps1') {
    $AuditHelper = '.\win_audit.ps1'
}
else {
    $AuditHelper = $ProvidedAuditHelper
}

$AccountPolicyScript = if ($env:ACCOUNT_POLICY_SCRIPT) {
    $env:ACCOUNT_POLICY_SCRIPT
}
else {
    '.\account_policy.ps1'
}

$AuditPolicyScript = if ($env:AUDIT_POLICY_SCRIPT) {
    $env:AUDIT_POLICY_SCRIPT
}
else {
    '.\audit_policy.ps1'
}

$FirewallScript = if ($env:FIREWALL_BASELINE_SCRIPT) {
    $env:FIREWALL_BASELINE_SCRIPT
}
else {
    '.\windows_firewall_baseline.ps1'
}

$SysmonScript = if ($env:SYSMON_INSTALL_SCRIPT) {
    $env:SYSMON_INSTALL_SCRIPT
}
else {
    '.\sysmon_install.ps1'
}

$PowerShellLoggingScript = if ($env:POWERSHELL_LOGGING_SCRIPT) {
    $env:POWERSHELL_LOGGING_SCRIPT
}
else {
    '.\powershell_logging.ps1'
}

$ApplicationControlScript = if ($env:APPLICATION_CONTROL_SCRIPT) {
    $env:APPLICATION_CONTROL_SCRIPT
}
else {
    '.\application_control.ps1'
}

$ServiceMinimizationScript = if ($env:SERVICE_MINIMIZATION_SCRIPT) {
    $env:SERVICE_MINIMIZATION_SCRIPT
}
else {
    '.\service_minimization.ps1'
}

$HardeningSteps = @(
    [ordered]@{
        Name = 'Account policy'
        ScriptPath = $AccountPolicyScript
    },
    [ordered]@{
        Name = 'Audit policy'
        ScriptPath = $AuditPolicyScript
    },
    [ordered]@{
        Name = 'Windows Firewall baseline'
        ScriptPath = $FirewallScript
    },
    [ordered]@{
        Name = 'Sysmon installation with MedDefense config'
        ScriptPath = $SysmonScript
    },
    [ordered]@{
        Name = 'PowerShell Script Block Logging enable'
        ScriptPath = $PowerShellLoggingScript
    },
    [ordered]@{
        Name = 'AppLocker or Defender Application Control baseline'
        ScriptPath = $ApplicationControlScript
    },
    [ordered]@{
        Name = 'Service minimization'
        ScriptPath = $ServiceMinimizationScript
    }
)

$ControlsTouched = @(
    'WIN-FW-01',
    'WIN-PSLOG-01',
    'WIN-SYSMON-01',
    'WIN-AUDIT-01',
    'WIN-CIS-01',
    'TEL-WIN-01',
    'TEL-WIN-02'
)

if (-not (Test-Path -LiteralPath $TargetState)) {
    Write-Error "Missing target state: $TargetState"
    exit 2
}

if (-not (Test-Path -LiteralPath $BaselineFile)) {
    Write-Error "Missing Windows baseline: $BaselineFile"
    exit 2
}

try {
    $TargetData = Get-Content `
        -LiteralPath $TargetState `
        -Raw |
        ConvertFrom-Json

    $BaselineData = Get-Content `
        -LiteralPath $BaselineFile `
        -Raw |
        ConvertFrom-Json
}
catch {
    Write-Error 'target_state.json or baseline_windows.json is corrupted.'
    exit 2
}

$TargetPassRate = $null

if (
    $null -ne $TargetData.windows -and
    $null -ne $TargetData.windows.pass_rate
) {
    $TargetPassRate = [double]$TargetData.windows.pass_rate
}
else {
    $CisControl = $TargetData.controls |
        Where-Object {
            $_.id -eq 'WIN-CIS-01'
        } |
        Select-Object -First 1

    if ($null -ne $CisControl) {
        $TargetPassRate = [double]$CisControl.expected_value
    }
}

if ($null -eq $TargetPassRate) {
    Write-Error 'Windows CIS pass-rate target is missing.'
    exit 2
}

if ($null -eq $BaselineData.pass_rate_percent) {
    Write-Error 'baseline_windows.json has no pass_rate_percent.'
    exit 2
}

$PassRateBefore = [double]$BaselineData.pass_rate_percent

Write-Output 'Windows hardening orchestration'
Write-Output "Target CIS Level 1 pass rate: $TargetPassRate%"

if (-not $Apply) {
    Write-Output ''
    Write-Output 'SAFE MODE: no Windows hardening changes will be applied.'
    Write-Output ''

    $Missing = $false

    foreach ($Step in $HardeningSteps) {
        if (Test-Path -LiteralPath $Step.ScriptPath) {
            Write-Output "[OK] $($Step.Name) -> $($Step.ScriptPath)"
        }
        else {
            Write-Output "[MISSING] $($Step.Name) -> $($Step.ScriptPath)"
            $Missing = $true
        }
    }

    if (Test-Path -LiteralPath $AuditHelper) {
        Write-Output "[OK] CIS audit helper -> $AuditHelper"
    }
    else {
        Write-Output "[MISSING] CIS audit helper -> $AuditHelper"
        $Missing = $true
    }

    Write-Output ''
    Write-Output 'No account, audit, firewall, Sysmon, PowerShell, AppLocker/WDAC, or service settings were changed.'
    Write-Output ''
    Write-Output 'Real hardening requires the explicit -Apply switch.'

    if ($Missing) {
        exit 2
    }

    exit 0
}

$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()

$Principal = New-Object `
    Security.Principal.WindowsPrincipal($Identity)

$IsAdministrator = $Principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

if (-not $IsAdministrator) {
    Write-Error '-Apply requires an elevated Administrator PowerShell session.'
    exit 2
}

foreach ($Step in $HardeningSteps) {
    if (-not (Test-Path -LiteralPath $Step.ScriptPath)) {
        Write-Error "Missing hardening script: $($Step.ScriptPath)"
        exit 2
    }
}

if (-not (Test-Path -LiteralPath $AuditHelper)) {
    Write-Error "Missing audit helper: $AuditHelper"
    exit 2
}

if (-not (Test-Path -LiteralPath $ExecDir)) {
    New-Item `
        -ItemType Directory `
        -Path $ExecDir `
        -Force |
        Out-Null
}

[System.IO.File]::WriteAllText(
    $LogPath,
    '',
    [System.Text.UTF8Encoding]::new($false)
)

$StepResults = @()
$EveryStepPassed = $true

function Invoke-HardeningStep {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$ScriptPath
    )

    $StdOutFile = Join-Path `
        $ExecDir `
        ('step-' + [Guid]::NewGuid().ToString() + '.stdout')

    $StdErrFile = Join-Path `
        $ExecDir `
        ('step-' + [Guid]::NewGuid().ToString() + '.stderr')

    $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    try {
        $Process = Start-Process `
            -FilePath 'powershell.exe' `
            -ArgumentList @(
                '-NoProfile',
                '-ExecutionPolicy',
                'Bypass',
                '-File',
                "`"$ScriptPath`""
            ) `
            -Wait `
            -PassThru `
            -RedirectStandardOutput $StdOutFile `
            -RedirectStandardError $StdErrFile

        $ExitCode = $Process.ExitCode
    }
    catch {
        $ExitCode = 1

        $_.Exception.Message |
            Set-Content `
                -LiteralPath $StdErrFile `
                -Encoding UTF8
    }

    $Stopwatch.Stop()

    $Duration = [Math]::Round(
        $Stopwatch.Elapsed.TotalSeconds,
        2
    )

    $StdOut = ''

    if (Test-Path -LiteralPath $StdOutFile) {
        $StdOut = Get-Content `
            -LiteralPath $StdOutFile `
            -Raw `
            -ErrorAction SilentlyContinue
    }

    $StdErr = ''

    if (Test-Path -LiteralPath $StdErrFile) {
        $StdErr = Get-Content `
            -LiteralPath $StdErrFile `
            -Raw `
            -ErrorAction SilentlyContinue
    }

    $Changed = $false

    if (
        $StdOut -match
        '(?i)changed|modified|updated|applied|configured|enabled|installed'
    ) {
        $Changed = $true
    }

    $LogEntry = [ordered]@{
        name = $Name
        script_path = $ScriptPath
        stdout = $StdOut
        stderr = $StdErr
        exit_code = $ExitCode
        duration_seconds = $Duration
        changed = $Changed
    }

    $LogEntry |
        ConvertTo-Json -Compress |
        Add-Content `
            -LiteralPath $LogPath `
            -Encoding UTF8

    Remove-Item `
        -LiteralPath $StdOutFile, $StdErrFile `
        -Force `
        -ErrorAction SilentlyContinue

    return [PSCustomObject]@{
        name = $Name
        script_path = $ScriptPath
        exit_code = $ExitCode
        duration_seconds = $Duration
        changed = $Changed
    }
}

foreach ($Step in $HardeningSteps) {
    $Result = Invoke-HardeningStep `
        -Name $Step.Name `
        -ScriptPath $Step.ScriptPath

    $StepResults += $Result

    if ($Result.exit_code -eq 0) {
        Write-Output "[OK] $($Step.Name)"
    }
    else {
        Write-Output "[FAILED] $($Step.Name)"
        $EveryStepPassed = $false
        break
    }
}

$PostPassRate = 0.0
$PassCount = 0
$FailCount = 0
$NaCount = 0
$ControlsTotal = 0

if ($EveryStepPassed) {
    try {
        $AuditOutput = @(
            & $AuditHelper 2>&1 |
            ForEach-Object {
                $_.ToString()
            }
        )

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

        $ScoredControls = $PassCount + $FailCount

        if ($ScoredControls -gt 0) {
            $PostPassRate = [Math]::Round(
                ($PassCount / $ScoredControls) * 100,
                2
            )
        }
        elseif ($ControlsTotal -gt 0) {
            $PostPassRate = 100.00
        }
        else {
            Write-Error 'No PASS, FAIL or NOT_APPLICABLE controls returned by win_audit.ps1.'
            $EveryStepPassed = $false
        }
    }
    catch {
        Write-Error "Post-hardening audit failed: $($_.Exception.Message)"
        $EveryStepPassed = $false
    }
}

$ScoreDelta = [Math]::Round(
    $PostPassRate - $PassRateBefore,
    2
)

$Timestamp = (Get-Date).ToUniversalTime().ToString(
    'yyyy-MM-ddTHH:mm:ssZ'
)

$Evidence = [ordered]@{
    timestamp = $Timestamp
    hostname = $env:COMPUTERNAME
    steps = $StepResults

    score_before = $PassRateBefore
    score_after = $PostPassRate
    score_delta = $ScoreDelta

    post_pass_rate = $PostPassRate
    target_pass_rate = $TargetPassRate

    audit = [ordered]@{
        controls_total = $ControlsTotal
        pass_count = $PassCount
        fail_count = $FailCount
        na_count = $NaCount
    }

    controls_touched = $ControlsTouched
}

$Json = $Evidence |
    ConvertTo-Json -Depth 8

[System.IO.File]::WriteAllText(
    $OutputPath,
    $Json + [Environment]::NewLine,
    [System.Text.UTF8Encoding]::new($false)
)

Write-Output "Baseline pass rate: $PassRateBefore%"
Write-Output "Post pass rate:     $PostPassRate%"
Write-Output "Target pass rate:   $TargetPassRate%"
Write-Output "Execution log:      $LogPath"
Write-Output "Evidence:           $OutputPath"

if (-not $EveryStepPassed) {
    exit 1
}

if ($PostPassRate -lt $TargetPassRate) {
    Write-Error 'Windows CIS Level 1 target pass rate was not reached.'
    exit 1
}

exit 0
