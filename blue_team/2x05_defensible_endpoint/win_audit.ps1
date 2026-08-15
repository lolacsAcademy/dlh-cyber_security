$ErrorActionPreference = 'Stop'

function Write-ControlResult {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Control,

        [Parameter(Mandatory = $true)]
        [ValidateSet('PASS', 'FAIL', 'NOT_APPLICABLE')]
        [string]$Status,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    Write-Output "$Control | $Status | $Description"
}

# ------------------------------------------------------------
# 1. Windows Firewall - Domain
# ------------------------------------------------------------
try {
    $Profile = Get-NetFirewallProfile -Profile Domain

    if ($Profile.Enabled) {
        Write-ControlResult 'CIS-1' 'PASS' 'Domain firewall enabled'
    }
    else {
        Write-ControlResult 'CIS-1' 'FAIL' 'Domain firewall disabled'
    }
}
catch {
    Write-ControlResult 'CIS-1' 'NOT_APPLICABLE' 'Domain firewall unavailable'
}

# ------------------------------------------------------------
# 2. Windows Firewall - Private
# ------------------------------------------------------------
try {
    $Profile = Get-NetFirewallProfile -Profile Private

    if ($Profile.Enabled) {
        Write-ControlResult 'CIS-2' 'PASS' 'Private firewall enabled'
    }
    else {
        Write-ControlResult 'CIS-2' 'FAIL' 'Private firewall disabled'
    }
}
catch {
    Write-ControlResult 'CIS-2' 'NOT_APPLICABLE' 'Private firewall unavailable'
}

# ------------------------------------------------------------
# 3. Windows Firewall - Public
# ------------------------------------------------------------
try {
    $Profile = Get-NetFirewallProfile -Profile Public

    if ($Profile.Enabled) {
        Write-ControlResult 'CIS-3' 'PASS' 'Public firewall enabled'
    }
    else {
        Write-ControlResult 'CIS-3' 'FAIL' 'Public firewall disabled'
    }
}
catch {
    Write-ControlResult 'CIS-3' 'NOT_APPLICABLE' 'Public firewall unavailable'
}

# ------------------------------------------------------------
# 4. Guest account disabled
# ------------------------------------------------------------
try {
    $Guest = Get-LocalUser -Name 'Guest' -ErrorAction Stop

    if (-not $Guest.Enabled) {
        Write-ControlResult 'CIS-4' 'PASS' 'Guest account disabled'
    }
    else {
        Write-ControlResult 'CIS-4' 'FAIL' 'Guest account enabled'
    }
}
catch {
    Write-ControlResult 'CIS-4' 'NOT_APPLICABLE' 'Guest account unavailable'
}

# ------------------------------------------------------------
# 5. Password minimum length
# ------------------------------------------------------------
try {
    $Accounts = net.exe accounts

    $Line = $Accounts |
        Where-Object {
            $_ -match 'Minimum password length'
        } |
        Select-Object -First 1

    if ($Line -match '(\d+)\s*$') {
        $Length = [int]$Matches[1]

        if ($Length -ge 14) {
            Write-ControlResult 'CIS-5' 'PASS' "Minimum password length: $Length"
        }
        else {
            Write-ControlResult 'CIS-5' 'FAIL' "Minimum password length: $Length"
        }
    }
    else {
        Write-ControlResult 'CIS-5' 'NOT_APPLICABLE' 'Password length not detected'
    }
}
catch {
    Write-ControlResult 'CIS-5' 'NOT_APPLICABLE' 'Password policy unavailable'
}

# ------------------------------------------------------------
# 6. Account lockout threshold
# ------------------------------------------------------------
try {
    $Accounts = net.exe accounts

    $Line = $Accounts |
        Where-Object {
            $_ -match 'Lockout threshold'
        } |
        Select-Object -First 1

    if ($Line -match '(\d+)\s*$') {
        $Threshold = [int]$Matches[1]

        if (($Threshold -gt 0) -and ($Threshold -le 10)) {
            Write-ControlResult 'CIS-6' 'PASS' "Lockout threshold: $Threshold"
        }
        else {
            Write-ControlResult 'CIS-6' 'FAIL' "Lockout threshold: $Threshold"
        }
    }
    else {
        Write-ControlResult 'CIS-6' 'NOT_APPLICABLE' 'Lockout threshold not detected'
    }
}
catch {
    Write-ControlResult 'CIS-6' 'NOT_APPLICABLE' 'Account policy unavailable'
}

# ------------------------------------------------------------
# 7. Windows Defender real-time protection
# ------------------------------------------------------------
try {
    $Defender = Get-MpComputerStatus -ErrorAction Stop

    if ($Defender.RealTimeProtectionEnabled) {
        Write-ControlResult 'CIS-7' 'PASS' 'Defender real-time protection enabled'
    }
    else {
        Write-ControlResult 'CIS-7' 'FAIL' 'Defender real-time protection disabled'
    }
}
catch {
    Write-ControlResult 'CIS-7' 'NOT_APPLICABLE' 'Microsoft Defender status unavailable'
}

# ------------------------------------------------------------
# 8. PowerShell Script Block Logging
# ------------------------------------------------------------
try {
    $Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'

    $Value = Get-ItemProperty `
        -Path $Path `
        -Name EnableScriptBlockLogging `
        -ErrorAction Stop

    if ($Value.EnableScriptBlockLogging -eq 1) {
        Write-ControlResult 'CIS-8' 'PASS' 'Script Block Logging enabled'
    }
    else {
        Write-ControlResult 'CIS-8' 'FAIL' 'Script Block Logging disabled'
    }
}
catch {
    Write-ControlResult 'CIS-8' 'FAIL' 'Script Block Logging not configured'
}

# ------------------------------------------------------------
# 9. PowerShell Module Logging
# ------------------------------------------------------------
try {
    $Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'

    $Value = Get-ItemProperty `
        -Path $Path `
        -Name EnableModuleLogging `
        -ErrorAction Stop

    if ($Value.EnableModuleLogging -eq 1) {
        Write-ControlResult 'CIS-9' 'PASS' 'Module Logging enabled'
    }
    else {
        Write-ControlResult 'CIS-9' 'FAIL' 'Module Logging disabled'
    }
}
catch {
    Write-ControlResult 'CIS-9' 'FAIL' 'Module Logging not configured'
}

# ------------------------------------------------------------
# 10. Audit process creation
# ------------------------------------------------------------
try {
    $Audit = auditpol.exe /get /subcategory:'Process Creation'

    if ($Audit -match 'Success') {
        Write-ControlResult 'CIS-10' 'PASS' 'Process Creation auditing enabled'
    }
    else {
        Write-ControlResult 'CIS-10' 'FAIL' 'Process Creation auditing not enabled'
    }
}
catch {
    Write-ControlResult 'CIS-10' 'NOT_APPLICABLE' 'Audit policy unavailable'
}

# ------------------------------------------------------------
# 11. Remote Registry service
# ------------------------------------------------------------
try {
    $Service = Get-Service -Name RemoteRegistry -ErrorAction Stop

    if ($Service.Status -ne 'Running') {
        Write-ControlResult 'CIS-11' 'PASS' 'Remote Registry not running'
    }
    else {
        Write-ControlResult 'CIS-11' 'FAIL' 'Remote Registry running'
    }
}
catch {
    Write-ControlResult 'CIS-11' 'NOT_APPLICABLE' 'Remote Registry service unavailable'
}

# ------------------------------------------------------------
# 12. Sysmon presence
# ------------------------------------------------------------
try {
    $Sysmon = Get-Service -Name 'Sysmon*' -ErrorAction Stop |
        Select-Object -First 1

    if ($null -ne $Sysmon) {
        Write-ControlResult 'CIS-12' 'PASS' 'Sysmon service present'
    }
    else {
        Write-ControlResult 'CIS-12' 'FAIL' 'Sysmon service missing'
    }
}
catch {
    Write-ControlResult 'CIS-12' 'FAIL' 'Sysmon service missing'
}

exit 0
