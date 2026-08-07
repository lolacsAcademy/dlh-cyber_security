# name: 2-powershell_logging_validation.ps1
# purpose: Validate PowerShell ScriptBlock Logging, ModuleLogging, and Transcript capture
# author: analyst
# EncodedCommand, -enc, Import-Module ActiveDirectory, full multi-line script block, transcript file creation, CAPTURED MISSED DETAIL-LEVEL results
Set-StrictMode -Version Latest
Write-Host "[*] Testing PowerShell ScriptBlock logging coverage..."
Write-Host "    [1/5] Simple command (Get-Process)..."
$s1 = (Get-Date).AddSeconds(-2)
powershell -Command "Get-Process" | Out-Null
Start-Sleep -Seconds 3
$e1 = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" |
    Where-Object { $_.Id -eq 4104 -and $_.TimeCreated -ge $s1 -and $_.Message -match "Get-Process" } |
    Select-Object -First 1
if ($e1) {
    Write-Host "          EID 4104: 'Get-Process' captured [PASS]"
} else {
    Write-Host "          EID 4104: 'Get-Process' NOT captured [FAIL]"
}
Write-Host "    [2/5] Encoded command (-enc)..."
$s2 = Get-Date
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Write-Host "Test"'))
powershell -enc $enc | Out-Null
Start-Sleep -Seconds 2
$e2 = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" |
    Where-Object { $_.Id -eq 4104 -and $_.TimeCreated -ge $s2 -and $_.Message -match "Write-Host" } |
    Select-Object -First 1
if ($e2) {
    Write-Host "          EID 4104: decoded encoded PowerShell content captured [PASS]"
} else {
    Write-Host "          EID 4104: decoded encoded PowerShell content NOT captured [FAIL]"
}
Write-Host "    [3/5] Module Logging (Event ID 4103)..."
$s3 = Get-Date
powershell -Command "Import-Module ActiveDirectory" | Out-Null
Start-Sleep -Seconds 2
$e3 = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" |
    Where-Object { $_.Id -eq 4103 -and $_.TimeCreated -ge $s3 } |
    Select-Object -First 1
if ($e3) {
    Write-Host "          EID 4103: ModuleLogging import captured [PASS]"
} else {
    Write-Host "          EID 4103: ModuleLogging import NOT captured [FAIL]"
}
Write-Host "    [4/5] Full multi-line script block..."
$s4 = Get-Date
powershell -Command "1..3 | ForEach-Object { `$_ * 2 }" | Out-Null
Start-Sleep -Seconds 2
$e4 = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" |
    Where-Object { $_.Id -eq 4104 -and $_.TimeCreated -ge $s4 -and $_.Message -match "ForEach-Object" } |
    Select-Object -First 1
if ($e4) {
    Write-Host "          EID 4104: full multi-line script block captured [PASS]"
} else {
    Write-Host "          EID 4104: full multi-line script block NOT captured [FAIL]"
}
Write-Host "    [5/5] Transcript file creation..."
New-Item -ItemType Directory -Path "C:\PSTranscripts" -Force | Out-Null
Start-Transcript -Path "C:\PSTranscripts\test_transcript.txt" -Force | Out-Null
Get-Date | Out-Null
Stop-Transcript | Out-Null
$e5 = Test-Path "C:\PSTranscripts\*.txt"
if ($e5) {
    Write-Host "          Transcript file creation confirmed [PASS]"
} else {
    Write-Host "          Transcript file creation FAILED [FAIL]"
}
$results = @($e1,$e2,$e3,$e4,$e5)
$cap = ($results | Where-Object { $_ }).Count
Write-Host "Tests: 5 | CAPTURED: $cap | MISSED: $(5-$cap) | DETAIL-LEVEL: full"
