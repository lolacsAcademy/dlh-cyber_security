# Name: 2-powershell_logging_validation.ps1
# Purpose: Validate PowerShell Script Block, Module Logging, and Transcription
# Author: analyst
Set-StrictMode -Version Latest

Write-Host "[*] Testing PowerShell logging coverage..."

Write-Host "    [1/5] Simple command (Get-Process)..."
$s1 = (Get-Date).AddSeconds(-2)
powershell -Command "Get-Process" | Out-Null
Start-Sleep -Seconds 3
$e1 = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" |
    Where-Object { $_.Id -eq 4104 -and $_.TimeCreated -ge $s1 -and $_.Message -match "Get-Process" } | Select-Object -First 1
if ($e1) { Write-Host "          EID 4104: 'Get-Process' captured                     [PASS]" }
else { Write-Host "          EID 4104: 'Get-Process' NOT captured                     [FAIL]" }

Write-Host "    [2/5] Encoded command..."
$s2 = Get-Date
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Write-Host "Test"'))
powershell -enc $enc | Out-Null
Start-Sleep -Seconds 2
$e2 = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" |
    Where-Object { $_.Id -eq 4104 -and $_.TimeCreated -ge $s2 -and $_.Message -match "Write-Host" } | Select-Object -First 1
Write-Host "          Input: -enc $enc"
if ($e2) { Write-Host "          EID 4104: decoded content captured                   [PASS]" }
else { Write-Host "          EID 4104: decoded content NOT captured                   [FAIL]" }

Write-Host "    [3/5] Module import..."
$s3 = Get-Date
powershell -Command "Import-Module Microsoft.PowerShell.Management -Force"
Start-Sleep -Seconds 2
$e3 = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" |
    Where-Object { $_.Id -eq 4103 -and $_.TimeCreated -ge $s3 } | Select-Object -First 1
if ($e3) { Write-Host "          EID 4103: module import captured                     [PASS]" }
else { Write-Host "          EID 4103: module import NOT captured                     [FAIL]" }

Write-Host "    [4/5] Multi-line script block..."
$s4 = Get-Date
powershell -Command "1..3 | ForEach-Object { `$_ * 2 }" | Out-Null
Start-Sleep -Seconds 2
$e4 = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" |
    Where-Object { $_.Id -eq 4104 -and $_.TimeCreated -ge $s4 -and $_.Message -match "ForEach-Object" } | Select-Object -First 1
if ($e4) { Write-Host "          EID 4104: multi-line block captured                  [PASS]" }
else { Write-Host "          EID 4104: multi-line block NOT captured                  [FAIL]" }

Write-Host "    [5/5] Transcription file..."
Start-Transcript -Path "C:\PSTranscripts\test_transcript.txt" -Force | Out-Null
Get-Date | Out-Null
Stop-Transcript | Out-Null
$e5 = Test-Path "C:\PSTranscripts\*.txt"
if ($e5) { Write-Host "          C:\PSTranscripts\*.txt exists, session recorded       [PASS]" }
else { Write-Host "          C:\PSTranscripts\*.txt NOT found                         [FAIL]" }

$results = @($e1, $e2, $e3, $e4, $e5)
$cap = @($results | Where-Object { $_ }).Count
Write-Host "Tests: 5 | Captured: $cap | Missed: $(5 - $cap)"
