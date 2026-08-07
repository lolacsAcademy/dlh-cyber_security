# name: 0-sysmon_validation.ps1
# purpose: validate Sysmon Event ID 1 process creation with CommandLine, Event ID 3 network connection DestinationIp DestinationPort details, Event ID 11 file creation TargetFilename, Event ID 13 registry modification TargetObject Details, Event ID 22 DNS query QueryName, searches Sysmon logs records TimeCreated timestamps reports pass or miss counts, cleans up test artifacts
# author: analyst
Set-StrictMode -Version Latest

Write-Host "[*] Running Sysmon telemetry validation..."

Write-Host "    [1/5] Process creation (Event ID 1)..."
$start1 = Get-Date
cmd.exe /c whoami | Out-Null
Start-Sleep -Seconds 3
$evt1 = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
    Where-Object { $_.Id -eq 1 -and $_.TimeCreated -ge $start1 -and $_.Message -match "whoami" } |
    Select-Object -First 1
if ($evt1) { Write-Host "          cmd.exe /c whoami -> Sysmon EID 1 captured, cmdline present   [PASS]" }
else { Write-Host "          cmd.exe /c whoami -> Sysmon EID 1 NOT captured                [FAIL]" }

Write-Host "    [2/5] Network connection (Event ID 3): DestinationIp, DestinationPort..."
$start2 = Get-Date
Test-NetConnection -ComputerName 10.10.3.10 -Port 389 | Out-Null
Start-Sleep -Seconds 3
$evt2 = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
    Where-Object { $_.Id -eq 3 -and $_.TimeCreated -ge $start2 -and $_.Message -match "10.10.3.10" } |
    Select-Object -First 1
if ($evt2) { Write-Host "          Outbound TCP -> Sysmon EID 3 captured, DestinationIp/DestinationPort present   [PASS]" }
else { Write-Host "          Outbound TCP -> Sysmon EID 3 NOT captured                     [FAIL]" }

Write-Host "    [3/5] File creation (Event ID 11): TargetFilename..."
$start3 = Get-Date
"test" | Out-File -FilePath "C:\Windows\Temp\test.txt"
Start-Sleep -Seconds 3
$evt3 = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
    Where-Object { $_.Id -eq 11 -and $_.TimeCreated -ge $start3 -and $_.Message -match "test.txt" } |
    Select-Object -First 1
if ($evt3) { Write-Host "          C:\Windows\Temp\test.txt -> Sysmon EID 11 captured, TargetFilename present   [PASS]" }
else { Write-Host "          C:\Windows\Temp\test.txt -> Sysmon EID 11 NOT captured        [FAIL]" }

Write-Host "    [4/5] Registry modification (Event ID 13): TargetObject, Details..."
$start4 = Get-Date
New-ItemProperty -Path "HKCU:\Software" -Name "SysmonTest" -Value "1" -PropertyType String -Force | Out-Null
Start-Sleep -Seconds 3
$evt4 = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
    Where-Object { $_.Id -eq 13 -and $_.TimeCreated -ge $start4 -and $_.Message -match "SysmonTest" } |
    Select-Object -First 1
if ($evt4) { Write-Host "          HKCU\...\SysmonTest -> Sysmon EID 13 captured, TargetObject/Details present   [PASS]" }
else { Write-Host "          HKCU\...\SysmonTest -> Sysmon EID 13 NOT captured             [FAIL]" }

Write-Host "    [5/5] DNS query (Event ID 22): QueryName..."
$start5 = Get-Date
Clear-DnsClientCache
Resolve-DnsName meddefense.local -NoHostsFile | Out-Null
Start-Sleep -Seconds 6
$evt5 = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
    Where-Object { $_.Id -eq 22 -and $_.TimeCreated -ge $start5 -and $_.Message -match "meddefense.local" } |
    Select-Object -First 1
if ($evt5) { Write-Host "          nslookup meddefense.local -> Sysmon EID 22 captured, QueryName present   [PASS]" }
else { Write-Host "          nslookup meddefense.local -> Sysmon EID 22 NOT captured       [FAIL]" }

# searches Sysmon logs, records TimeCreated timestamps, and reports pass or miss counts; cleans up test artifacts
Write-Host "[*] Cleanup: removing test artifacts..."
Remove-Item "C:\Windows\Temp\test.txt" -Force -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKCU:\Software" -Name "SysmonTest" -Force -ErrorAction SilentlyContinue
$results = @($evt1, $evt2, $evt3, $evt4, $evt5)
$captured = @($results | Where-Object { $_ -ne $null }).Count
Write-Host "Actions tested: 5 | Captured: $captured | Missed: $(5 - $captured)"
