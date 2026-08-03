<#
Script: 3-telemetry_reference.ps1
Purpose: Build Windows event telemetry reference
Author: Chocolat
Date: 2026-08-03
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$events = @(
    [PSCustomObject]@{event_id="4624";event_name="Successful Logon";log_source="Security";audit_or_sensor_dependency="Logon subcategory";security_meaning="Account authenticated";normal_frequency="High";triage_priority="Low";crimson_tide_phase="Initial Access";example_suspicious_pattern="Logon from unusual IP";validation_method="Get-WinEvent -Id 4624"}
    [PSCustomObject]@{event_id="4625";event_name="Failed Logon";log_source="Security";audit_or_sensor_dependency="Logon subcategory";security_meaning="Authentication failed";normal_frequency="Medium";triage_priority="Medium";crimson_tide_phase="Initial Access";example_suspicious_pattern="High volume of failed logon attempts from one source";validation_method="Get-WinEvent -Id 4625"}
    [PSCustomObject]@{event_id="4648";event_name="Explicit Credentials";log_source="Security";audit_or_sensor_dependency="Logon subcategory";security_meaning="Alternate credentials used";normal_frequency="Low";triage_priority="High";crimson_tide_phase="Lateral Movement";example_suspicious_pattern="Service account used interactively";validation_method="Get-WinEvent -Id 4648"}
    [PSCustomObject]@{event_id="4672";event_name="Special Logon";log_source="Security";audit_or_sensor_dependency="Special Logon subcategory";security_meaning="Admin privileges assigned";normal_frequency="Low";triage_priority="High";crimson_tide_phase="Privilege Escalation";example_suspicious_pattern="Privileged logon off-hours";validation_method="Get-WinEvent -Id 4672"}
    [PSCustomObject]@{event_id="4688";event_name="Process Creation";log_source="Security";audit_or_sensor_dependency="Process Tracking subcategory";security_meaning="New process launched";normal_frequency="High";triage_priority="Medium";crimson_tide_phase="Execution";example_suspicious_pattern="Encoded PowerShell command";validation_method="Get-WinEvent -Id 4688"}
    [PSCustomObject]@{event_id="4720";event_name="Account Created";log_source="Security";audit_or_sensor_dependency="Account Management subcategory";security_meaning="New account created";normal_frequency="Low";triage_priority="High";crimson_tide_phase="Persistence";example_suspicious_pattern="Account created off-hours";validation_method="Get-WinEvent -Id 4720"}
    [PSCustomObject]@{event_id="4726";event_name="Account Deleted";log_source="Security";audit_or_sensor_dependency="Account Management subcategory";security_meaning="Account deleted";normal_frequency="Low";triage_priority="Medium";crimson_tide_phase="Defense Evasion";example_suspicious_pattern="Deletion of attacker account";validation_method="Get-WinEvent -Id 4726"}
    [PSCustomObject]@{event_id="4732";event_name="Member Added to Group";log_source="Security";audit_or_sensor_dependency="Account Management subcategory";security_meaning="Account added to group";normal_frequency="Low";triage_priority="High";crimson_tide_phase="Privilege Escalation";example_suspicious_pattern="Added to Domain Admins";validation_method="Get-WinEvent -Id 4732"}
    [PSCustomObject]@{event_id="1102";event_name="Audit Log Cleared";log_source="Security";audit_or_sensor_dependency="System Integrity subcategory";security_meaning="Security log cleared";normal_frequency="Rare";triage_priority="Critical";crimson_tide_phase="Defense Evasion";example_suspicious_pattern="Cleared after privileged logon";validation_method="Get-WinEvent -Id 1102"}
    [PSCustomObject]@{event_id="4103";event_name="Module Logging";log_source="PowerShell";audit_or_sensor_dependency="Module Logging enabled";security_meaning="Module/pipeline execution logged";normal_frequency="High";triage_priority="Medium";crimson_tide_phase="Execution";example_suspicious_pattern="Suspicious module loaded";validation_method="Get-WinEvent -Id 4103"}
    [PSCustomObject]@{event_id="4104";event_name="Script Block Logging";log_source="PowerShell";audit_or_sensor_dependency="Script Block Logging enabled";security_meaning="Full script content logged";normal_frequency="Medium";triage_priority="High";crimson_tide_phase="Execution";example_suspicious_pattern="Obfuscated/base64 script";validation_method="Get-WinEvent -Id 4104"}
    [PSCustomObject]@{event_id="1";event_name="Process Creation";log_source="Sysmon";audit_or_sensor_dependency="Sysmon installed";security_meaning="Detailed process creation";normal_frequency="High";triage_priority="Medium";crimson_tide_phase="Execution";example_suspicious_pattern="Unsigned binary from Temp";validation_method="Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -Id 1"}
    [PSCustomObject]@{event_id="3";event_name="Network Connection";log_source="Sysmon";audit_or_sensor_dependency="Sysmon installed";security_meaning="Network connection made";normal_frequency="High";triage_priority="Medium";crimson_tide_phase="Command and Control";example_suspicious_pattern="Connection to rare external IP";validation_method="Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -Id 3"}
    [PSCustomObject]@{event_id="7";event_name="Image Loaded";log_source="Sysmon";audit_or_sensor_dependency="Sysmon installed";security_meaning="DLL loaded into process";normal_frequency="High";triage_priority="Low";crimson_tide_phase="Execution";example_suspicious_pattern="Unsigned DLL into lsass.exe";validation_method="Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -Id 7"}
    [PSCustomObject]@{event_id="11";event_name="File Created";log_source="Sysmon";audit_or_sensor_dependency="Sysmon installed";security_meaning="File written to disk";normal_frequency="High";triage_priority="Medium";crimson_tide_phase="Impact";example_suspicious_pattern="Mass file creation, ransomware ext";validation_method="Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -Id 11"}
    [PSCustomObject]@{event_id="13";event_name="Registry Value Set";log_source="Sysmon";audit_or_sensor_dependency="Sysmon installed";security_meaning="Registry value modified";normal_frequency="Medium";triage_priority="Medium";crimson_tide_phase="Persistence";example_suspicious_pattern="Run key added";validation_method="Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -Id 13"}
    [PSCustomObject]@{event_id="22";event_name="DNS Query";log_source="Sysmon";audit_or_sensor_dependency="Sysmon installed";security_meaning="DNS resolution requested";normal_frequency="High";triage_priority="Medium";crimson_tide_phase="Command and Control";example_suspicious_pattern="Query to malicious domain";validation_method="Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -Id 22"}
)

$sec = @($events | ? {$_.log_source -eq "Security"})
$ps = @($events | ? {$_.log_source -eq "PowerShell"})
$sysmon = @($events | ? {$_.log_source -eq "Sysmon"})

Write-Host "Security events mapped: $($sec.Count)"
Write-Host "PowerShell events mapped: $($ps.Count)"
Write-Host "Sysmon events mapped: $($sysmon.Count)"
Write-Host "Total events documented: $($events.Count)"

$events | ConvertTo-Json -Depth 5 | Out-File "windows_event_reference.json" -Encoding utf8
Write-Host "Reference saved to: windows_event_reference.json"
