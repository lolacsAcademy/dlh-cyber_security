# Name: 1-sysmon_coverage_matrix.ps1
# Purpose: Generate ATT&CK-aligned Sysmon coverage matrix from sysmonconfig.xml
# Author: analyst
Set-StrictMode -Version Latest
Write-Host "[*] Parsing Sysmon config: sysmonconfig.xml"
[xml]$cfg = Get-Content "sysmonconfig.xml"
$enabledIds = @{1=$false;3=$false;7=$false;8=$false;10=$false;11=$false;12=$false;13=$false;15=$false;22=$false}
$rules = $cfg.Sysmon.EventFiltering.ChildNodes
foreach ($r in $rules) {
    switch ($r.LocalName) {
        "ProcessCreate"   { $enabledIds[1]  = $true }
        "NetworkConnect"  { $enabledIds[3]  = $true }
        "CreateRemoteThread" { $enabledIds[8] = $true }
        "ProcessAccess"   { $enabledIds[10] = $true }
        "FileCreate"      { $enabledIds[11] = $true }
        "RegistryEvent"   { $enabledIds[12] = $true; $enabledIds[13] = $true }
        "ImageLoad"       { $enabledIds[7]  = $true }
        "FileCreateStreamHash" { $enabledIds[15] = $true }
        "DnsQuery"        { $enabledIds[22] = $true }
    }
}
$enabledList = ($enabledIds.GetEnumerator() | Where-Object {$_.Value} | Sort-Object Name | ForEach-Object {$_.Name}) -join ", "
Write-Host "Enabled Event IDs: $enabledList"
$techniques = @(
    @{id="T1059"; name="Command and Scripting Interpreter"; req=@(1); evidence="CommandLine, ParentImage"},
    @{id="T1053"; name="Scheduled Task/Job"; req=@(1); evidence="CommandLine, ParentImage"},
    @{id="T1547"; name="Boot or Logon Autostart Execution"; req=@(13); evidence="TargetObject, Details"},
    @{id="T1055"; name="Process Injection"; req=@(8,10); evidence="SourceImage, TargetImage, GrantedAccess"},
    @{id="T1071"; name="Application Layer Protocol"; req=@(3,22); evidence="DestinationIp, DestinationPort, QueryName"},
    @{id="T1574.002"; name="DLL Side-Loading"; req=@(7); evidence="ImageLoaded, Signed, Signature"},
    @{id="T1027"; name="Obfuscated or Compressed Files"; req=@(11,15); evidence="TargetFilename, Hash"}
)
$report = @()
foreach ($t in $techniques) {
    $enabled = @($t.req | Where-Object { $enabledIds[$_] })
    $missing = @($t.req | Where-Object { -not $enabledIds[$_] })
    if ($missing.Count -eq 0) {
        $status = "covered"; $rec = ""
    } elseif ($enabled.Count -gt 0) {
        $status = "partial"; $rec = "Enable Event ID $($missing -join ',') in sysmonconfig.xml"
    } else {
        $status = "blind"; $rec = "Enable Event ID $($t.req -join ',') in sysmonconfig.xml"
    }
    $report += [PSCustomObject]@{
        technique_id = $t.id
        technique_name = $t.name
        required_event_ids = $t.req
        enabled_event_ids = $enabled
        filter_conflicts = @()
        coverage_status = $status
        evidence_fields_expected = $t.evidence
        recommendation = $rec
    }
}
$covered = @($report | Where-Object {$_.coverage_status -eq "covered"}).Count
$partial = @($report | Where-Object {$_.coverage_status -eq "partial"}).Count
$blind = @($report | Where-Object {$_.coverage_status -eq "blind"}).Count
Write-Host "Techniques assessed: $($report.Count)"
Write-Host "Covered: $covered"
Write-Host "Partial: $partial"
Write-Host "Blind: $blind"
$report | ConvertTo-Json -Depth 5 | Out-File "sysmon_coverage_matrix.json"
Write-Host "Report saved to: sysmon_coverage_matrix.json"
