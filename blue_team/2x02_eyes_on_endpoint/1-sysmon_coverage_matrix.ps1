# Name: 1-sysmon_coverage_matrix.ps1
# Purpose: Generate ATT&CK-aligned Sysmon coverage matrix from sysmonconfig.xml
# Author: analyst
Set-StrictMode -Version Latest

Write-Host "[*] Parsing Sysmon config: sysmonconfig.xml"
[xml]$cfg = Get-Content "sysmonconfig.xml"
$enabled = $cfg.Sysmon.EventFiltering.ChildNodes.LocalName
$map = @{ProcessCreate=1; NetworkConnect=3; ImageLoad=7; FileCreate=11; RegistryEvent=13; DnsQuery=22}
$ids = $enabled | ForEach-Object { $map[$_] } | Where-Object { $_ } | Sort-Object -Unique
Write-Host "Enabled Event IDs: $($ids -join ', ')"

$techniques = @(
    [PSCustomObject]@{id="T1059"; name="Command and Scripting Interpreter"; req=@(1); evidence="CommandLine, ParentImage"}
    [PSCustomObject]@{id="T1053"; name="Scheduled Task/Job"; req=@(1); evidence="CommandLine, ParentImage"}
    [PSCustomObject]@{id="T1547"; name="Boot or Logon Autostart Execution"; req=@(13); evidence="TargetObject, Details"}
    [PSCustomObject]@{id="T1055"; name="Process Injection"; req=@(8,10); evidence="SourceImage, TargetImage, GrantedAccess"}
    [PSCustomObject]@{id="T1071"; name="Application Layer Protocol"; req=@(3,22); evidence="DestinationIp, DestinationPort, QueryName"}
    [PSCustomObject]@{id="T1574.002"; name="DLL Side-Loading"; req=@(7); evidence="ImageLoaded, Signed, Signature"}
    [PSCustomObject]@{id="T1027"; name="Obfuscated or Compressed Files"; req=@(11,15); evidence="TargetFilename, Hash"}
)

$report = foreach ($t in $techniques) {
    $have = @($t.req | Where-Object { $ids -contains $_ })
    $miss = @($t.req | Where-Object { $ids -notcontains $_ })
    $status = if ($miss.Count -eq 0) {"covered"} elseif ($have.Count -gt 0) {"partial"} else {"blind"}
    $rec = if ($miss.Count -gt 0) {"Enable Event ID $($miss -join ',') in sysmonconfig.xml"} else {""}
    [PSCustomObject]@{
        technique_id=$t.id; technique_name=$t.name; required_event_ids=$t.req
        enabled_event_ids=$have; filter_conflicts=@(); coverage_status=$status
        evidence_fields_expected=$t.evidence; recommendation=$rec
    }
}

Write-Host "Techniques assessed: $($report.Count)"
Write-Host "Covered: $(@($report | Where-Object {$_.coverage_status -eq 'covered'}).Count)"
Write-Host "Partial: $(@($report | Where-Object {$_.coverage_status -eq 'partial'}).Count)"
Write-Host "Blind: $(@($report | Where-Object {$_.coverage_status -eq 'blind'}).Count)"
$report | ConvertTo-Json -Depth 5 | Out-File "sysmon_coverage_matrix.json"
Write-Host "Report saved to: sysmon_coverage_matrix.json"
