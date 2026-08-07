# name: 3-windows_telemetry_export.ps1
# purpose: export Windows telemetry (Security, Sysmon, PowerShell logs) into normalized analyst-ready JSON with timestamp, hostname, platform, source_type, channel, event_id, event_category, provider, raw_message and event-specific enrichment
# author: analyst
param([int]$HoursBack = 24)
Set-StrictMode -Version Latest

Write-Host "[*] Exporting Windows telemetry from last $HoursBack hours..."
$since = (Get-Date).AddHours(-$HoursBack)
$hostname = $env:COMPUTERNAME

function Get-Enrichment($evt) {
    $data = @{}
    try {
        $x = [xml]$evt.ToXml()
        if ($x.Event.EventData -and $x.Event.EventData.Data) {
            foreach ($d in $x.Event.EventData.Data) {
                if ($d.Name) { $data[$d.Name] = $d.InnerText }
            }
        }
    } catch {}
    switch ($evt.Id) {
        4624 { return @{target_user=$data['TargetUserName']; logon_type=$data['LogonType']; source_ip=$data['IpAddress']; workstation=$data['WorkstationName']} }
        4625 { return @{target_user=$data['TargetUserName']; failure_reason=$data['FailureReason']; source_ip=$data['IpAddress']} }
        4672 { return @{privileged_account=$data['SubjectUserName']} }
        4688 { return @{process_name=$data['NewProcessName']; command_line=$data['CommandLine']; parent_process=$data['ParentProcessName']} }
        4104 { return @{decoded_script_block=$data['ScriptBlockText']} }
        1    { return @{image=$data['Image']; command_line=$data['CommandLine']; parent_image=$data['ParentImage']; hashes=$data['Hashes']} }
        3    { return @{destination_ip=$data['DestinationIp']; destination_port=$data['DestinationPort']; process=$data['Image']} }
        11   { return @{target_filename=$data['TargetFilename']; creating_process=$data['Image']} }
        13   { return @{registry_key=$data['TargetObject']; value_name=$data['Details']} }
        22   { return @{query_name=$data['QueryName']; query_results=$data['QueryResults']} }
        default { return @{} }
    }
}

function Export-Channel($channel, $sourceType) {
    Get-WinEvent -FilterHashtable @{LogName=$channel; StartTime=$since} -ErrorAction SilentlyContinue | ForEach-Object {
        $enrich = Get-Enrichment $_
        $obj = [PSCustomObject]@{
            timestamp = $_.TimeCreated
            hostname = $hostname
            platform = "Windows"
            source_type = $sourceType
            channel = $channel
            event_id = $_.Id
            event_category = $_.LevelDisplayName
            provider = $_.ProviderName
            raw_message = $_.Message
        }
        if ($enrich -and $enrich.Count -gt 0) { $obj | Add-Member -NotePropertyMembers $enrich }
        $obj
    }
}

$security = @(Export-Channel "Security" "WindowsSecurity")
$sysmon = @(Export-Channel "Microsoft-Windows-Sysmon/Operational" "Sysmon")
$ps = @(Export-Channel "Microsoft-Windows-PowerShell/Operational" "PowerShell")

$all = $security + $sysmon + $ps
Write-Host "Security events: $($security.Count)"
Write-Host "Sysmon events: $($sysmon.Count)"
Write-Host "PowerShell events: $($ps.Count)"
Write-Host "Total events: $($all.Count)"
$top = $all | Group-Object event_id | Sort-Object Count -Descending | Select-Object -First 4 -ExpandProperty Name
Write-Host "Top Event IDs: $($top -join ', ')"
$all | ConvertTo-Json -Depth 5 | Out-File "windows_events_export.json"
Write-Host "Output: windows_events_export.json"
