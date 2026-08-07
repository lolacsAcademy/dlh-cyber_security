# name: 4-windows_telemetry_quality.ps1
# purpose: analyze windows_events_export.json for Event Distribution, Channel Distribution, Time Coverage and gap detection (gaps longer than 30 minutes), Field Completeness for key event types, and a Weighted quality score and assessment (good, acceptable, poor). Calculates events per hour, hours with events, hours without events. Writes windowstelemetryquality.json
# author: analyst
Set-StrictMode -Version Latest

Write-Host "[*] Analyzing windows_events_export.json..."
$events = Get-Content "windows_events_export.json" | ConvertFrom-Json
$total = $events.Count
Write-Host "Total events: $total"

Write-Host "Event Distribution and Channel Distribution:"
$eventIdDist = $events | Group-Object event_id | ForEach-Object {
    [PSCustomObject]@{event_id=$_.Name; count=$_.Count; percentage=[math]::Round(($_.Count/$total)*100,1)}
}
$channelDist = $events | Group-Object source_type | ForEach-Object {
    [PSCustomObject]@{channel=$_.Name; count=$_.Count; percentage=[math]::Round(($_.Count/$total)*100,1)}
}

Write-Host "Time Coverage and gap detection: events per hour, hours with events, hours without events, gaps longer than 30 minutes"
$times = $events | ForEach-Object { [datetime]$_.timestamp } | Sort-Object
$hourBuckets = $times | ForEach-Object { $_.ToString("yyyy-MM-dd HH:00") } | Group-Object
$hoursWithEvents = $hourBuckets.Count
$totalHours = [math]::Ceiling(($times[-1] - $times[0]).TotalHours)
if ($totalHours -lt 1) { $totalHours = 1 }
$hoursWithoutEvents = $totalHours - $hoursWithEvents
$gaps = @()
for ($i=1; $i -lt $times.Count; $i++) {
    $diff = ($times[$i] - $times[$i-1]).TotalMinutes
    if ($diff -gt 30) { $gaps += $diff }
}
$largestGap = if ($gaps.Count -gt 0) { [math]::Round(($gaps | Measure-Object -Maximum).Maximum,0) } else { 0 }

Write-Host "Field Completeness for key event types"
$procEvents = $events | Where-Object { $_.event_id -in @(4688,1) }
$cmdComplete = if ($procEvents.Count -gt 0) { [math]::Round((($procEvents | Where-Object {$_.command_line}).Count/$procEvents.Count)*100,1) } else { 100 }
$logonEvents = $events | Where-Object { $_.event_id -in @(4624,4625) }
$ipComplete = if ($logonEvents.Count -gt 0) { [math]::Round((($logonEvents | Where-Object {$_.source_ip}).Count/$logonEvents.Count)*100,1) } else { 100 }
$psEvents = $events | Where-Object { $_.event_id -eq 4104 }
$sbComplete = if ($psEvents.Count -gt 0) { [math]::Round((($psEvents | Where-Object {$_.decoded_script_block}).Count/$psEvents.Count)*100,1) } else { 100 }

Write-Host "Weighted quality score and assessment"
$hourScore = ($hoursWithEvents/$totalHours)*100
$score = [math]::Round((($cmdComplete*0.3)+($ipComplete*0.3)+($sbComplete*0.2)+($hourScore*0.2)),1)
$assessment = if ($score -ge 90) {"good"} elseif ($score -ge 70) {"acceptable"} else {"poor"}

Write-Host "Hours with events: $hoursWithEvents/$totalHours"
Write-Host "Largest gap: $largestGap minutes"
Write-Host "Command-line completeness: $cmdComplete%"
Write-Host "Source IP completeness: $ipComplete%"
Write-Host "Script block completeness: $sbComplete%"
Write-Host "Quality score: $score% ($assessment)"

$report = [PSCustomObject]@{
    event_distribution = $eventIdDist
    channel_distribution = $channelDist
    hours_with_events = $hoursWithEvents
    hours_without_events = $hoursWithoutEvents
    total_hours = $totalHours
    largest_gap_minutes = $largestGap
    command_line_completeness = $cmdComplete
    source_ip_completeness = $ipComplete
    script_block_completeness = $sbComplete
    quality_score = $score
    assessment = $assessment
}

$report | ConvertTo-Json -Depth 5 | Out-File "windowstelemetryquality.json"
Write-Host "Report saved to: windowstelemetryquality.json"
