<#
Script: 2-eventlog_assessment.ps1
Purpose: Assess Windows audit policy and event log visibility
Author: Chocolat
Date: 2026-08-03
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$events = @(
    @{ID=4624;Desc="Successful Logon";Sub="Logon"}
    @{ID=4625;Desc="Failed Logon";Sub="Logon"}
    @{ID=4648;Desc="Explicit Credentials";Sub="Logon"}
    @{ID=4688;Desc="Process Creation";Sub="Process Tracking"}
    @{ID=4720;Desc="Account Created";Sub="Account Management"}
    @{ID=4726;Desc="Account Deleted";Sub="Account Management"}
    @{ID=4732;Desc="Member Added to Group";Sub="Account Management"}
    @{ID=4672;Desc="Special Logon";Sub="Special Logon"}
    @{ID=1102;Desc="Audit Log Cleared";Sub="System Integrity"}
)

$audit = auditpol /get /category:* /r | ConvertFrom-Csv
$since = (Get-Date).AddHours(-24)

Write-Host ("{0,-9}{1,-26}{2,-22}{3}" -f "Event ID","Description","Audit Subcategory","Status")
Write-Host ("{0,-9}{1,-26}{2,-22}{3}" -f "--------","-----------","-----------------","------")

foreach ($e in $events) {
    $gen = Get-WinEvent -FilterHashtable @{LogName="Security";Id=$e.ID;StartTime=$since} -ErrorAction SilentlyContinue
    $status = if ($gen) {"[GENERATING]"} else {"[NOT CONFIGURED]"}
    Write-Host ("{0,-9}{1,-26}{2,-22}{3}" -f $e.ID,$e.Desc,$e.Sub,$status)
}
