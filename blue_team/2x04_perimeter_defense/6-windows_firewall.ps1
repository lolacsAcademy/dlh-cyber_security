# name: 6-windows_firewall.ps1
# purpose: Align Windows Firewall to segmentation_rules.json
# author: analyst
# date: 2026-08-14
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$rulesJson = "C:\meddefense\segmentation_rules.json"
Write-Host "[*] Reading segmentation_rules.json..."
$rules = Get-Content $rulesJson -Raw | ConvertFrom-Json

Write-Host "[*] Setting profile defaults..."
foreach ($profile in @("Domain", "Private", "Public")) {
    Set-NetFirewallProfile -Profile $profile -DefaultInboundAction Block -DefaultOutboundAction Allow -LogBlocked True -LogFileName "%systemroot%\system32\LogFiles\Firewall\meddefense.log"
    Write-Host "  ${profile}: DefaultInboundAction=Block  LogBlocked=True   [SET]"
}

Write-Host "[*] Clearing previous MedDefense-* rules..."
$existing = Get-NetFirewallRule -DisplayName "MedDefense-*" -ErrorAction SilentlyContinue
$removedCount = ($existing | Measure-Object).Count
if ($existing) { $existing | Remove-NetFirewallRule }
Write-Host "  [$removedCount removed]"

Write-Host "[*] Creating rules from flow matrix..."
$zones = @{}
foreach ($z in $rules.zones) { $zones[$z.name] = $z.cidr }

$hostZones = @("INTERNAL")

foreach ($flow in $rules.flows) {
    if ($flow.dst_zone -in $hostZones -and $flow.justification -ne "deny_all" -and $flow.src_zone -ne "ALL") {
        $srcCidr = $zones[$flow.src_zone]
        if ($srcCidr) {
            $name = "MedDefense-$($flow.src_zone)-$($flow.proto.ToUpper())-$($flow.dport)"
            New-NetFirewallRule -DisplayName $name -Direction Inbound -Action Allow -Protocol $flow.proto -LocalPort $flow.dport -RemoteAddress $srcCidr -Profile Any | Out-Null
            Write-Host "  $name Inbound Allow $($flow.proto) $($flow.dport)  [CREATED]"
        }
    }
}

Get-NetFirewallRule -DisplayName "MedDefense-*" | ForEach-Object {
    $filter = $_ | Get-NetFirewallAddressFilter
    [PSCustomObject]@{
        DisplayName = $_.DisplayName
        Direction = $_.Direction.ToString()
        Action = $_.Action.ToString()
        RemoteAddress = $filter.RemoteAddress
    }
} | ConvertTo-Json | Out-File "C:\meddefense\windows_firewall_rules.json"

Write-Host "[*] Done."
