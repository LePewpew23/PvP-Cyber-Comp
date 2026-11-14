#requires -Version 5.1
<#
.SYNOPSIS
Create inbound block rules for exact remote IPv4/IPv6 addresses.
.DESCRIPTION
Default: block ALL inbound protocols/ports from the supplied IPs, on every profile.
Use -Traffic SMB for TCP 445 only. Use -Direction Both to also block outbound
traffic TO those IPs (for outbound SMB, the destination/remote port is 445).
No CIDRs, IP ranges, hostnames or automatic Kali discovery are accepted.
Default is preview; -Apply creates new local rules only. Existing rules are never
overwritten. Rule names are deterministic; a matching existing rule is left alone.
Keep required client/scorer/admin addresses out of the block list. Roll back new
rules using the printed change.json with 10-Restore-Change.ps1.
.EXAMPLE
.\11-Block-RemoteIPs.ps1 -RemoteAddress '192.0.2.10' -WhatIf
# The address above is documentation-only: replace with the actual Kali IP.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string[]]$RemoteAddress,
    [ValidateSet('All','SMB')][string]$Traffic='All',
    [ValidateSet('Inbound','Both')][string]$Direction='Inbound',
    [string[]]$ProtectedAddress=@(),
    [switch]$Apply,
    [string]$ExpectedComputerName='sunflower'
)
$ErrorActionPreference='Stop'
Import-Module "$PSScriptRoot\Lib\SmbDefense.Common.psm1" -Force
Assert-DefenseHost $ExpectedComputerName

function ConvertTo-BlockIP {
    param([string]$Address)
    $value=$Address.Trim()
    $ip=$null
    if ($value -match '[/%,*?\s]' -or
        ($value -notmatch ':' -and $value -notmatch '^\d{1,3}(\.\d{1,3}){3}$') -or
        -not [Net.IPAddress]::TryParse($value,[ref]$ip)) {
        throw "Use an exact IP address, not a subnet/range/hostname/placeholder: '$Address'."
    }
    if ($ip.IsIPv4MappedToIPv6) { $ip=$ip.MapToIPv4() }
    if ($value -notmatch ':' -and $value -cne $ip.ToString()) {
        throw "Use an exact IP without leading zeros or alternate numeric notation: '$Address'."
    }
    if ([Net.IPAddress]::IsLoopback($ip) -or $ip.Equals([Net.IPAddress]::Any) -or
        $ip.Equals([Net.IPAddress]::IPv6Any) -or $ip.IsIPv6Multicast -or
        ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork -and
            ($ip.GetAddressBytes()[0] -eq 0 -or $ip.GetAddressBytes()[0] -ge 224))) {
        throw "Loopback, unspecified, multicast or reserved broadcast-range IP refused: '$Address'."
    }
    return $ip.ToString()
}
function Get-BlockRuleName {
    param([string]$IP,[string]$Flow)
    $sha=[Security.Cryptography.SHA256]::Create()
    try {
        $bytes=[Text.Encoding]::UTF8.GetBytes("$IP|$Traffic|$Flow")
        $hash=([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').Substring(0,24)
        return "SFDefense-IPBlock-$hash"
    } finally { $sha.Dispose() }
}
function Assert-MatchingBlock {
    param($State,$Plan)
    $protocol=if ($Traffic -eq 'SMB') {'TCP'} else {'Any'}
    $localPort=if ($Traffic -eq 'SMB' -and $Plan.Flow -eq 'Inbound') {'445'} else {'Any'}
    $remotePort=if ($Traffic -eq 'SMB' -and $Plan.Flow -eq 'Outbound') {'445'} else {'Any'}
    $actualProtocol=switch ($State.Protocol) { '6' {'TCP'} '256' {'Any'} default {$State.Protocol} }
    if (-not $State.Exists -or $State.Group -ne 'SunflowerDefense.ManagedIPBlocks.v1' -or
        $State.Enabled -ne 'True' -or $State.Profile -ne 'Any' -or
        $State.Action -ne 'Block' -or $State.Direction -ne $Plan.Flow -or
        $actualProtocol -ne $protocol -or
        (@($State.LocalPort) -join ',') -ne $localPort -or
        (@($State.RemotePort) -join ',') -ne $remotePort -or
        (@($State.RemoteAddress) -join ',') -ne $Plan.IP -or
        (@($State.LocalAddress) -join ',') -ne 'Any') {
        throw "Rule '$($Plan.Name)' has unexpected settings. Inspect it; this script will not overwrite it."
    }
    foreach ($value in @($State.Program,$State.Package,$State.Service,$State.InterfaceType,
        $State.LocalUser,$State.RemoteUser,$State.RemoteMachine)+@($State.InterfaceAlias)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$value) -and [string]$value -ne 'Any') {
            throw "Rule '$($Plan.Name)' contains an extra application/interface/security restriction. Review manually."
        }
    }
    if ($State.Authentication -notin @('NotRequired','NotConfigured') -or
        $State.Encryption -notin @('NotRequired','NotConfigured')) {
        throw "Rule '$($Plan.Name)' contains an unexpected IPsec requirement."
    }
}

$ips=@($RemoteAddress | ForEach-Object {ConvertTo-BlockIP $_} | Sort-Object -Unique)
$protected=@($ProtectedAddress | ForEach-Object {ConvertTo-BlockIP $_})
# Never block the server's own addresses. Protect observed remote admin peers.
foreach ($address in @(Get-NetIPAddress -ErrorAction Stop | Select-Object -ExpandProperty IPAddress)) {
    try { $protected+=ConvertTo-BlockIP ($address -replace '%\d+$','') } catch { }
}
foreach ($connection in @(Get-NetTCPConnection -ErrorAction Stop |
    Where-Object { [string]$_.State -eq 'Established' -and $_.LocalPort -in @(22,3389,5985,5986) })) {
    try { $protected+=ConvertTo-BlockIP ($connection.RemoteAddress -replace '%\d+$','') } catch { }
}
foreach ($ip in $ips) {
    if ($ip -in $protected) { throw "Refusing protected/local/connected-management address '$ip'." }
}
$profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
$profiles | Select-Object Name,Enabled,AllowLocalFirewallRules | Format-Table -AutoSize
$services=@(Get-Service -Name MpsSvc,BFE -ErrorAction Stop)
$profileProblems=@($profiles | Where-Object {
    [string]$_.Enabled -ne 'True' -or [string]$_.AllowLocalFirewallRules -eq 'False'
})
if ($profiles.Count -lt 3 -or $profileProblems.Count -or @($services | Where-Object Status -ne 'Running').Count) {
    $message='Firewall services/profiles/local-rule merging are not ready. Review module 08 and the owning Group Policy before relying on local blocks.'
    if ($Apply -and -not $WhatIfPreference) { throw $message }
    Write-Warning $message
}
$flows=@('Inbound')
if ($Direction -eq 'Both') { $flows+= 'Outbound' }
$plan=@(foreach ($ip in $ips) { foreach ($flow in $flows) {
    [pscustomobject]@{Name=(Get-BlockRuleName $ip $flow); IP=$ip; Flow=$flow; Traffic=$Traffic}
} })
$plan | Format-Table -AutoSize
Write-Warning 'An explicit block normally overrides a conflicting allow. Do not include shared NAT, scorer, legitimate-client or management IPs.'
Write-Host 'These are host firewall rules only. They neither probe Kali nor change the router.'
# Read policy stores once for collision detection. No filter is silently overwritten.
$local=@(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop)
$active=@(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop)
$missing=@(foreach ($item in $plan) {
    $localMatch=@($local | Where-Object Name -eq $item.Name)
    $activeMatch=@($active | Where-Object Name -eq $item.Name)
    if (@($activeMatch | Where-Object { [string]$_.PolicyStoreSourceType -eq 'GroupPolicy' }).Count) {
        throw "Rule-name collision with Group Policy: $($item.Name)"
    }
    if ($localMatch.Count -eq 0) {
        if ($activeMatch.Count) { throw "Rule-name collision outside the local store: $($item.Name)" }
        $item
    } else {
        if ($localMatch.Count -ne 1) { throw "Ambiguous local rule: $($item.Name)" }
        $state=Get-DefenseState 'FirewallBlockCreate' @{RuleNames=@($item.Name)}
        Assert-MatchingBlock $state.Rules[0] $item
        Write-Host "Already configured: $($item.Name). No change."
    }
})
if (-not $missing.Count) { Write-Host 'No new rules needed. Verify traffic from the actual permitted test clients.'; return }
if (-not $Apply) { Write-Host 'Preview only. Add -Apply to create the displayed missing rules.'; return }
if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME,"Create $($missing.Count) IP block rule(s)")) {
    $target=@{RuleNames=@($missing | ForEach-Object Name); Traffic=$Traffic; Direction=$Direction; RemoteAddress=$ips}
    Invoke-DefenseChange 'FirewallBlockCreate' $target {
        param($record)
        if (@($record.Before.Rules | Where-Object Exists).Count) {
            throw 'A planned new rule appeared since preview. Stop and review the competing change.'
        }
        foreach ($item in $missing) {
            $ruleArgs=@{
                PolicyStore='PersistentStore'; Name=$item.Name
                DisplayName="Sunflower: block $($item.IP) $($item.Flow) $Traffic"
                Group='SunflowerDefense.ManagedIPBlocks.v1'
                Description='Created by 11-Block-RemoteIPs.ps1; use its saved change.json for removal.'
                Enabled='True'; Profile='Any'; Direction=$item.Flow; Action='Block'
                RemoteAddress=$item.IP; Protocol='Any'; ErrorAction='Stop'
            }
            if ($Traffic -eq 'SMB') {
                $ruleArgs.Protocol='TCP'
                if ($item.Flow -eq 'Inbound') { $ruleArgs.LocalPort='445' }
                else { $ruleArgs.RemotePort='445' }
            }
            New-NetFirewallRule @ruleArgs | Out-Null
            $state=Get-DefenseState 'FirewallBlockCreate' @{RuleNames=@($item.Name)}
            Assert-MatchingBlock $state.Rules[0] $item
            $effective=@(Get-NetFirewallRule -PolicyStore ActiveStore -Name $item.Name -ErrorAction Stop)
            if ($effective.Count -ne 1 -or [string]$effective[0].Enabled -ne 'True' -or
                [string]$effective[0].Action -ne 'Block' -or
                [string]$effective[0].PolicyStoreSourceType -eq 'GroupPolicy') {
                throw "The new local block was not verified in ActiveStore: $($item.Name)"
            }
        }
    }
}
Write-Host 'Verify fresh traffic from an excluded and an allowed client, then check scoring.'
Write-Host 'New connections may use different source IPs. An IP list does not identify an operating system.'

