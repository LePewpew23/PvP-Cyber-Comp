#requires -Version 5.1
<#
.SYNOPSIS
Scope selected EXISTING local inbound TCP 445 allow rules to verified client IPs/CIDRs.
.DESCRIPTION
Use Name from inventory, not localized DisplayName. Include every intended client
network and the actual scorer/NAT sources, subject to event rules. No guessed IPs.
This does not enable a disabled firewall, create rules, or edit RDP/WinRM/AD rules.
Unselected broad allow rules can still permit traffic; inspect them separately.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string[]]$RuleName,
    [Parameter(Mandatory)][string[]]$RemoteAddress,
    [switch]$Apply,
    [string]$ExpectedComputerName='sunflower'
)
$ErrorActionPreference='Stop'
Import-Module "$PSScriptRoot\..\Lib\SmbDefense.Common.psm1" -Force
Assert-DefenseHost $ExpectedComputerName

# Require real IPv4/IPv6 addresses or CIDRs, not placeholder words or "Any".
foreach ($address in $RemoteAddress) {
    $parts=$address.Split('/')
    $ip=$null
    if ($parts.Count -gt 2 -or -not [Net.IPAddress]::TryParse($parts[0],[ref]$ip)) {
        throw "Invalid IP/CIDR '$address'. Replace example values with verified sources."
    }
    if ($parts.Count -eq 2) {
        $prefix=0
        $max=if ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {32} else {128}
        if (-not [int]::TryParse($parts[1],[ref]$prefix) -or $prefix -lt 1 -or $prefix -gt $max) {
            throw "Invalid or unrestricted CIDR '$address'."
        }
    }
}
$names=@($RuleName | Sort-Object -Unique)
foreach ($name in $names) {
    if ([Management.Automation.WildcardPattern]::ContainsWildcardCharacters($name)) { throw 'Wildcard rule names are not accepted.' }
    $rules=@(Get-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction Stop)
    if ($rules.Count -ne 1) { throw "Rule '$name' is ambiguous." }
    $r=$rules[0]
    $p=$r | Get-NetFirewallPortFilter -ErrorAction Stop
    if ([string]$r.Direction -ne 'Inbound' -or [string]$r.Action -ne 'Allow' -or
        [string]$p.Protocol -notin @('TCP','6') -or
        @($p.LocalPort).Count -ne 1 -or [string](@($p.LocalPort)[0]) -ne '445') {
        throw "Rule '$name' is not an exact inbound TCP 445 allow rule."
    }
    $effective=@(Get-NetFirewallRule -PolicyStore ActiveStore -Name $name -ErrorAction Stop)
    if (@($effective | Where-Object { [string]$_.PolicyStoreSourceType -eq 'GroupPolicy' }).Count) {
        throw "Rule '$name' is controlled by Group Policy. Change its owning policy with the team."
    }
    $r | Select-Object Name,DisplayName,Enabled,Profile | Format-Table -AutoSize
}
$target=@{ RuleNames=$names }
Get-DefenseState 'FirewallScope' $target | ConvertTo-Json -Depth 6 | Write-Host
Write-Host "PLAN: replace selected rules' RemoteAddress with: $($RemoteAddress -join ', ')"
Write-Warning 'A narrow allow does not override an unrelated broad allow. No blanket block rule will be added.'
if (-not $Apply) { Write-Host 'Preview only. Add -Apply after client/source verification.'; return }
if ($PSCmdlet.ShouldProcess(($names -join ', '),'Scope SMB rule source addresses')) {
    Invoke-DefenseChange 'FirewallScope' $target {
        foreach ($name in $names) {
            Set-NetFirewallRule -PolicyStore PersistentStore -Name $name `
                -RemoteAddress $RemoteAddress -ErrorAction Stop | Out-Null
        }
    }
}
Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name,Enabled,DefaultInboundAction
Write-Host 'Check unselected Any/port-range/GPO rules and IPv6; then test intended and excluded clients.'
