#requires -Version 5.1
<#
.SYNOPSIS
Stage explicit SMB, ping, management and network-essential inbound allowances.
.DESCRIPTION
Preview by default. -Apply adds the planned local rules without disabling old
rules or changing profile defaults. Fill the config with verified sources first.
#>
[CmdletBinding(SupportsShouldProcess)]
param([string]$ConfigPath="$PSScriptRoot\config\firewall.json",[switch]$Apply)
$ErrorActionPreference='Stop'
Import-Module "$PSScriptRoot\Lib\SmbDefense.Common.psm1" -Force
Import-Module "$PSScriptRoot\Lib\RoleFirewall.Common.psm1" -Force
$config=Read-PvPFirewallConfig $ConfigPath
Assert-DefenseHost $config.ExpectedComputerName
$plan=@(Get-PvPFirewallPlan $config (Get-PvPNetworkFacts))
Assert-PvPPolicyReady $config $plan
$plan | ForEach-Object {
    [pscustomobject]@{Name=$_.Name;Protocol=$_.Spec.Protocol;LocalPort=$_.Spec.LocalPort -join ',';Source=$_.Spec.RemoteAddress -join ',';Reason=$_.Spec.Reason}
} | Format-Table -Wrap
$local=@(Get-NetFirewallRule -PolicyStore PersistentStore)
foreach ($entry in $plan) {
    $match=@($local | Where-Object Name -eq $entry.Name)
    if ($match.Count -gt 1) {throw "Ambiguous local rule: $($entry.Name)"}
    if ($match.Count) {Assert-PvPPlannedRule $match[0] $entry}
}
if (-not $Apply) {Write-Host 'Preview only. Add -Apply to stage these allowances.';return}
if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME,'Stage role firewall allowances')) {return}
$folder=New-PvPFirewallBackup 'stage'
$created=New-Object 'System.Collections.Generic.List[string]'
try {
    foreach ($entry in $plan) {
        if ($entry.Name -notin @($local | ForEach-Object Name)) {
            New-PvPPlannedRule $entry
            $created.Add($entry.Name)
        }
        $effective=@(Get-NetFirewallRule -PolicyStore ActiveStore -Name $entry.Name -ErrorAction Stop)
        if ($effective.Count -ne 1) {throw "Planned rule is not uniquely effective: $($entry.Name)"}
        Assert-PvPPlannedRule $effective[0] $entry
    }
} catch {
    # Remove only rules newly created in this failed staging attempt.
    foreach ($name in $created) {
        try {Remove-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction Stop}
        catch {Write-Warning "Inspect leftover staging rule '$name': $_"}
    }
    throw
}
$plan | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $folder 'staged-plan.json') -Encoding UTF8
Write-Host "Allowances staged. Backup: $folder"
Write-Host 'Now preview 03_firewall_lockdown.ps1. Existing inbound allowances still remain.'
