#requires -Version 5.1
<#
.SYNOPSIS
Restore the complete local firewall snapshot from immediately before lockdown.
.DESCRIPTION
Preview by default. This replaces concurrent local firewall edits, including
new blocks. It cannot remove domain Group Policy. Use the original state path.
#>
[CmdletBinding(SupportsShouldProcess)]
param([Parameter(Mandatory)][string]$StateFile,[switch]$Apply,[string]$ExpectedComputerName='sunflower')
$ErrorActionPreference='Stop'
Import-Module "$PSScriptRoot\Lib\SmbDefense.Common.psm1" -Force
Import-Module "$PSScriptRoot\Lib\RoleFirewall.Common.psm1" -Force
Assert-DefenseHost $ExpectedComputerName
$t=Get-PvPTransaction $StateFile
Write-Host "PLAN: restore pre-lockdown local firewall policy for $($t.State.ComputerName), captured $($t.State.CreatedUtc)."
Write-Host "Transaction status: $($t.State.Status). All later local firewall edits will be replaced."
if (-not $Apply) {Write-Host 'Preview only. Add -Apply to restore.';return}
if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME,'Restore complete pre-lockdown local firewall policy')) {
    & $t.Worker -StateFile $t.StateFile -Mode Restore
}
