#requires -Version 5.1
<#
.SYNOPSIS
Preserves your ORIGINAL two SMB1 commands, with preview and configuration backup.
.DESCRIPTION
No automatic reboot. A reboot may still be needed; inspect RestartNeeded/pending
feature state. SMB2/3 are not disabled. Test legacy-client/scorer compatibility.
.EXAMPLE
.\01-Disable-SMB1-Original.ps1
.EXAMPLE
.\01-Disable-SMB1-Original.ps1 -Apply
#>
[CmdletBinding(SupportsShouldProcess)]
param([switch]$Apply,[string]$ExpectedComputerName='sunflower')
$ErrorActionPreference='Stop'
Import-Module "$PSScriptRoot\..\Lib\SmbDefense.Common.psm1" -Force
Assert-DefenseHost $ExpectedComputerName
$state=Get-DefenseState 'Smb1' @{}
$state | ConvertTo-Json -Depth 6 | Write-Host
if (@($state.Features | Where-Object { $_.State -match 'Pending|Partially' }).Count) {
    throw 'SMB1 servicing is already pending/incomplete. Review the existing operation and reboot plan first.'
}
if (-not (Get-SmbServerConfiguration).EnableSMB2Protocol) {
    throw 'SMB2/3 are disabled. Investigate that condition before this change.'
}
Write-Host 'PLAN: run your original feature command, then your original SMB1 registry command.'
Write-Host '-NoRestart defers reboot; it does not guarantee the feature change is complete.'
if (-not $Apply) { Write-Host 'Preview only. Add -Apply to run this module.'; return }
if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME,'Disable SMB1 with the original two commands')) {
    Invoke-DefenseChange 'Smb1' @{} {
        # Original command 1: disable the optional feature without automatic reboot.
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
        # Original command 2: set the SMB server registry switch to disabled (0).
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 0 -Force
    }
    Write-Warning 'Inspect feature state/RestartNeeded and schedule any required reboot with your team. This script does not restart the host or Server service.'
}
