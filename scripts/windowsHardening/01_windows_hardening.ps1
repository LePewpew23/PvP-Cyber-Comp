#requires -Version 5.1
<#
.SYNOPSIS
Review Windows settings or apply one selected host protection.
.DESCRIPTION
Keep service dependencies, scheduled tasks and competition flags intact.
Use 02/03 for the staged role firewall. Passwords remain in the original 12 script.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('Inspect','Defender','RdpNla','Auditing')][string]$Control='Inspect',
    [switch]$Apply,[string]$ExpectedComputerName='sunflower'
)
$ErrorActionPreference='Stop'
Import-Module "$PSScriptRoot\Lib\SmbDefense.Common.psm1" -Force
Assert-DefenseHost $ExpectedComputerName
if ($Control -eq 'Inspect') {
    & "$PSScriptRoot\Modules\00-Inspect-Sunflower.ps1" -ExpectedComputerName $ExpectedComputerName
    Get-CimInstance Win32_Service | Where-Object State -eq 'Running' |
        Select-Object Name,StartName,StartMode,PathName | Format-Table -Wrap
    Get-ScheduledTask | Select-Object TaskPath,TaskName,State | Format-Table -AutoSize
    Write-Host 'Review unexpected startup paths/tasks with your team; this script does not delete them.'
    return
}
$argsForModule=@{Apply=$Apply;ExpectedComputerName=$ExpectedComputerName;WhatIf=[bool]$WhatIfPreference}
if ($Control -eq 'Auditing') {& "$PSScriptRoot\Modules\06-Enable-Auditing.ps1" @argsForModule}
else {& "$PSScriptRoot\Modules\08-Set-HostProtection.ps1" -Control $Control @argsForModule}
