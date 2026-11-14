#requires -Version 5.1
<#
.SYNOPSIS
Enable focused authentication/account/share auditing and SMB1-use auditing.
.DESCRIPTION
GUIDs avoid localized subcategory names. Saves auditpol's official CSV before
changes. Does not clear logs, add file SACLs, log command lines, or resize logs.
Advanced subcategory policy is made authoritative over legacy category policy.
Domain Group Policy may override local settings; verify effective policy.
#>
[CmdletBinding(SupportsShouldProcess)]
param([switch]$Apply,[string]$ExpectedComputerName='sunflower')
$ErrorActionPreference='Stop'
Import-Module "$PSScriptRoot\..\Lib\SmbDefense.Common.psm1" -Force
Assert-DefenseHost $ExpectedComputerName
$categories=[ordered]@{
    'Logon'='{0CCE9215-69AE-11D9-BED3-505054503030}'
    'User Account Management'='{0CCE9235-69AE-11D9-BED3-505054503030}'
    'Security Group Management'='{0CCE9237-69AE-11D9-BED3-505054503030}'
    'File Share'='{0CCE9224-69AE-11D9-BED3-505054503030}'
    'Audit Policy Change'='{0CCE922F-69AE-11D9-BED3-505054503030}'
}
foreach ($entry in $categories.GetEnumerator()) {
    Write-Host "PLAN: success/failure auditing for $($entry.Key) ($($entry.Value))"
    Invoke-DefenseAuditpol @('/get',"/subcategory:$($entry.Value)")
}
Write-Host 'PLAN: enable advanced-subcategory precedence and AuditSmb1Access.'
if (-not $Apply) { Write-Host 'Preview only. Add -Apply to configure these audit settings.'; return }
if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME,'Enable focused audit categories')) {
    Invoke-DefenseChange 'Auditing' @{} {
        param($record)
        $backup=Join-Path $record.Directory 'audit-before.csv'
        # If this backup fails, stop before changing any audit setting.
        Invoke-DefenseAuditpol @('/backup',"/file:$backup")
        $record.Target['AuditBackupSHA256']=(Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash
        $registryArgs=@{
            Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
            Name='SCENoApplyLegacyAuditPolicy'; PropertyType='DWord'
            Value=1; Force=$true; ErrorAction='Stop'
        }
        New-ItemProperty @registryArgs | Out-Null
        foreach ($entry in $categories.GetEnumerator()) {
            Invoke-DefenseAuditpol @('/set',"/subcategory:$($entry.Value)",'/success:enable','/failure:enable')
        }
        Set-SmbServerConfiguration -AuditSmb1Access $true -Confirm:$false -ErrorAction Stop
    }
}
Write-Host 'Watch 4624/4625, 4720, 4732, 4719, 5140 and SMBServer/Audit event 3000.'
Write-Host '5145 detailed-share events and 4663 file events require additional auditing/SACL configuration.'
Write-Host 'Review event volume and disk usage; no events is not proof of no attacks.'
