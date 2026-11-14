#requires -Version 5.1
<#
.SYNOPSIS
Inspect or change ONE principal's Allow entries on ONE ordinary SMB share.
.DESCRIPTION
This changes share permissions only. It does not change NTFS ACLs, owner,
inheritance, deny entries, other principals, or any file/flag contents.
Use qualified identities, e.g. sunflower\jalapeno or the verified DOMAIN\user.
.EXAMPLE
.\03-Set-ShareAccess.ps1 -ShareName ActualShare
.EXAMPLE
.\03-Set-ShareAccess.ps1 -ShareName ActualShare -Action SetAllow -Principal 'sunflower\jalapeno' -AccessRight Read
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$ShareName,
    [ValidateSet('Inspect','SetAllow','RemoveAllow')][string]$Action='Inspect',
    [string]$Principal,
    [ValidateSet('Read','Change','Full')][string]$AccessRight='Read',
    [switch]$Apply,
    [string]$ExpectedComputerName='sunflower'
)
$ErrorActionPreference='Stop'
Import-Module "$PSScriptRoot\..\Lib\SmbDefense.Common.psm1" -Force
Assert-DefenseHost $ExpectedComputerName
$share=Get-DefenseShare $ShareName
Get-SmbShareAccess -Name $share.Name -ScopeName $share.ScopeName | Format-Table -AutoSize
if ($Action -eq 'Inspect') { return }
if ([string]::IsNullOrWhiteSpace($Principal)) { throw '-Principal is required for changes.' }
$sid=Resolve-DefenseSid $Principal
$currentSid=Get-DefenseOperatorSid
if ($sid -in @('S-1-5-18','S-1-5-32-544',$currentSid) -or $sid -match '-500$') {
    throw 'This module preserves SYSTEM, Administrators, built-in Administrator, and the current operator.'
}
$target=@{ ShareName=$ShareName; Sid=$sid; Principal=$Principal }
Write-Host "PLAN: $Action for $Principal ($sid) on $ShareName; requested right: $AccessRight."
Write-Host 'SetAllow replaces this principal''s existing Allow entries; other principals and all Deny entries remain.'
Write-Host 'Ensure the scored identity keeps its required read/write operation, then check effective NTFS access.'
if (-not $Apply) { Write-Host 'Preview only. Add -Apply for this specific ACL change.'; return }
if ($PSCmdlet.ShouldProcess("$ShareName / $Principal",$Action)) {
    Invoke-DefenseChange 'ShareAllow' $target {
        param($record)
        # Revoke only the selected principal's allow ACEs, never the whole ACL.
        foreach ($name in @($record.Before.Entries | ForEach-Object { $_.AccountName } | Sort-Object -Unique)) {
            Revoke-SmbShareAccess -Name $share.Name -ScopeName $share.ScopeName `
                -AccountName $name -Force -ErrorAction Stop | Out-Null
        }
        if ($Action -eq 'SetAllow') {
            Grant-SmbShareAccess -Name $share.Name -ScopeName $share.ScopeName `
                -AccountName $Principal -AccessRight $AccessRight -Force -ErrorAction Stop | Out-Null
        }
        $after=Get-DefenseState 'ShareAllow' $target
        if ($Action -eq 'SetAllow' -and
            (@($after.Entries).Count -ne 1 -or $after.Entries[0].AccessRight -ne $AccessRight)) {
            throw 'Share permission verification failed; use the saved change record.'
        }
        if ($Action -eq 'RemoveAllow' -and @($after.Entries).Count -ne 0) {
            throw 'An allow entry remains for the selected principal.'
        }
    }
}
