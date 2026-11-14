#requires -Version 5.1
<#
.SYNOPSIS
Inspect SMB or select one existing, commented hardening module.
.DESCRIPTION
SMB2/3, shares, NTFS ACLs and flag contents are preserved unless a specific
supported change is selected. No reboot or automatic all-controls mode.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('Inspect','SMB1','Signing','SharePermissions','Encryption')][string]$Control='Inspect',
    [string]$ShareName,
    [ValidateSet('Inspect','SetAllow','RemoveAllow')][string]$Action='Inspect',
    [string]$Principal,[ValidateSet('Read','Change','Full')][string]$AccessRight='Read',
    [switch]$Apply,[string]$ExpectedComputerName='sunflower'
)
$ErrorActionPreference='Stop'
Import-Module "$PSScriptRoot\Lib\SmbDefense.Common.psm1" -Force
Assert-DefenseHost $ExpectedComputerName
if ($Control -eq 'Inspect') {
    Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol,EnableSMB2Protocol,RequireSecuritySignature,EncryptData,RejectUnencryptedAccess,AuditSmb1Access | Format-List
    Get-SmbShare | Select-Object Name,Path,Special,EncryptData | Format-Table -AutoSize
    Get-SmbSession | Select-Object ClientComputerName,ClientUserName,Dialect,NumOpens | Format-Table -AutoSize
    return
}
$a=@{Apply=$Apply;ExpectedComputerName=$ExpectedComputerName;WhatIf=[bool]$WhatIfPreference}
switch ($Control) {
    'SMB1' {& "$PSScriptRoot\Modules\01-Disable-SMB1-Original.ps1" @a}
    'Signing' {& "$PSScriptRoot\Modules\02-Require-SmbSigning.ps1" @a}
    'SharePermissions' {
        if ([string]::IsNullOrWhiteSpace($ShareName)) {throw 'Specify the actual ordinary data share with -ShareName.'}
        & "$PSScriptRoot\Modules\03-Set-ShareAccess.ps1" -ShareName $ShareName -Action $Action -Principal $Principal -AccessRight $AccessRight @a
    }
    'Encryption' {
        if ([string]::IsNullOrWhiteSpace($ShareName)) {throw 'Specify the actual ordinary data share with -ShareName.'}
        & "$PSScriptRoot\Modules\07-Require-ShareEncryption.ps1" -ShareName $ShareName @a
    }
}
