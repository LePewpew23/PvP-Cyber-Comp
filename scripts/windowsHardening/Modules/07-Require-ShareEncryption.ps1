#requires -Version 5.1
<#
.SYNOPSIS
Require SMB3 encryption for one ordinary data share.
.DESCRIPTION
OPTIONAL: test the actual scorer/client before applying. RejectUnencryptedAccess
is server-wide and affects EVERY share that requires encryption, not just this
share. Signing protects integrity; encryption also protects traffic contents.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$ShareName,
    [switch]$Apply,
    [string]$ExpectedComputerName='sunflower'
)
$ErrorActionPreference='Stop'
Import-Module "$PSScriptRoot\..\Lib\SmbDefense.Common.psm1" -Force
Assert-DefenseHost $ExpectedComputerName
$share=Get-DefenseShare $ShareName
$target=@{ ShareName=$ShareName }
Get-DefenseState 'ShareEncryption' $target | ConvertTo-Json -Depth 6 | Write-Host
Write-Host "PLAN: EncryptData=True on $ShareName; RejectUnencryptedAccess=True server-wide."
Write-Warning 'Unsupported clients/scorers can lose access. Confirm SMB3 encryption support first.'
if (-not $Apply) { Write-Host 'Preview only. Add -Apply after compatibility testing.'; return }
if ($PSCmdlet.ShouldProcess($ShareName,'Require share encryption and reject unencrypted access')) {
    Invoke-DefenseChange 'ShareEncryption' $target {
        Set-SmbServerConfiguration -RejectUnencryptedAccess $true -Confirm:$false -ErrorAction Stop
        Set-SmbShare -Name $share.Name -ScopeName $share.ScopeName -EncryptData $true -Confirm:$false -ErrorAction Stop | Out-Null
        $after=Get-DefenseState 'ShareEncryption' $target
        if (-not $after.EncryptData -or -not $after.RejectUnencryptedAccess) { throw 'Encryption enforcement verification failed.' }
    }
}
