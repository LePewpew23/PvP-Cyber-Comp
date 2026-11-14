#requires -Version 5.1
<#
.SYNOPSIS
Require message integrity on incoming SMB sessions.
.DESCRIPTION
Test the scored client's signing support first. This does not encrypt file data,
change outbound SMB client settings, change permissions, or reset passwords.
#>
[CmdletBinding(SupportsShouldProcess)]
param([switch]$Apply,[string]$ExpectedComputerName='sunflower')
$ErrorActionPreference='Stop'
Import-Module "$PSScriptRoot\..\Lib\SmbDefense.Common.psm1" -Force
Assert-DefenseHost $ExpectedComputerName
$before=Get-DefenseState 'Signing' @{}
Write-Host "RequireSecuritySignature currently: $($before.RequireSecuritySignature)"
if ($before.RequireSecuritySignature) { Write-Host 'Already required; nothing to change.'; return }
Write-Host 'PLAN: require inbound SMB signing. Unsupported/guest clients may stop working.'
if (-not $Apply) { Write-Host 'Preview only. Add -Apply after a compatibility check.'; return }
if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME,'Require inbound SMB signing')) {
    Invoke-DefenseChange 'Signing' @{} {
        Set-SmbServerConfiguration -RequireSecuritySignature $true -Confirm:$false -ErrorAction Stop
        if (-not (Get-SmbServerConfiguration).RequireSecuritySignature) {
            throw 'Signing requirement did not take effect. Check Group Policy.'
        }
    }
}
