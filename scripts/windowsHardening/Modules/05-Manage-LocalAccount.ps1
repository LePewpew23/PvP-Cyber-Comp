#requires -Version 5.1
<#
.SYNOPSIS
One explicit local-account action: inspect, reset a password, disable an unknown
account, or remove unnecessary local Administrators membership.
.DESCRIPTION
Never mass-deletes users or changes domain accounts. Password reset has no
automatic undo: old passwords are not captured. Coordinate scored-user PCRs and
all services/tasks using the credential. Windows EFS/DPAPI-protected material can
be affected by an administrative password reset; review dependencies first.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$UserName,
    [ValidateSet('Inspect','ResetPassword','DisableUser','RemoveAdministrator')]
    [string]$Action='Inspect',
    [switch]$Apply,
    [string]$ExpectedComputerName='sunflower'
)
$ErrorActionPreference='Stop'
Import-Module "$PSScriptRoot\..\Lib\SmbDefense.Common.psm1" -Force
Assert-DefenseHost $ExpectedComputerName
if ([Management.Automation.WildcardPattern]::ContainsWildcardCharacters($UserName)) { throw 'Use one exact local username.' }
$u=Get-LocalUser -Name $UserName -ErrorAction Stop
$sid=$u.SID.Value
$target=@{ Sid=$sid; UserName=$u.Name }
$u | Select-Object Name,Enabled,SID,PasswordLastSet,PasswordExpires | Format-List
if ($Action -eq 'Inspect') { return }
$authorized=@('Administrator','jalapeno','coffeebean','pepperpult')
if ($Action -eq 'ResetPassword' -and $u.Name -notin $authorized) {
    throw 'Reset passwords only for the four packet-authorized users. Review/delete unauthorized users separately.'
}
$operatorSid=Get-DefenseOperatorSid
if ($Action -in @('DisableUser','RemoveAdministrator')) {
    if ($sid -eq $operatorSid -or $sid -match '-500$') {
        throw 'This module preserves the current operator and built-in Administrator.'
    }
}
if ($Action -eq 'DisableUser' -and
    ($u.Name -in $authorized -or $u.Name -in @('DefaultAccount','WDAGUtilityAccount') -or $u.Name.EndsWith('$'))) {
    throw 'Refusing to disable a packet-authorized or protected system/service identity.'
}
if ($Action -eq 'RemoveAdministrator') {
    $others=@(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop |
        Where-Object { $_.SID.Value -ne $sid } | ForEach-Object {
            # Require another enabled LOCAL administrator as a recovery route.
            try { Get-LocalUser -SID $_.SID -ErrorAction Stop | Where-Object Enabled } catch { }
        })
    if ($others.Count -eq 0) { throw 'No other enabled local administrator was verified. Establish recovery access first.' }
}
Write-Host "PLAN: $Action on LOCAL account $($u.Name) ($sid)."
if ($Action -eq 'ResetPassword') { Write-Warning 'Coordinate the actual reset with PCRs and consumers. The password is prompted securely only during Apply.' }
if (-not $Apply) { Write-Host 'Preview only. Add -Apply for this one account action.'; return }
if ($PSCmdlet.ShouldProcess($u.Name,$Action)) {
    switch ($Action) {
        'ResetPassword' {
            $newPassword=Read-Host 'New unique password' -AsSecureString
            if ($newPassword.Length -lt 16) { $newPassword.Dispose(); throw 'Use a unique password of at least 16 characters.' }
            try {
                Invoke-DefenseChange 'LocalPassword' $target {
                    Set-LocalUser -SID $u.SID -Password $newPassword -ErrorAction Stop
                }
            } finally { $newPassword.Dispose(); Remove-Variable newPassword }
        }
        'DisableUser' {
            Invoke-DefenseChange 'LocalEnabled' $target {
                Disable-LocalUser -SID $u.SID -ErrorAction Stop
            }
            Write-Warning 'Disabling an account does not close existing SMB/RDP sessions or remove tasks. Review and contain those separately.'
        }
        'RemoveAdministrator' {
            Invoke-DefenseChange 'LocalAdmin' $target {
                Remove-LocalGroupMember -SID 'S-1-5-32-544' -Member $u -Confirm:$false -ErrorAction Stop
            }
            Write-Warning 'Existing logon tokens can retain privileges. Review sessions and re-test with a fresh login.'
        }
    }
}
