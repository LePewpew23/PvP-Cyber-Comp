#requires -Version 5.1
<#
.SYNOPSIS
Reset passwords only for sunflower's four packet-authorized LOCAL human users.
.DESCRIPTION
Default target list: Administrator, jalapeno, coffeebean, pepperpult.
Preview by default. -Apply prompts twice using hidden input.
-SamePasswordForAll uses one supplied password for every selected authorized
account. The actual password is never embedded, printed or saved by this script.
Use -MinimumLength 13 for the user's requested 13-character password; Windows'
own password policy still applies and is not weakened by this option.
This is an administrator reset. Old passwords cannot be recovered. Coordinate
scored-user PCRs and consumers; resets can affect EFS/DPAPI-protected material.
.EXAMPLE
.\12-Change-LocalPasswords.ps1 -SamePasswordForAll -MinimumLength 13
.EXAMPLE
.\12-Change-LocalPasswords.ps1 -SamePasswordForAll -MinimumLength 13 -Apply
# Enter the user-selected password at both masked prompts.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateNotNullOrEmpty()][string[]]$UserName=@('Administrator','jalapeno','coffeebean','pepperpult'),
    [ValidateRange(12,128)][int]$MinimumLength=16,
    [switch]$SamePasswordForAll,
    [switch]$Apply,
    [string]$ExpectedComputerName='sunflower'
)
$ErrorActionPreference='Stop'
Import-Module "$PSScriptRoot\Lib\SmbDefense.Common.psm1" -Force
Assert-DefenseHost $ExpectedComputerName
$authorized=@('Administrator','jalapeno','coffeebean','pepperpult')

function Test-PasswordMatch {
    # No managed plaintext strings. BSTR memory is zeroed/freed in finally.
    param([Security.SecureString]$First,[Security.SecureString]$Second)
    if ($First.Length -ne $Second.Length) { return $false }
    $a=[IntPtr]::Zero; $b=[IntPtr]::Zero
    try {
        $a=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($First)
        $b=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($Second)
        $difference=0
        for ($i=0;$i -lt $First.Length;$i++) {
            $difference=$difference -bor (
                [Runtime.InteropServices.Marshal]::ReadInt16($a,2*$i) -bxor
                [Runtime.InteropServices.Marshal]::ReadInt16($b,2*$i))
        }
        return $difference -eq 0
    } finally {
        if ($a -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($a) }
        if ($b -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
    }
}
function Read-ConfirmedPassword {
    param([string]$Label)
    $first=$null; $second=$null; $accepted=$false
    try {
        $first=Read-Host "New password for $Label" -AsSecureString
        if ($first.Length -lt $MinimumLength) { throw "Use at least $MinimumLength characters. No reset was attempted for $Label." }
        $second=Read-Host "Repeat the new password for $Label" -AsSecureString
        if (-not (Test-PasswordMatch $first $second)) { throw "Passwords do not match. No reset was attempted for $Label." }
        $accepted=$true
        return $first
    } finally {
        if ($second) { $second.Dispose() }
        if ($first -and -not $accepted) { $first.Dispose() }
    }
}
# Resolve the complete list before any reset. Reject names outside the briefing
# even if the caller explicitly includes them; deletion/review is a separate step.
$users=@(foreach ($name in @($UserName | Select-Object -Unique)) {
    if ($name -notin $authorized) { throw "Password reset refused: '$name' is not one of the four packet-authorized users." }
    $u=Get-LocalUser -Name $name -ErrorAction Stop
    if ([string]$u.PrincipalSource -ne 'Local') { throw "Account '$name' is not verified as a Local principal. Domain/cloud resets are outside this module." }
    $u
})
$users | Select-Object Name,Enabled,SID,PasswordLastSet | Format-Table -AutoSize
Write-Host "PLAN: reset ONLY these $($users.Count) authorized local password(s)."
if ($SamePasswordForAll) { Write-Host 'One masked password/confirmation pair will be used for the selected accounts.' }
else { Write-Host 'Each selected account will have its own masked password/confirmation pair.' }
Write-Warning 'Coordinate scored accounts with PCRs and consumers. This cannot recover the old password or undo a reset.'
if (-not $Apply) { Write-Host 'Preview only. Add -Apply to perform the listed resets.'; return }
$changed=@()
if ($SamePasswordForAll) {
    if ($PSCmdlet.ShouldProcess(($users.Name -join ', '),'Reset authorized users with one supplied password')) {
        $sharedPassword=$null
        try {
            $sharedPassword=Read-ConfirmedPassword 'the listed authorized users'
            foreach ($u in $users) {
                $target=@{Sid=$u.SID.Value;UserName=$u.Name}
                Invoke-DefenseChange 'LocalPassword' $target {
                    param($record)
                    Set-LocalUser -SID $record.Target.Sid -Password $sharedPassword -ErrorAction Stop
                }
                $changed+=$u.Name
                Write-Host "PASSWORD UPDATED: $($u.Name)"
            }
        } finally {
            if ($sharedPassword) { $sharedPassword.Dispose() }
            Remove-Variable sharedPassword -ErrorAction SilentlyContinue
            Write-Host "Completed password updates in this run: $($changed -join ', ')"
        }
    }
} else {
    foreach ($u in $users) {
        if ($PSCmdlet.ShouldProcess("$($u.Name) ($($u.SID.Value))",'Reset authorized local password')) {
            $newPassword=$null
            try {
                $newPassword=Read-ConfirmedPassword $u.Name
                $target=@{Sid=$u.SID.Value;UserName=$u.Name}
                Invoke-DefenseChange 'LocalPassword' $target {
                    param($record)
                    Set-LocalUser -SID $record.Target.Sid -Password $newPassword -ErrorAction Stop
                }
                $changed+=$u.Name
                Write-Host "PASSWORD UPDATED: $($u.Name)"
            } finally {
                if ($newPassword) { $newPassword.Dispose() }
                Remove-Variable newPassword -ErrorAction SilentlyContinue
            }
        }
    }
}
Write-Host 'Test fresh logins and scoring/PCR status. Earlier completed resets are not undone if a later reset fails.'

