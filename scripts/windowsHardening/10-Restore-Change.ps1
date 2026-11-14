#requires -Version 5.1
<#
.SYNOPSIS
Restore one supported configuration change from this toolkit's change.json.
.DESCRIPTION
Preview by default. Refuses a different machine and refuses state drift instead
of overwriting a teammate's later change. Undo changes in reverse order.
Passwords cannot be recovered. SMB1 optional-feature servicing needs the manual
recovery procedure in README; this script does not automatically re-enable SMB1.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$StateFile,
    [switch]$Apply,
    [string]$ExpectedComputerName='sunflower'
)
$ErrorActionPreference='Stop'
Import-Module "$PSScriptRoot\Lib\SmbDefense.Common.psm1" -Force
Assert-DefenseHost $ExpectedComputerName

$file=Get-Item -LiteralPath $StateFile -Force -ErrorAction Stop
if ($file.PSIsContainer -or $file.Length -gt 2097152) { throw 'Select a small, trusted change.json file.' }
$root=[IO.Path]::GetFullPath((Join-Path $env:ProgramData 'SunflowerDefense'))+[IO.Path]::DirectorySeparatorChar
if (-not $file.FullName.StartsWith($root,[StringComparison]::OrdinalIgnoreCase)) { throw 'Use an original backup under ProgramData\SunflowerDefense on this server.' }
$check=$file
while ($check -and $check.FullName.StartsWith($root.TrimEnd('\'),[StringComparison]::OrdinalIgnoreCase)) {
    if ($check.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse-point backup paths are not accepted.' }
    $check=if ($check.PSIsContainer) { $check.Parent } else { $check.Directory }
}
$record=Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
$machine=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid
if ($record.SchemaVersion -ne 1 -or $record.ComputerName -ine $env:COMPUTERNAME -or $record.MachineGuid -ne $machine) {
    throw 'Backup format or machine identity does not match.'
}
if ($record.Kind -eq 'LocalPassword') { throw 'Password resets cannot be undone from a backup. Set another secure password and update PCRs/consumers.' }
if ($record.Kind -eq 'LocalUserDeletion') { throw 'Deleted users cannot be restored with their original SID/password. This record is an audit record, not a recoverable account backup.' }
if ($record.Kind -eq 'Smb1') {
    $record.Before | ConvertTo-Json -Depth 8 | Write-Host
    throw 'SMB1 feature servicing requires planned manual recovery; see README. The original feature and registry states are shown above.'
}
if ($null -eq $record.After) { throw 'The final state was not captured. Review the failed change manually; do not blindly restore.' }
$current=Get-DefenseState $record.Kind $record.Target
if (Test-DefenseStateEqual $current $record.Before) { Write-Host 'The covered settings already match the original state.'; return }
if (-not (Test-DefenseStateEqual $current $record.After)) {
    throw 'State drift detected: covered settings changed since this backup. Restore a newer change first or reconcile manually.'
}
Write-Host "PLAN: restore $($record.Kind) created $($record.CreatedUtc)."
$record.Before | ConvertTo-Json -Depth 10 | Write-Host
Write-Warning 'Restoring an earlier state can relax a security control. Restore only the change causing the problem.'
if (-not $Apply) { Write-Host 'Preview only. Add -Apply to restore these settings.'; return }
if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME,"Restore $($record.Kind) from $($file.FullName)")) {
    $t=$record.Target
    $b=$record.Before
    try {
        switch ($record.Kind) {
            'FirewallBlockCreate' {
                # Only newly created rules belong to this record. Their full
                # captured filters were compared above before removing them.
                foreach ($rule in @($b.Rules)) {
                    if ($rule.Exists) { throw 'This record contains a pre-existing rule; manual review is required.' }
                }
                foreach ($name in @($t.RuleNames)) {
                    Remove-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction Stop
                }
            }
            'Signing' {
                Set-SmbServerConfiguration -RequireSecuritySignature ([bool]$b.RequireSecuritySignature) -Confirm:$false -ErrorAction Stop
            }
            'ShareAllow' {
                $share=Get-DefenseShare $t.ShareName
                foreach ($name in @($current.Entries | ForEach-Object { $_.AccountName } | Sort-Object -Unique)) {
                    Revoke-SmbShareAccess -Name $share.Name -ScopeName $share.ScopeName -AccountName $name -Force -ErrorAction Stop | Out-Null
                }
                foreach ($entry in @($b.Entries)) {
                    Grant-SmbShareAccess -Name $share.Name -ScopeName $share.ScopeName -AccountName $entry.AccountName -AccessRight $entry.AccessRight -Force -ErrorAction Stop | Out-Null
                }
            }
            'FirewallScope' {
                foreach ($rule in @($b.Rules)) {
                    Set-NetFirewallRule -PolicyStore PersistentStore -Name $rule.Name -RemoteAddress @($rule.RemoteAddress) -ErrorAction Stop | Out-Null
                }
            }
            'LocalEnabled' {
                if ($b.Enabled) { Enable-LocalUser -SID $t.Sid -ErrorAction Stop }
                else { Disable-LocalUser -SID $t.Sid -ErrorAction Stop }
            }
            'LocalAdmin' {
                if ($b.IsMember) {
                    $user=Get-LocalUser -SID $t.Sid -ErrorAction Stop
                    Add-LocalGroupMember -SID 'S-1-5-32-544' -Member $user -ErrorAction Stop
                } else { throw 'This record does not represent an administrator-membership removal.' }
            }
            'Auditing' {
                # System/per-user policy and audit options were compared with
                # the recorded after-state; later changes prevent this full restore.
                $csv=Join-Path $file.DirectoryName 'audit-before.csv'
                if (-not (Test-Path -LiteralPath $csv -PathType Leaf)) { throw 'The official auditpol CSV backup is missing.' }
                $csvItem=Get-Item -LiteralPath $csv -Force
                if ($csvItem.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Redirected audit backups are not accepted.' }
                if ((Get-FileHash -LiteralPath $csv -Algorithm SHA256).Hash -ne $t.AuditBackupSHA256) { throw 'The audit backup CSV has changed since capture.' }
                Invoke-DefenseAuditpol @('/restore',"/file:$csv")
                Restore-DefenseRegistryValue $b.ForceSubcategories
                Set-SmbServerConfiguration -AuditSmb1Access ([bool]$b.AuditSmb1Access) -Confirm:$false -ErrorAction Stop
            }
            'ShareEncryption' {
                $share=Get-DefenseShare $t.ShareName
                Set-SmbShare -Name $share.Name -ScopeName $share.ScopeName -EncryptData ([bool]$b.EncryptData) -Confirm:$false -ErrorAction Stop | Out-Null
                Set-SmbServerConfiguration -RejectUnencryptedAccess ([bool]$b.RejectUnencryptedAccess) -Confirm:$false -ErrorAction Stop
            }
            'Defender' {
                Set-MpPreference -DisableRealtimeMonitoring ([bool]$b.DisableRealtimeMonitoring) -ErrorAction Stop
            }
            'RdpNla' {
                $setting=Get-CimInstance -Namespace root/cimv2/TerminalServices -ClassName Win32_TSGeneralSetting -Filter "TerminalName='RDP-tcp'" -ErrorAction Stop
                $nlaArgs=@{
                    InputObject=$setting; MethodName='SetUserAuthenticationRequired'
                    Arguments=@{UserAuthenticationRequired=[uint32]$b.UserAuthenticationRequired}; ErrorAction='Stop'
                }
                $result=Invoke-CimMethod @nlaArgs
                if ($result.ReturnValue -ne 0) { throw "NLA restore failed: $($result.ReturnValue)" }
            }
            'FirewallProfiles' {
                foreach ($p in @($b.Profiles)) {
                    Set-NetFirewallProfile -PolicyStore PersistentStore -Name $p.Name -Enabled $p.Enabled -DefaultInboundAction $p.DefaultInboundAction -ErrorAction Stop
                }
            }
            default { throw "Unsupported restore kind '$($record.Kind)'." }
        }
        $restored=Get-DefenseState $record.Kind $record.Target
        if (-not (Test-DefenseStateEqual $restored $record.Before)) { throw 'Restored settings do not match the backup. Inspect the host and owning policy.' }
        $record.Status='Restored'
        $record.Error=$null
        $record | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath $file.FullName -Encoding UTF8 -ErrorAction Stop
        Write-Host 'Covered settings restored. Test a NEW SMB login/file operation and check scoring.'
    } catch {
        # Preserve Before and After. Record the failure without pretending recovery
        # succeeded; partial restores require inspection.
        $record.Status='RestoreFailed'
        $record.Error=$_.Exception.Message
        $record | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath $file.FullName -Encoding UTF8 -ErrorAction Stop
        throw
    }
}
