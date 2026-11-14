#requires -Version 5.1
<#
.SYNOPSIS
Preview/delete unapproved LOCAL users while preserving an explicit allowlist.
.DESCRIPTION
Default allowlist follows the sunflower packet. Extra protections always retain
packet-authorized names, built-in local-account RIDs, the current operator,
non-local/system identities, and detected Windows-service/scheduled-task users.
These protections do not prove an account is legitimate: investigate protected
unknown service/task users and migrate dependencies before manual removal.
-Apply deletes the previewed unprotected candidates by SID, one at a time. It
does not delete profiles, data, home folders, tasks, shares, or flags. No domain
accounts are modified. Deleted SID/password identities cannot be recreated by
this toolkit. Configuration records are evidence, not recoverable user backups.
.EXAMPLE
.\13-Remove-UnapprovedLocalUsers.ps1
.EXAMPLE
.\13-Remove-UnapprovedLocalUsers.ps1 -AllowedUsers 'Administrator','jalapeno','coffeebean','pepperpult','RequiredAppUser'
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateNotNullOrEmpty()][string[]]$AllowedUsers=@('Administrator','jalapeno','coffeebean','pepperpult'),
    [switch]$Apply,
    [string]$ExpectedComputerName='sunflower'
)
$ErrorActionPreference='Stop'
Import-Module "$PSScriptRoot\Lib\SmbDefense.Common.psm1" -Force
Assert-DefenseHost $ExpectedComputerName
$packetUsers=@('Administrator','jalapeno','coffeebean','pepperpult')
$operatorSid=Get-DefenseOperatorSid
foreach ($name in $AllowedUsers) {
    if ([string]::IsNullOrWhiteSpace($name) -or $name -match '[\\/@]' -or
        [Management.Automation.WildcardPattern]::ContainsWildcardCharacters($name)) {
        throw "Allowlist requires literal local usernames, not wildcards/domain names: '$name'."
    }
}
function Get-RemovalReview {
    $localUsers=@(Get-LocalUser -ErrorAction Stop)
    # Missing allowlist names can indicate typos or domain accounts; fail before
    # deletion rather than assume the intended identity has been protected.
    foreach ($name in $AllowedUsers) {
        if (-not @($localUsers | Where-Object Name -eq $name).Count) {
            throw "Allowlist user '$name' does not exist locally. Check spelling and local/domain authority."
        }
    }
    # Read ALL services/tasks; if either inventory fails, no deletion proceeds.
    $identities=@(
        Get-CimInstance Win32_Service -ErrorAction Stop |
            ForEach-Object { [pscustomobject]@{Identity=$_.StartName;Source="Service:$($_.Name)"} }
        Get-ScheduledTask -ErrorAction Stop |
            ForEach-Object { [pscustomobject]@{Identity=$_.Principal.UserId;Source="Task:$($_.TaskPath)$($_.TaskName)"} }
    )
    foreach ($u in $localUsers) {
        $reasons=@()
        $sid=$u.SID.Value
        if ($u.Name -in $AllowedUsers) { $reasons+='Allowlist' }
        if ($u.Name -in $packetUsers) { $reasons+='Packet-authorized name' }
        if ($sid -eq $operatorSid) { $reasons+='Current operator' }
        if ($sid -match '-(500|501|503|504)$') { $reasons+='Built-in Windows account SID' }
        if ($u.Name.EndsWith('$')) { $reasons+='System/service-style name' }
        if ([string]$u.PrincipalSource -ne 'Local') { $reasons+='Non-local/unknown principal source' }
        foreach ($entry in $identities) {
            $identity=[string]$entry.Identity
            if ($identity -ieq $u.Name -or $identity -ieq ".\$($u.Name)" -or
                $identity -ieq "$env:COMPUTERNAME\$($u.Name)" -or $identity -ieq $sid) {
                $reasons+="Dependency:$($entry.Source)"
            }
        }
        [pscustomobject]@{
            Name=$u.Name;Sid=$sid;Enabled=[bool]$u.Enabled
            Authorization=$(if($u.Name -in $packetUsers){'Briefing user'}elseif($u.Name -in $AllowedUsers){'Extra allowlist'}elseif($sid -match '-(500|501|503|504)$'){'Windows built-in'}else{'Unlisted - review'})
            Decision=$(if($reasons.Count){'KEEP'}else{'DELETE candidate'})
            Reason=($reasons -join '; ');User=$u
        }
    }
}
function Assert-RecoveryAdmin {
    param($Review)
    $candidates=@($Review | Where-Object Decision -eq 'DELETE candidate' | ForEach-Object { $_.Sid })
    $members=@(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)
    $recovery=@($Review | Where-Object {
        $_.Enabled -and $_.Sid -notin $candidates -and
        $_.Sid -in @($members | ForEach-Object {$_.SID.Value})
    })
    if (-not $recovery.Count) { throw 'No enabled retained LOCAL administrator was verified. Establish recovery access first.' }
}
$review=@(Get-RemovalReview)
$review | Select-Object Name,Enabled,Sid,Authorization,Decision,Reason | Format-Table -Wrap -AutoSize
Write-Host 'ACCOUNTS OUTSIDE THE AUTHORIZED HUMAN ALLOWLIST (excluding built-in Windows accounts):'
$review | Where-Object Authorization -eq 'Unlisted - review' |
    Select-Object Name,Sid,Decision,Reason | Format-Table -Wrap -AutoSize
$candidates=@($review | Where-Object Decision -eq 'DELETE candidate')
if (-not $candidates.Count) { Write-Host 'No unprotected local-user deletion candidates.'; return }
Assert-RecoveryAdmin $review
Write-Warning 'Deletion is permanent for the original SID/password. Recreating the same username does not restore that identity or its old permissions.'
Write-Host 'Review app/share/backup dependencies and flag access; service/task detection is not a complete dependency inventory.'
Write-Host 'Protected unknown accounts are retained for investigation, not declared authorized.'
if (-not $Apply) { Write-Host 'Preview only. Add -Apply to delete the listed candidates after reviewing them.'; return }
$reportPath=$null
$report=[pscustomobject]@{
    ComputerName=$env:COMPUTERNAME;CreatedUtc=[DateTime]::UtcNow.ToString('o')
    AuthorizedHumanUsers=$packetUsers;Status='InProgress'
    Accounts=@($review | ForEach-Object {
        [pscustomobject]@{
            Name=$_.Name;Sid=$_.Sid;Authorization=$_.Authorization
            Plan=$_.Decision;Reason=$_.Reason
            Outcome=$(if($_.Decision -eq 'DELETE candidate'){'NotAttempted'}else{'Retained'})
            StateFile=$null;Error=$null
        }
    })
}
function Save-RemovalReport {
    $report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $reportPath -Encoding UTF8 -ErrorAction Stop
}
foreach ($candidate in $candidates) {
    if ($PSCmdlet.ShouldProcess("$($candidate.Name) ($($candidate.Sid))",'Permanently delete local user')) {
        # Refresh before EACH deletion to catch newly added service/task uses.
        $fresh=@(Get-RemovalReview)
        Assert-RecoveryAdmin $fresh
        $match=@($fresh | Where-Object Sid -eq $candidate.Sid)
        if ($match.Count -ne 1 -or $match[0].Name -ne $candidate.Name -or $match[0].Decision -ne 'DELETE candidate') {
            throw "Account/dependency state changed for '$($candidate.Name)'. Stop and review a new preview."
        }
        if (-not $reportPath) {
            $folder=Join-Path (Initialize-DefenseStore) ('user-removal-'+[guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $folder -ErrorAction Stop | Out-Null
            $reportPath=Join-Path $folder 'user-removal-report.json'
            Save-RemovalReport
            Write-Host "Deletion report: $reportPath" -ForegroundColor Cyan
        }
        $row=@($report.Accounts | Where-Object Sid -eq $candidate.Sid)[0]
        $row.Outcome='InProgress'
        Save-RemovalReport
        try {
            $target=@{Sid=$candidate.Sid;UserName=$candidate.Name}
            Invoke-DefenseChange 'LocalUserDeletion' $target {
                param($record)
                $row.StateFile=$record.StateFile
                Save-RemovalReport
                if (-not $record.Before.Exists -or $record.Before.Name -ne $record.Target.UserName -or
                    $record.Before.Name -in $AllowedUsers -or $record.Before.Name -in $packetUsers) {
                    throw 'Account state changed before deletion; review a new preview.'
                }
                # Metadata/group memberships are evidence, not a recoverable SID.
                Remove-LocalUser -SID $record.Target.Sid -Confirm:$false -ErrorAction Stop
                $remaining=@(Get-LocalUser -ErrorAction Stop | Where-Object {$_.SID.Value -eq $record.Target.Sid})
                if ($remaining.Count) { throw "Account still exists after deletion: $($record.Target.UserName)" }
            }
            $row.Outcome='Deleted'
            Save-RemovalReport
            Write-Host "DELETED: $($candidate.Name) ($($candidate.Sid))" -ForegroundColor Yellow
        } catch {
            $row.Outcome='FailedOrIncomplete'
            $row.Error=$_.Exception.Message
            $report.Status='StoppedAfterFailure'
            Save-RemovalReport
            throw
        }
    }
}
if ($reportPath) {
    $report.Status='Completed'
    Save-RemovalReport
    Write-Host 'ACTUAL DELETION RESULTS:'
    $report.Accounts | Select-Object Name,Sid,Outcome,Reason | Format-Table -Wrap -AutoSize
    Write-Host "Full retained/deleted/failed account report: $reportPath"
}
Write-Host 'Review existing sessions/tokens separately. Confirm retained user logins, SMB access and scoring.'

