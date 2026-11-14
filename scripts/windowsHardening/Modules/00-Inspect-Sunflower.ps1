#requires -Version 5.1
<#
.SYNOPSIS
Read-only inventory for the SMB server. No policy/account/ACL changes.
.EXAMPLE
.\00-Inspect-Sunflower.ps1
#>
[CmdletBinding()]
param([string]$ExpectedComputerName='sunflower')
$ErrorActionPreference='Stop'
Import-Module "$PSScriptRoot\..\Lib\SmbDefense.Common.psm1" -Force
Assert-DefenseHost $ExpectedComputerName

function Show-Section {
    param([string]$Title,[scriptblock]$Read)
    Write-Host "`n=== $Title ===" -ForegroundColor Cyan
    try { & $Read | Out-Host } catch { Write-Warning $_.Exception.Message }
}
Show-Section 'Host/domain/build' {
    Get-CimInstance Win32_ComputerSystem | Select-Object Name,Domain,DomainRole
    Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber
}
Show-Section 'SMB settings (SMB2 also covers SMB3)' {
    Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol,EnableSMB2Protocol,
        RequireSecuritySignature,EncryptData,RejectUnencryptedAccess,AuditSmb1Access | Format-List
    Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
}
Show-Section 'Shares and share ACLs' {
    foreach ($share in Get-SmbShare) {
        $share | Select-Object Name,Path,ScopeName,Special,EncryptData | Format-List
        Get-SmbShareAccess -Name $share.Name -ScopeName $share.ScopeName | Format-Table -AutoSize
        # Read NTFS ACL metadata only; do not recurse, read files, or change flags.
        if (-not $share.Special -and (Test-Path -LiteralPath $share.Path)) {
            (Get-Acl -LiteralPath $share.Path).Access |
                Select-Object IdentityReference,FileSystemRights,AccessControlType,IsInherited
        }
    }
}
Show-Section 'Local users and local Administrators' {
    Get-LocalUser | Select-Object Name,Enabled,SID,PasswordLastSet,PasswordExpires
    Get-LocalGroupMember -SID 'S-1-5-32-544'
}
Write-Host 'Packet human-user list: Administrator, jalapeno, coffeebean, pepperpult.'
Write-Host 'This is not a list of accounts to delete; preserve required system/service identities.'
Show-Section 'SMB sessions and open files (private operational data)' {
    Get-SmbSession | Select-Object SessionId,ClientComputerName,ClientUserName,NumOpens,Dialect
    Get-SmbOpenFile | Select-Object ClientComputerName,ClientUserName,Path
}
Show-Section 'Firewall profiles and possible inbound SMB allow rules' {
    Get-NetFirewallProfile -PolicyStore ActiveStore |
        Select-Object Name,Enabled,DefaultInboundAction,AllowLocalFirewallRules
    foreach ($rule in Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Inbound -Action Allow) {
        $port=$rule | Get-NetFirewallPortFilter
        # Includes Any/ranges for review; module 04 edits exact TCP 445 rules only.
        if ([string]$port.Protocol -in @('TCP','6','Any','256')) {
            $addr=$rule | Get-NetFirewallAddressFilter
            [pscustomobject]@{
                Name=$rule.Name; DisplayName=$rule.DisplayName; Profile=$rule.Profile
                LocalPort=($port.LocalPort -join ','); RemoteAddress=($addr.RemoteAddress -join ',')
                SourceType=$rule.PolicyStoreSourceType
            }
        }
    }
}
Show-Section 'Defender state and exclusions (if installed)' {
    Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated
    Get-MpPreference | Select-Object DisableRealtimeMonitoring,ExclusionPath,ExclusionProcess,ExclusionExtension
}
Show-Section 'Services and task identities; investigate unknown entries' {
    Get-CimInstance Win32_Service | Select-Object Name,State,StartMode,StartName,PathName
    Get-ScheduledTask | Select-Object TaskPath,TaskName,State,
        @{Name='RunAs';Expression={$_.Principal.UserId}}
}
Show-Section 'Recent relevant security events (auditing must be configured)' {
    Get-WinEvent -FilterHashtable @{
        LogName='Security'; Id=4624,4625,4720,4728,4732,4756,1102,5140,5145
        StartTime=(Get-Date).AddMinutes(-30)
    } -MaxEvents 100 | Select-Object TimeCreated,Id,Message
}
Write-Host "`nRecord the real share, scored account authority, client networks, and expected file operation."
