#requires -Version 5.1
<#
.SYNOPSIS
Apply ONE host protection: Defender real-time monitoring, RDP NLA, or firewall profiles.
.DESCRIPTION
Choose one control per run and verify it. Firewall activation requires existing
working inbound allowances for SMB, your management path, and all dependencies.
Have console recovery before firewall/NLA changes. No service restart or reboot.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidateSet('Defender','RdpNla','FirewallProfiles')][string]$Control,
    [ValidateSet('Domain','Private','Public')][string[]]$Profile=@('Domain','Private','Public'),
    [switch]$Apply,
    [string]$ExpectedComputerName='sunflower'
)
$ErrorActionPreference='Stop'
Import-Module "$PSScriptRoot\..\Lib\SmbDefense.Common.psm1" -Force
Assert-DefenseHost $ExpectedComputerName
$target=@{}
if ($Control -eq 'FirewallProfiles') { $target=@{Profiles=@($Profile | Sort-Object -Unique)} }
Get-DefenseState $Control $target | ConvertTo-Json -Depth 6 | Write-Host
switch ($Control) {
    'Defender' {
        Write-Host 'PLAN: enable real-time monitoring. This does not remove exclusions, force a scan, or change tamper protection.'
        Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled
    }
    'RdpNla' {
        Write-Host 'PLAN: require authentication before an RDP session. Confirm compatible clients and console access.'
    }
    'FirewallProfiles' {
        Write-Host "PLAN: enable $($Profile -join ', ') profiles and set their default inbound action to Block."
        Write-Warning 'Existing explicit rules are preserved, including broad allows and blocks. Verify SMB, RDP/WinRM and other dependencies BEFORE applying.'
        # This detects the total absence of an SMB allow, not whether all sources,
        # profiles, interfaces, or management dependencies are correctly allowed.
        $smbRules=@(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Inbound -Action Allow -Enabled True |
            Get-NetFirewallPortFilter | Where-Object {
                [string]$_.Protocol -in @('TCP','6','Any','256') -and
                (@($_.LocalPort) -contains '445' -or @($_.LocalPort) -contains 'Any')
            })
        if ($smbRules.Count -eq 0) { throw 'No enabled SMB allow rule found. Configure and review required allowances before enabling default-deny.' }
    }
}
if (-not $Apply) { Write-Host 'Preview only. Add -Apply for the selected control.'; return }
if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME,"Enable $Control")) {
    Invoke-DefenseChange $Control $target {
        switch ($Control) {
            'Defender' {
                Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
                if ((Get-MpPreference).DisableRealtimeMonitoring) { throw 'Defender setting did not change; investigate policy/tamper protection.' }
                $status=Get-MpComputerStatus
                if (-not $status.RealTimeProtectionEnabled) {
                    throw 'Preference changed, but real-time protection is not active. Check service state, passive mode and centrally managed policy.'
                }
            }
            'RdpNla' {
                $cimArgs=@{
                    Namespace='root/cimv2/TerminalServices'
                    ClassName='Win32_TSGeneralSetting'
                    Filter="TerminalName='RDP-tcp'"; ErrorAction='Stop'
                }
                $setting=Get-CimInstance @cimArgs
                $methodArgs=@{
                    InputObject=$setting; MethodName='SetUserAuthenticationRequired'
                    Arguments=@{UserAuthenticationRequired=[uint32]1}; ErrorAction='Stop'
                }
                $result=Invoke-CimMethod @methodArgs
                if ($result.ReturnValue -ne 0) { throw "RDP NLA failed with return code $($result.ReturnValue)." }
                if ((Get-DefenseState 'RdpNla' @{}).UserAuthenticationRequired -ne 1) { throw 'NLA is not effective; check owning policy.' }
            }
            'FirewallProfiles' {
                $profileArgs=@{
                    PolicyStore='PersistentStore'; Name=$target.Profiles
                    Enabled='True'; DefaultInboundAction='Block'; ErrorAction='Stop'
                }
                Set-NetFirewallProfile @profileArgs
                $effective=@(Get-NetFirewallProfile -PolicyStore ActiveStore -Name $target.Profiles)
                if (@($effective | Where-Object { [string]$_.Enabled -ne 'True' -or [string]$_.DefaultInboundAction -ne 'Block' }).Count) {
                    throw 'Effective firewall profiles do not match the requested settings. Check Group Policy.'
                }
            }
        }
    }
}
