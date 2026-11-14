#requires -Version 5.1
<#
.SYNOPSIS
Inspect local SMB/firewall state; explicitly commit a tested firewall transaction.
.DESCRIPTION
Local checks cannot prove remote reachability, NTFS access or scoring. Use a new
session from the actual client/scorer and check its required operation first.
#>
[CmdletBinding(SupportsShouldProcess)]
param([string]$StateFile,[switch]$Commit,[switch]$RemoteChecksPassed,[string]$ExpectedComputerName='sunflower')
$ErrorActionPreference='Stop'
Import-Module "$PSScriptRoot\Lib\SmbDefense.Common.psm1" -Force
Import-Module "$PSScriptRoot\Lib\RoleFirewall.Common.psm1" -Force
Assert-DefenseHost $ExpectedComputerName
Get-Service LanmanServer,BFE,MpsSvc | Format-Table Name,Status,StartType
Get-NetFirewallProfile -PolicyStore ActiveStore | Format-Table Name,Enabled,DefaultInboundAction,DefaultOutboundAction
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol,EnableSMB2Protocol,RequireSecuritySignature,RejectUnencryptedAccess | Format-List
Get-SmbShare | Select-Object Name,Path,EncryptData | Format-Table -AutoSize
Get-NetTCPConnection -State Listen -LocalPort 445 -ErrorAction Stop | Format-Table LocalAddress,LocalPort
if (-not $StateFile) {
    if ($Commit) {throw 'Provide the exact -StateFile printed by 03. Nothing was committed.'}
    Write-Host 'Inspection only; no rollback was cancelled.';return
}
$transaction=Get-PvPTransaction $StateFile
Write-Host "Transaction: $($transaction.State.Status); rollback deadline UTC: $($transaction.State.DeadlineUtc)"
if ($transaction.State.Status -eq 'AwaitingValidation') {
    Assert-PvPPolicyReady $transaction.State.Config $transaction.State.Plan -ForLockdown
    Assert-PvPLockdownEffective $transaction.State.Plan $transaction.State.KeepRuleNames
}
if (-not $Commit) {Write-Host 'Inspection only. The rollback timer remains active.';return}
if (-not $RemoteChecksPassed) {throw 'Verify fresh remote ping, management, SMB and scoring first, then add -RemoteChecksPassed.'}
if ($transaction.State.Status -ne 'AwaitingValidation') {throw 'Only an AwaitingValidation transaction can be committed.'}
if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME,'Commit validated firewall rules and cancel automatic rollback')) {
    & $transaction.Worker -StateFile $transaction.StateFile -Mode Commit
    Write-Host 'Firewall transaction committed. Keep monitoring service scoring.'
}
