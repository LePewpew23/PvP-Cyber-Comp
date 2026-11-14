#requires -Version 5.1
<#
.SYNOPSIS
Inspect Sunflower and, with -Save, capture a private configuration baseline.
.DESCRIPTION
Does not copy passwords, credential hives, shares, flags, or user documents.
The firewall export is a local-policy snapshot, not a full machine backup.
#>
[CmdletBinding()]
param([switch]$Save,[string]$ExpectedComputerName='sunflower')
$ErrorActionPreference='Stop'
Import-Module "$PSScriptRoot\Lib\SmbDefense.Common.psm1" -Force
Import-Module "$PSScriptRoot\Lib\RoleFirewall.Common.psm1" -Force
Assert-DefenseHost $ExpectedComputerName
& "$PSScriptRoot\Modules\00-Inspect-Sunflower.ps1" -ExpectedComputerName $ExpectedComputerName
if (-not $Save) {Write-Host 'Inspection only. Add -Save to write a private baseline.';return}
$folder=New-PvPFirewallBackup 'baseline'
Get-SmbServerConfiguration | Export-Clixml -LiteralPath (Join-Path $folder 'smb-server.xml')
$shares=@(Get-SmbShare)
$shares | Export-Clixml -LiteralPath (Join-Path $folder 'shares.xml')
@(foreach ($s in $shares) {
    [pscustomobject]@{Name=$s.Name;ScopeName=$s.ScopeName;Access=@(Get-SmbShareAccess -Name $s.Name -ScopeName $s.ScopeName)}
}) | Export-Clixml -LiteralPath (Join-Path $folder 'share-access.xml')
Get-LocalUser | Select-Object Name,SID,Enabled,PrincipalSource,PasswordLastSet |
    Export-Clixml -LiteralPath (Join-Path $folder 'users-metadata.xml')
Get-NetTCPConnection -State Listen | Export-Clixml -LiteralPath (Join-Path $folder 'tcp-listeners.xml')
Get-NetUDPEndpoint | Export-Clixml -LiteralPath (Join-Path $folder 'udp-endpoints.xml')
Write-Host "Baseline saved privately: $folder"
Write-Host 'This does not back up file contents, NTFS permissions, account SIDs for recreation, or passwords.'
