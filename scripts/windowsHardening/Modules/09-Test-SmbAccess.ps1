#requires -Version 5.1
<#
.SYNOPSIS
From a permitted WINDOWS CLIENT, authenticate to a share and read one known file.
.DESCRIPTION
Run in a fresh client logon/session so cached credentials cannot hide a failure.
Prompts for credentials, creates one temporary PSDrive, hashes the selected file,
then removes only that PSDrive. No server settings or file contents are changed.
This verifies a read; it does not prove write access or the scorer's exact check.
#>
[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9.-]*$')]
    [string]$Server='sunflower.misty.view',
    [Parameter(Mandatory)][ValidatePattern('^[^\\/:*?"<>|]+$')][string]$ShareName,
    [Parameter(Mandatory)][string]$RelativeFile,
    [Management.Automation.PSCredential]$Credential,
    [ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedSHA256
)
$ErrorActionPreference='Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Run this test on a permitted Windows client.' }
if ([IO.Path]::IsPathRooted($RelativeFile) -or $RelativeFile -match '(^|[\\/])\.\.([\\/]|$)' -or $RelativeFile.Contains(':')) {
    throw 'RelativeFile must name a known file inside this share, without .. or a drive/stream prefix.'
}
if (-not (Test-NetConnection -ComputerName $Server -Port 445 -InformationLevel Quiet)) {
    throw "TCP 445 on $Server is unreachable. Check listener, route and firewall."
}
$shortName=$Server.Split('.')[0]
$existing=@(Get-SmbConnection -ErrorAction Stop | Where-Object {
    $_.ServerName -ieq $Server -or $_.ServerName -ieq $shortName
})
if ($existing.Count) {
    throw 'An SMB connection to this server already exists in this logon session. Use a fresh client sign-in; this script will not disconnect other sessions.'
}
if (-not $Credential) {
    $Credential=Get-Credential -Message 'Enter the SCORED identity, including its verified server/domain authority'
}
if (-not $Credential) { throw 'No credential supplied.' }
$drive='SmbTest'+[guid]::NewGuid().ToString('N').Substring(0,8)
$created=$false
try {
    $driveArgs=@{
        Name=$drive; PSProvider='FileSystem'; Root="\\$Server\$ShareName"
        Credential=$Credential; Scope='Script'; ErrorAction='Stop'
    }
    New-PSDrive @driveArgs | Out-Null
    $created=$true
    $path=Join-Path ($drive+':\') $RelativeFile
    $file=Get-Item -LiteralPath $path -ErrorAction Stop
    if ($file.PSIsContainer) { throw 'Select a required FILE, not only a directory.' }
    # Reading the whole selected file proves data access without printing its contents.
    $hash=Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop
    if ($ExpectedSHA256 -and $hash.Hash -ine $ExpectedSHA256) { throw 'File was readable, but its hash does not match the expected value.' }
    [pscustomobject]@{
        ReadPassed=$true; Server=$Server; Share=$ShareName
        File=$RelativeFile; Bytes=$file.Length; SHA256=$hash.Hash
    }
    Get-SmbConnection | Where-Object { $_.ServerName -ieq $Server -or $_.ServerName -ieq $shortName } |
        Select-Object ServerName,ShareName,UserName,Dialect,Encrypted
} finally {
    if ($created) { Remove-PSDrive -Name $drive -Scope Script -Force -ErrorAction Continue }
}
Write-Host 'Read test passed. Check the scoring engine and any required WRITE operation separately.'
