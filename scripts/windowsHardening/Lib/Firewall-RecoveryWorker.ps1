#requires -Version 5.1
# Internal recovery worker. Copied into the private transaction folder before use.
# The scheduled SYSTEM task calls Rollback unless 05_verify.ps1 commits the change.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$StateFile,
    [ValidateSet('Probe','Rollback','Restore','Commit')][string]$Mode='Rollback'
)
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $env:ProgramData 'SunflowerDefense'))+[IO.Path]::DirectorySeparatorChar
$item=Get-Item -LiteralPath $StateFile -Force -ErrorAction Stop
if ($item.PSIsContainer -or $item.Length -gt 2097152 -or
    -not $item.FullName.StartsWith($root,[StringComparison]::OrdinalIgnoreCase)) {throw 'Invalid private firewall state file.'}
$parent=$item
while ($parent -and $parent.FullName.StartsWith($root.TrimEnd('\'),[StringComparison]::OrdinalIgnoreCase)) {
    if ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) {throw 'Redirected transaction paths are refused.'}
    $parent=if($parent -is [IO.DirectoryInfo]){$parent.Parent}else{$parent.Directory}
}
$folder=$item.DirectoryName
$lockPath=Join-Path $folder 'state.lock'
$lock=$null
$limit=[DateTime]::UtcNow.AddSeconds(30)
while (-not $lock -and [DateTime]::UtcNow -lt $limit) {
    try {$lock=[IO.File]::Open($lockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)}
    catch [IO.IOException] {Start-Sleep -Milliseconds 200}
}
if (-not $lock) {throw 'Could not acquire the firewall transaction lock. Use console recovery.'}
function Save-State {
    $temp=Join-Path $folder 'state-write.tmp'
    $state | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath $temp -Encoding UTF8 -ErrorAction Stop
    Move-Item -LiteralPath $temp -Destination $item.FullName -Force -ErrorAction Stop
}
try {
    $state=Get-Content -LiteralPath $item.FullName -Raw | ConvertFrom-Json
    $guid=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop).MachineGuid
    if ($state.SchemaVersion -ne 2 -or $state.ComputerName -ine $env:COMPUTERNAME -or $state.MachineGuid -ne $guid) {
        throw 'Wrong host or unsupported firewall transaction.'
    }
    if ((Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash -ne $state.WorkerSHA256) {
        throw 'The recovery worker changed after capture.'
    }
    $backup=Join-Path $folder 'firewall-before.wfw'
    $b=Get-Item -LiteralPath $backup -Force
    if ($b.Attributes -band [IO.FileAttributes]::ReparsePoint -or
        (Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash -ne $state.BackupSHA256) {throw 'The firewall snapshot changed after capture.'}
    if ($Mode -eq 'Probe') {
        [pscustomobject]@{OK=$true;Utc=[DateTime]::UtcNow.ToString('o');Machine=$env:COMPUTERNAME} |
            ConvertTo-Json | Set-Content -LiteralPath (Join-Path $folder 'probe-ok.json') -Encoding UTF8
        return
    }
    if ($Mode -eq 'Commit') {
        if ($state.Status -ne 'AwaitingValidation') {throw "Cannot commit a transaction in state '$($state.Status)'."}
        $state.Status='Committed';$state.VerifiedUtc=[DateTime]::UtcNow.ToString('o')
        Save-State
    } elseif (($Mode -eq 'Restore' -and $state.Status -eq 'Committed') -or
        $state.Status -notin @('Committed','RolledBack','CancelledBeforeChange')) {
        $state.Status='RollingBack';Save-State
        try {
            # This restores the complete LOCAL firewall snapshot from immediately
            # before lockdown. Coordinate an exclusive firewall-change window.
            $output=& "$env:SystemRoot\System32\netsh.exe" advfirewall import $backup 2>&1
            if ($LASTEXITCODE -ne 0) {throw "netsh import failed: $($output -join ' ')"}
            $state.Status='RolledBack';$state.RolledBackUtc=[DateTime]::UtcNow.ToString('o');$state.Error=$null
            Save-State
            Write-Host 'Previous local firewall policy restored. Verify scoring and management access.'
        } catch {
            $state.Status='RollbackFailed';$state.Error=$_.Exception.Message;Save-State
            throw
        }
    }
    if ($state.Status -in @('Committed','RolledBack','CancelledBeforeChange')) {
        try {Unregister-ScheduledTask -TaskName $state.TaskName -Confirm:$false -ErrorAction Stop} catch {
            Write-Warning 'The transaction is complete, but its task registration could not be removed. Its state prevents another rollback.'
        }
    }
} finally {$lock.Dispose()}

