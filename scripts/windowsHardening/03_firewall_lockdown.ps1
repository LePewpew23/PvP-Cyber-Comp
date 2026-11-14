#requires -Version 5.1
<#
.SYNOPSIS
Restrict inbound access to the staged SMB role, with a timed local-policy rollback.
.DESCRIPTION
Default preview. Fill and stage the config with 02 first. On -Apply, require
console recovery, back up local policy and test the scheduled SYSTEM worker
before changing firewall rules. Outbound rules/defaults are not changed.
Do not edit the firewall concurrently: rollback restores the full local snapshot.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ConfigPath="$PSScriptRoot\config\firewall.json",
    [ValidateRange(5,30)][int]$RollbackMinutes=10,
    [switch]$ConsoleRecoveryAvailable,[switch]$Apply
)
$ErrorActionPreference='Stop'
Import-Module "$PSScriptRoot\Lib\SmbDefense.Common.psm1" -Force
Import-Module "$PSScriptRoot\Lib\RoleFirewall.Common.psm1" -Force
$config=Read-PvPFirewallConfig $ConfigPath
Assert-DefenseHost $config.ExpectedComputerName
$plan=@(Get-PvPFirewallPlan $config (Get-PvPNetworkFacts))
Assert-PvPPolicyReady $config $plan -ForLockdown
$keep=@($plan | ForEach-Object Name)+@($config.PreserveInboundRuleNames)
$disable=@(Get-NetFirewallRule -PolicyStore PersistentStore -Direction Inbound -Action Allow -Enabled True |
    Where-Object {$_.Name -notin $keep})
Write-Host 'KEEP (only these inbound allowances will remain):'
$keep | ForEach-Object {Write-Host "  $_"}
Write-Host 'DISABLE (local inbound Allow rules; services are not stopped):'
$disable | Select-Object Name,DisplayName,Profile | Format-Table -Wrap
Write-Host 'PLAN: enable Domain/Private/Public profiles with default inbound Block. Keep existing block rules and all outbound settings.'
Write-Host "Rollback after $RollbackMinutes minutes unless fresh remote/scoring checks pass and you commit with 05_verify.ps1."
if (-not $Apply) {Write-Host 'Preview only. Add -Apply -ConsoleRecoveryAvailable after reviewing the plan.';return}
if (-not $ConsoleRecoveryAvailable) {throw 'Verify working hypervisor/physical console recovery, then supply -ConsoleRecoveryAvailable.'}
if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME,'Restrict inbound firewall access with timed rollback')) {return}
$root=Initialize-DefenseStore
$pointer=Join-Path $root 'LAST_FIREWALL_TRANSACTION.txt'
if (Test-Path -LiteralPath $pointer) {
    $previous=Get-PvPTransaction ((Get-Content -LiteralPath $pointer -Raw).Trim())
    if ($previous.State.Status -notin @('Committed','RolledBack','CancelledBeforeChange')) {
        throw "Finish or restore the pending transaction first: $($previous.StateFile) [$($previous.State.Status)]"
    }
}
# Capture exactly the local policy we will restore, after staging and before lockdown.
$folder=New-PvPFirewallBackup 'lockdown'
$worker=Join-Path $folder 'recovery-worker.ps1'
Copy-Item -LiteralPath "$PSScriptRoot\Lib\Firewall-RecoveryWorker.ps1" -Destination $worker -ErrorAction Stop
$stateFile=Join-Path $folder 'state.json'
$taskName='Sunflower-PvP-Rollback-'+[guid]::NewGuid().ToString('N')
$deadline=(Get-Date).AddMinutes($RollbackMinutes)
$state=[ordered]@{
    SchemaVersion=2;ComputerName=$env:COMPUTERNAME
    MachineGuid=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid
    CreatedUtc=[DateTime]::UtcNow.ToString('o');Status='Prepared';TaskName=$taskName
    DeadlineUtc=$deadline.ToUniversalTime().ToString('o')
    BackupSHA256=(Get-FileHash -LiteralPath (Join-Path $folder 'firewall-before.wfw') -Algorithm SHA256).Hash
    WorkerSHA256=(Get-FileHash -LiteralPath $worker -Algorithm SHA256).Hash
    ConfigSHA256=(Get-FileHash -LiteralPath $ConfigPath -Algorithm SHA256).Hash
    Config=$config;Plan=$plan;KeepRuleNames=$keep;DisableRuleNames=@($disable | ForEach-Object Name)
    Error=$null;VerifiedUtc=$null;RolledBackUtc=$null
}
$state | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath $stateFile -Encoding UTF8
$stateFile | Set-Content -LiteralPath $pointer -Encoding UTF8
$powershell="$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$argumentBase='-NoProfile -NonInteractive -File "'+$worker+'" -StateFile "'+$stateFile+'" -Mode '
$registered=$false
$armed=$false
try {
    # The probe uses the same account, executable, policy and private files as rollback.
    $action=New-ScheduledTaskAction -Execute $powershell -Argument ($argumentBase+'Probe')
    $trigger=New-ScheduledTaskTrigger -Once -At $deadline
    $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settingsArgs=@{
        StartWhenAvailable=$true;AllowStartIfOnBatteries=$true;DontStopIfGoingOnBatteries=$true
        ExecutionTimeLimit=(New-TimeSpan -Minutes 5);MultipleInstances='IgnoreNew'
    }
    $settings=New-ScheduledTaskSettingsSet @settingsArgs
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -ErrorAction Stop | Out-Null
    $registered=$true
    Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
    $probe=Join-Path $folder 'probe-ok.json'
    $timeout=[DateTime]::UtcNow.AddSeconds(20)
    do {
        Start-Sleep -Milliseconds 250
        $task=Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
    } while ((-not (Test-Path -LiteralPath $probe) -or [string]$task.State -eq 'Running') -and [DateTime]::UtcNow -lt $timeout)
    if (-not (Test-Path -LiteralPath $probe) -or [string]$task.State -eq 'Running') {
        throw 'The scheduled recovery probe did not complete. Check Task Scheduler and execution policy; firewall has not changed.'
    }
    $probeResult=Get-Content -LiteralPath $probe -Raw | ConvertFrom-Json
    if (-not $probeResult.OK -or $probeResult.Machine -ine $env:COMPUTERNAME) {throw 'Recovery probe validation failed.'}
    $rollbackAction=New-ScheduledTaskAction -Execute $powershell -Argument ($argumentBase+'Rollback')
    Set-ScheduledTask -TaskName $taskName -Action $rollbackAction -ErrorAction Stop | Out-Null
    $task=Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
    if ($task.Actions.Count -ne 1 -or $task.Actions[0].Arguments -cne ($argumentBase+'Rollback') -or
        $task.Actions[0].Execute -ine $powershell -or [string]$task.State -eq 'Disabled') {throw 'Rollback task was not armed correctly.'}
    Invoke-PvPTransactionStep $stateFile @('Prepared') {param($r) $r.Status='Armed'}
    $armed=$true
    # Recheck after setup in case policy, sessions or stage rules changed.
    Assert-PvPPolicyReady $config $plan -ForLockdown
    foreach ($rule in $disable) {
        # Use the exact local CIM object, not a potentially wildcard-bearing name.
        $localRule=$rule
        $change={param($r) Disable-NetFirewallRule -InputObject $localRule -ErrorAction Stop | Out-Null}.GetNewClosure()
        Invoke-PvPTransactionStep $stateFile @('Armed') $change
    }
    Invoke-PvPTransactionStep $stateFile @('Armed') {
        param($r)
        Set-NetFirewallProfile -PolicyStore PersistentStore -Name Domain,Private,Public -Enabled True -DefaultInboundAction Block -ErrorAction Stop
    }
    Invoke-PvPTransactionStep $stateFile @('Armed') {
        param($r)
        Assert-PvPLockdownEffective $r.Plan $r.KeepRuleNames
        $r.Status='AwaitingValidation'
    }
} catch {
    $failure=$_
    if ($armed) {
        try {& $worker -StateFile $stateFile -Mode Rollback}
        catch {Write-Warning "Automatic recovery also failed: $_. Use the console and $folder\firewall-before.wfw."}
    } else {
        Invoke-PvPTransactionStep $stateFile @('Prepared','Armed') {param($r) $r.Status='CancelledBeforeChange'}
        if ($registered) {Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue}
    }
    throw $failure
}
Write-Host "Restricted inbound policy is active. Automatic rollback deadline (local): $deadline"
Write-Host "State: $stateFile"
Write-Host 'From a separate authorized client: test new ping, management login, SMB login and the exact scored file operation; check the scoreboard.'
Write-Host 'After all checks pass, run:'
Write-Host ('.\05_verify.ps1 -StateFile "'+$stateFile+'" -Commit -RemoteChecksPassed')
