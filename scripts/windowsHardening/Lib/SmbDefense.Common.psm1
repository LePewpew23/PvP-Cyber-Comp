# Shared helpers for the Sunflower SMB toolkit.
# Target: 64-bit Windows PowerShell 5.1 on Windows Server 2019.
# Importing this module defines functions only; it changes no machine settings.
Set-StrictMode -Version 2.0

function Assert-DefenseHost {
    [CmdletBinding()]
    param([string]$ExpectedComputerName = 'sunflower')
    if ($PSVersionTable.PSEdition -ne 'Desktop' -or -not [Environment]::Is64BitProcess) {
        throw 'Use 64-bit Windows PowerShell 5.1, opened as Administrator.'
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Open Windows PowerShell with Run as administrator.'
    }
    if ($env:COMPUTERNAME -ine $ExpectedComputerName) {
        throw "Wrong host: '$env:COMPUTERNAME'. Expected '$ExpectedComputerName'. Verify the console before changing -ExpectedComputerName."
    }
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    if ([int]$cs.DomainRole -ge 4) {
        throw 'This toolkit is for the SMB member/standalone server, not a domain controller.'
    }
    if ([int]$os.ProductType -ne 3 -or [string]$os.BuildNumber -ne '17763') {
        throw "This toolkit targets Windows Server 2019 (build 17763); found '$($os.Caption)', build $($os.BuildNumber)."
    }
}

function Resolve-DefenseSid {
    param([Parameter(Mandatory)][string]$Principal)
    if ($Principal -match '^S-1-') {
        return (New-Object Security.Principal.SecurityIdentifier($Principal)).Value
    }
    $account = New-Object Security.Principal.NTAccount($Principal)
    return $account.Translate([Security.Principal.SecurityIdentifier]).Value
}

function Get-DefenseOperatorSid {
    # Separate helper also makes preview/guard behavior testable without a live host.
    return [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
}

function Get-DefenseShare {
    param([Parameter(Mandatory)][string]$ShareName)
    if ([Management.Automation.WildcardPattern]::ContainsWildcardCharacters($ShareName)) {
        throw 'Supply one literal share name, without wildcard characters.'
    }
    $shares = @(Get-SmbShare -Name $ShareName -ErrorAction Stop)
    if ($shares.Count -ne 1 -or $shares[0].Special) {
        throw 'Select one ordinary data share; special/admin shares and ambiguous scopes are not supported.'
    }
    return $shares[0]
}

function Get-DefenseRegistryValue {
    param([string]$Path, [string]$Name)
    $key = Get-Item -LiteralPath $Path -ErrorAction Stop
    $present = $key.GetValueNames() -contains $Name
    $kind = $null
    $value = $null
    if ($present) {
        $kind = [string]$key.GetValueKind($Name)
        $value = $key.GetValue($Name)
    }
    return [ordered]@{ Path=$Path; Name=$Name; Present=$present; Kind=$kind; Value=$value }
}

function Restore-DefenseRegistryValue {
    param([Parameter(Mandatory)]$State)
    if ($State.Present) {
        # New-ItemProperty -Force restores both the original type and value.
        New-ItemProperty -LiteralPath $State.Path -Name $State.Name `
            -PropertyType $State.Kind -Value $State.Value -Force -ErrorAction Stop | Out-Null
    } else {
        $key = Get-Item -LiteralPath $State.Path -ErrorAction Stop
        if ($key.GetValueNames() -contains $State.Name) {
            Remove-ItemProperty -LiteralPath $State.Path -Name $State.Name -ErrorAction Stop
        }
    }
}

function Invoke-DefenseAuditpol {
    param([Parameter(Mandatory)][string[]]$ArgumentList)
    $output = & "$env:SystemRoot\System32\auditpol.exe" @ArgumentList 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "auditpol failed (exit $LASTEXITCODE): $($output -join ' ')"
    }
    return ($output | ForEach-Object { [string]$_ })
}

function Get-DefenseState {
    # Only ordinary data values go into backups. No passwords are exported.
    param([Parameter(Mandatory)][string]$Kind, [Parameter(Mandatory)]$Target)
    switch ($Kind) {
        'FirewallBlockCreate' {
            return [ordered]@{ Rules=@(foreach ($name in @($Target.RuleNames | Sort-Object)) {
                try {
                    $r=Get-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction Stop
                } catch {
                    if ($_.CategoryInfo.Category -ne 'ObjectNotFound') { throw }
                    [ordered]@{ Name=$name; Exists=$false }
                    continue
                }
                $address=$r | Get-NetFirewallAddressFilter -ErrorAction Stop
                $port=$r | Get-NetFirewallPortFilter -ErrorAction Stop
                $app=$r | Get-NetFirewallApplicationFilter -ErrorAction Stop
                $service=$r | Get-NetFirewallServiceFilter -ErrorAction Stop
                $interface=$r | Get-NetFirewallInterfaceFilter -ErrorAction Stop
                $interfaceType=$r | Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop
                $security=$r | Get-NetFirewallSecurityFilter -ErrorAction Stop
                [ordered]@{
                    Name=$r.Name; Exists=$true; DisplayName=$r.DisplayName
                    Group=$r.Group; Description=$r.Description
                    Enabled=[string]$r.Enabled; Profile=[string]$r.Profile
                    Direction=[string]$r.Direction; Action=[string]$r.Action
                    EdgeTraversalPolicy=[string]$r.EdgeTraversalPolicy
                    LocalAddress=@($address.LocalAddress | Sort-Object)
                    RemoteAddress=@($address.RemoteAddress | Sort-Object)
                    Protocol=[string]$port.Protocol
                    LocalPort=@($port.LocalPort | Sort-Object)
                    RemotePort=@($port.RemotePort | Sort-Object)
                    Program=$app.Program; Package=$app.Package; Service=$service.Service
                    InterfaceAlias=@($interface.InterfaceAlias | Sort-Object)
                    InterfaceType=[string]$interfaceType.InterfaceType
                    Authentication=[string]$security.Authentication
                    Encryption=[string]$security.Encryption
                    OverrideBlockRules=[string]$security.OverrideBlockRules
                    LocalUser=$security.LocalUser
                    RemoteUser=$security.RemoteUser
                    RemoteMachine=$security.RemoteMachine
                }
            }) }
        }
        'LocalUserDeletion' {
            try { $u=Get-LocalUser -SID $Target.Sid -ErrorAction Stop } catch {
                if ($_.CategoryInfo.Category -ne 'ObjectNotFound') { throw }
                return [ordered]@{ Exists=$false; Sid=$Target.Sid }
            }
            $groups=@(foreach ($group in Get-LocalGroup -ErrorAction Stop) {
                $members=@(Get-LocalGroupMember -SID $group.SID -ErrorAction Stop)
                if (@($members | Where-Object { $_.SID.Value -eq $Target.Sid }).Count) {
                    [ordered]@{ Name=$group.Name; Sid=$group.SID.Value }
                }
            })
            return [ordered]@{
                Exists=$true; Name=$u.Name; Sid=$u.SID.Value; Enabled=[bool]$u.Enabled
                FullName=$u.FullName; Description=$u.Description
                PasswordLastSet=[string]$u.PasswordLastSet
                Groups=@($groups | Sort-Object Name)
            }
        }
        'Smb1' {
            $features = @(Get-WindowsOptionalFeature -Online -ErrorAction Stop |
                Where-Object FeatureName -like 'SMB1Protocol*' |
                Sort-Object FeatureName |
                ForEach-Object { [ordered]@{ Name=$_.FeatureName; State=[string]$_.State } })
            return [ordered]@{
                Features=$features
                Registry=(Get-DefenseRegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1')
            }
        }
        'Signing' {
            return [ordered]@{ RequireSecuritySignature=[bool](Get-SmbServerConfiguration -ErrorAction Stop).RequireSecuritySignature }
        }
        'ShareAllow' {
            $share = Get-DefenseShare $Target.ShareName
            $entries = @(Get-SmbShareAccess -Name $share.Name -ScopeName $share.ScopeName -ErrorAction Stop |
                Where-Object {
                    $match = $false
                    try { $match = (Resolve-DefenseSid $_.AccountName) -eq $Target.Sid } catch { }
                    $match -and [string]$_.AccessControlType -eq 'Allow'
                } |
                Sort-Object AccountName,AccessRight |
                ForEach-Object { [ordered]@{ AccountName=$_.AccountName; AccessRight=[string]$_.AccessRight } })
            return [ordered]@{ ScopeName=$share.ScopeName; Path=$share.Path; Entries=$entries }
        }
        'FirewallScope' {
            $rules = @(
                foreach ($name in @($Target.RuleNames | Sort-Object)) {
                    $r = Get-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction Stop
                    $a = $r | Get-NetFirewallAddressFilter -ErrorAction Stop
                    [ordered]@{ Name=$r.Name; RemoteAddress=@($a.RemoteAddress | Sort-Object) }
                }
            )
            return [ordered]@{ Rules=$rules }
        }
        'LocalEnabled' {
            $u = Get-LocalUser -SID $Target.Sid -ErrorAction Stop
            return [ordered]@{ Name=$u.Name; Enabled=[bool]$u.Enabled }
        }
        'LocalAdmin' {
            $members = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)
            return [ordered]@{ IsMember=[bool](@($members | Where-Object { $_.SID.Value -eq $Target.Sid }).Count -gt 0) }
        }
        'LocalPassword' {
            $u = Get-LocalUser -SID $Target.Sid -ErrorAction Stop
            # This timestamp helps document a reset; it cannot recover a password.
            return [ordered]@{ Name=$u.Name; PasswordLastSet=[string]$u.PasswordLastSet }
        }
        'Auditing' {
            # auditpol /restore covers system policy, per-user policy and options.
            # Capture all three so rollback can detect later policy changes.
            $users=@(Invoke-DefenseAuditpol @('/list','/user','/v','/r'))
            $sids=@([regex]::Matches(($users -join [Environment]::NewLine),'S-\d-\d+(?:-\d+)+') |
                ForEach-Object { $_.Value } | Sort-Object -Unique)
            $perUser=@(foreach ($sid in $sids) {
                [ordered]@{ Sid=$sid; PolicyText=@(Invoke-DefenseAuditpol @('/get',"/user:{$sid}",'/category:*','/r')) }
            })
            $options=@(foreach ($name in @('AuditBaseDirectories','AuditBaseObjects','CrashOnAuditFail','FullPrivilegeAuditing')) {
                [ordered]@{ Name=$name; PolicyText=@(Invoke-DefenseAuditpol @('/get',"/option:$name",'/r')) }
            })
            return [ordered]@{
                PolicyText=@(Invoke-DefenseAuditpol @('/get','/category:*','/r'))
                PerUserList=$users
                PerUserPolicies=$perUser
                Options=$options
                ForceSubcategories=(Get-DefenseRegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'SCENoApplyLegacyAuditPolicy')
                AuditSmb1Access=[bool](Get-SmbServerConfiguration -ErrorAction Stop).AuditSmb1Access
            }
        }
        'ShareEncryption' {
            $share = Get-DefenseShare $Target.ShareName
            return [ordered]@{
                ScopeName=$share.ScopeName
                EncryptData=[bool]$share.EncryptData
                RejectUnencryptedAccess=[bool](Get-SmbServerConfiguration -ErrorAction Stop).RejectUnencryptedAccess
                # Detect later encryption changes on other shares before a rollback.
                OtherEncryptedShares=@(Get-SmbShare -ErrorAction Stop |
                    Where-Object { $_.EncryptData -and $_.Name -ne $Target.ShareName } |
                    Sort-Object ScopeName,Name | ForEach-Object { "$($_.ScopeName)/$($_.Name)" })
            }
        }
        'Defender' {
            return [ordered]@{ DisableRealtimeMonitoring=[bool](Get-MpPreference -ErrorAction Stop).DisableRealtimeMonitoring }
        }
        'RdpNla' {
            $r = Get-CimInstance -Namespace root/cimv2/TerminalServices `
                -ClassName Win32_TSGeneralSetting -Filter "TerminalName='RDP-tcp'" -ErrorAction Stop
            return [ordered]@{ UserAuthenticationRequired=[uint32]$r.UserAuthenticationRequired }
        }
        'FirewallProfiles' {
            return [ordered]@{ Profiles=@(
                Get-NetFirewallProfile -PolicyStore PersistentStore -Name $Target.Profiles -ErrorAction Stop |
                Sort-Object Name | ForEach-Object {
                    [ordered]@{ Name=[string]$_.Name; Enabled=[string]$_.Enabled; DefaultInboundAction=[string]$_.DefaultInboundAction }
                }
            ) }
        }
        default { throw "Unsupported backup kind '$Kind'." }
    }
}

function Initialize-DefenseStore {
    # Keep backups off shares/web roots. Restrict them to SYSTEM and Administrators.
    # Reject reparse points so a redirected directory cannot redirect privileged writes.
    $root = Join-Path $env:ProgramData 'SunflowerDefense'
    foreach ($path in @($env:ProgramData,$root)) {
        if (Test-Path -LiteralPath $path) {
            $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
            if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                throw "Backup path is not an ordinary directory: $path"
            }
        }
    }
    if (-not (Test-Path -LiteralPath $root)) {
        New-Item -ItemType Directory -Path $root -ErrorAction Stop | Out-Null
    }
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    $admins = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $acl.SetOwner($admins)
    foreach ($sid in @($admins,$system)) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            $sid,'FullControl','ContainerInherit, ObjectInherit','None','Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $root -AclObject $acl -ErrorAction Stop
    return $root
}

function New-DefenseRecord {
    param([string]$Kind, $Target, $Before)
    $root = Initialize-DefenseStore
    $id = (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N')
    $folder = Join-Path $root $id
    New-Item -ItemType Directory -Path $folder -ErrorAction Stop | Out-Null
    $record = [pscustomobject][ordered]@{
        SchemaVersion=1
        ComputerName=$env:COMPUTERNAME
        MachineGuid=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop).MachineGuid
        CreatedUtc=[DateTime]::UtcNow.ToString('o')
        Kind=$Kind
        Target=$Target
        Before=$Before
        After=$null
        Status='Prepared'
        Error=$null
        Directory=$folder
        StateFile=(Join-Path $folder 'change.json')
    }
    $record | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath $record.StateFile -Encoding UTF8 -ErrorAction Stop
    Write-Host "Backup: $($record.StateFile)" -ForegroundColor Cyan
    return $record
}

function Invoke-DefenseChange {
    param([string]$Kind, $Target, [scriptblock]$Change)
    $before = Get-DefenseState -Kind $Kind -Target $Target
    $record = New-DefenseRecord -Kind $Kind -Target $Target -Before $before
    $failure = $null
    try {
        # The callback receives the backup record, e.g. for an auditpol CSV backup.
        & $Change $record | Out-Host
        $record.Status = 'Applied'
    } catch {
        $failure = $_
        $record.Status = 'Failed'
        $record.Error = $_.Exception.Message
    }
    try { $record.After = Get-DefenseState -Kind $Kind -Target $Target } catch {
        $record.Status = 'NeedsReview'
        $record.Error = "$($record.Error) Cannot capture final state: $($_.Exception.Message)"
        if (-not $failure) { $failure = $_ }
    }
    $record | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath $record.StateFile -Encoding UTF8 -ErrorAction Stop
    Write-Host "Result: $($record.Status). State file: $($record.StateFile)"
    if ($failure) { throw $failure }
    Write-Host 'Verify a NEW remote SMB login/file read and the scoring result before another change.'
}

function Test-DefenseStateEqual {
    param($Left,$Right)
    return (ConvertTo-Json -InputObject $Left -Depth 15 -Compress) -ceq `
           (ConvertTo-Json -InputObject $Right -Depth 15 -Compress)
}

Export-ModuleMember -Function *-Defense*
