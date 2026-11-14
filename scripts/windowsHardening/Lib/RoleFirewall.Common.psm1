# Windows Server 2019 role firewall helpers. No changes occur on import.
Set-StrictMode -Version 2.0

function ConvertTo-PvPSource {
    param([string]$Value,[switch]$AllowAny)
    if ($AllowAny -and $Value -ieq 'Any') { return 'Any' }
    $parts=$Value.Trim().Split('/')
    $ip=$null
    if ($parts.Count -gt 2 -or $parts[0] -match '[%,*?\s]' -or
        ($parts[0] -notmatch ':' -and $parts[0] -notmatch '^\d{1,3}(\.\d{1,3}){3}$') -or
        -not [Net.IPAddress]::TryParse($parts[0],[ref]$ip)) { throw "Use a verified literal IP/CIDR: '$Value'." }
    if ($ip.IsIPv4MappedToIPv6) { throw 'Use ordinary IPv4 or IPv6, not mapped-address notation.' }
    if ($parts[0] -notmatch ':' -and $parts[0] -cne $ip.ToString()) { throw 'IPv4 leading zeros/alternate notation are not accepted.' }
    $bytes=$ip.GetAddressBytes()
    if ([Net.IPAddress]::IsLoopback($ip) -or $ip.Equals([Net.IPAddress]::Any) -or
        $ip.Equals([Net.IPAddress]::IPv6Any) -or $ip.IsIPv6Multicast -or
        ($bytes.Length -eq 4 -and ($bytes[0] -eq 0 -or $bytes[0] -ge 224))) { throw "Invalid source network: '$Value'." }
    $max=$bytes.Length*8
    $prefix=$max
    if ($parts.Count -eq 2) {
        if ($parts[1] -match '^\d+$') { $prefix=[int]$parts[1] }
        elseif ($bytes.Length -eq 4) {
            $mask=$null
            if (-not [Net.IPAddress]::TryParse($parts[1],[ref]$mask) -or $mask.GetAddressBytes().Length -ne 4) { throw 'Invalid subnet mask.' }
            $bits=($mask.GetAddressBytes() | ForEach-Object { [Convert]::ToString($_,2).PadLeft(8,'0') }) -join ''
            if ($bits -notmatch '^1+0*$') { throw 'Subnet mask must be contiguous.' }
            $prefix=$bits.IndexOf('0'); if ($prefix -lt 0) { $prefix=32 }
        } else { throw 'Invalid IPv6 prefix.' }
        if ($prefix -lt 1 -or $prefix -gt $max) { throw 'Unrestricted /0 and invalid prefixes are not accepted.' }
    }
    for ($i=0;$i -lt $bytes.Length;$i++) {
        $remaining=$prefix-8*$i
        if ($remaining -le 0) { $bytes[$i]=0 }
        elseif ($remaining -lt 8) { $bytes[$i]=$bytes[$i] -band (256-[int][Math]::Pow(2,8-$remaining)) }
    }
    $network=New-Object Net.IPAddress -ArgumentList (,$bytes)
    if ($prefix -eq $max) { return $network.ToString() }
    return "$($network.ToString())/$prefix"
}

function Test-PvPSourceOverlap {
    # Unknown Windows address keywords conservatively count as possible overlap.
    param([string]$Left,[string]$Right)
    if ($Left -eq 'Any' -or $Right -eq 'Any') { return $true }
    try { $a=(ConvertTo-PvPSource $Left).Split('/');$b=(ConvertTo-PvPSource $Right).Split('/') } catch { return $true }
    $ai=[Net.IPAddress]::Parse($a[0]).GetAddressBytes();$bi=[Net.IPAddress]::Parse($b[0]).GetAddressBytes()
    if ($ai.Length -ne $bi.Length) { return $false }
    $ap=if($a.Count -eq 2){[int]$a[1]}else{$ai.Length*8}
    $bp=if($b.Count -eq 2){[int]$b[1]}else{$bi.Length*8}
    $prefix=[Math]::Min($ap,$bp)
    for ($i=0;$i -lt $ai.Length;$i++) {
        $n=[Math]::Min(8,[Math]::Max(0,$prefix-8*$i))
        $mask=if($n){256-[int][Math]::Pow(2,8-$n)}else{0}
        if (($ai[$i] -band $mask) -ne ($bi[$i] -band $mask)) { return $false }
    }
    return $true
}

function ConvertTo-PvPPort {
    param([string]$Value)
    if ($Value -notmatch '^(\d{1,5})(?:-(\d{1,5}))?$') { throw "Invalid port/range '$Value'." }
    $lo=[int]$Matches[1];$hi=if($Matches[2]){[int]$Matches[2]}else{$lo}
    if ($lo -lt 1 -or $hi -gt 65535 -or $hi -lt $lo) { throw "Invalid port/range '$Value'." }
    if ($lo -eq $hi) {return [string]$lo};return "$lo-$hi"
}
function Test-PvPPortOverlap {
    param([string]$Left,[string]$Right)
    if ($Left -eq 'Any' -or $Right -eq 'Any') { return $true }
    try { $a=(ConvertTo-PvPPort $Left).Split('-');$b=(ConvertTo-PvPPort $Right).Split('-') } catch { return $true }
    $al=[int]$a[0];$ah=[int]$a[-1];$bl=[int]$b[0];$bh=[int]$b[-1]
    return $al -le $bh -and $bl -le $ah
}
function Read-PvPFirewallConfig {
    param([string]$Path)
    $raw=Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    $c=$raw | ConvertFrom-Json -ErrorAction Stop
    foreach ($field in @('ExpectedComputerName','ServerDnsName','SmbClientSources','ScoringSources','ManagementSources',
        'ManagementTcpPorts','ConsoleOnlyManagement','PingSources','PreserveInboundRuleNames','ReviewedInboundBlockRuleNames','AdditionalInbound')) {
        if ($c.PSObject.Properties.Name -notcontains $field) { throw "Missing configuration field: $field" }
    }
    foreach ($field in @('SmbClientSources','ScoringSources','ManagementSources','PingSources')) {
        $allowAny=$field -eq 'PingSources'
        $c.$field=@($c.$field | ForEach-Object { ConvertTo-PvPSource $_ -AllowAny:$allowAny } | Sort-Object -Unique)
    }
    if (-not @($c.SmbClientSources).Count -or -not @($c.ScoringSources).Count) {
        throw 'Enter VERIFIED SMB-client and scoring-source IPs/CIDRs in firewall.json. The packet does not supply them.'
    }
    if (-not @($c.PingSources).Count) { throw 'PingSources is required so intended clients can ping this server.' }
    if ($c.ConsoleOnlyManagement -isnot [bool]) { throw 'ConsoleOnlyManagement must be a JSON boolean.' }
    $c.ManagementTcpPorts=@($c.ManagementTcpPorts | ForEach-Object {
        $p=ConvertTo-PvPPort ([string]$_)
        if ($p -match '-') { throw 'ManagementTcpPorts requires individual ports.' }
        $p
    } | Sort-Object -Unique)
    if ($c.ConsoleOnlyManagement) {
        if (@($c.ManagementTcpPorts).Count -or @($c.ManagementSources).Count) { throw 'For ConsoleOnlyManagement, leave ManagementTcpPorts and ManagementSources empty.' }
    } elseif (-not @($c.ManagementSources).Count -or -not @($c.ManagementTcpPorts).Count) {
        throw 'Enter verified management source addresses and TCP ports, or explicitly select console-only management.'
    }
    foreach ($name in @($c.PreserveInboundRuleNames)+@($c.ReviewedInboundBlockRuleNames)) {
        if ([string]::IsNullOrWhiteSpace($name) -or [Management.Automation.WildcardPattern]::ContainsWildcardCharacters($name)) {
            throw 'Preserved/reviewed rule names must be literal nonempty Names, not DisplayName patterns.'
        }
    }
    foreach ($extra in @($c.AdditionalInbound)) {
        foreach ($field in @('Name','Protocol','LocalPorts','RemoteAddresses','Reason')) {
            if ($extra.PSObject.Properties.Name -notcontains $field) { throw "AdditionalInbound is missing '$field'." }
        }
        if ($extra.Name -notmatch '^[A-Za-z0-9_-]{1,40}$' -or $extra.Protocol -notin @('TCP','UDP') -or [string]::IsNullOrWhiteSpace($extra.Reason)) {
            throw 'Each additional allowance needs a simple name, TCP/UDP protocol and dependency reason.'
        }
        $extra.LocalPorts=@($extra.LocalPorts | ForEach-Object { ConvertTo-PvPPort ([string]$_) } | Sort-Object -Unique)
        $extra.RemoteAddresses=@($extra.RemoteAddresses | ForEach-Object { ConvertTo-PvPSource $_ } | Sort-Object -Unique)
        if (-not $extra.LocalPorts.Count -or -not $extra.RemoteAddresses.Count) { throw 'Additional allowances need ports and verified sources.' }
    }
    return $c
}
function Get-PvPNetworkFacts {
    $interfaces=@(Get-NetIPInterface -ErrorAction Stop | Where-Object {
        [string]$_.ConnectionState -eq 'Connected' -and $_.InterfaceAlias -notlike '*Loopback*'
    })
    return [pscustomobject]@{
        DhcpV4=[bool](@($interfaces | Where-Object { [string]$_.AddressFamily -eq 'IPv4' -and [string]$_.Dhcp -eq 'Enabled' }).Count)
        DhcpV6=[bool](@($interfaces | Where-Object { [string]$_.AddressFamily -eq 'IPv6' -and [string]$_.Dhcp -eq 'Enabled' }).Count)
        IPv6Enabled=[bool](@($interfaces | Where-Object { [string]$_.AddressFamily -eq 'IPv6' }).Count)
    }
}
function Get-PvPFirewallPlan {
    param($Config,$NetworkFacts)
    $entries=New-Object 'System.Collections.Generic.List[object]'
    function Add-Entry {
        param($Key,$Protocol,$LocalPort,$RemotePort,$RemoteAddress,$IcmpType='Any',$Service='Any',$Reason='')
        $entries.Add([pscustomobject][ordered]@{
            Key=$Key;Protocol=$Protocol;LocalPort=@($LocalPort);RemotePort=@($RemotePort)
            RemoteAddress=@($RemoteAddress | Sort-Object -Unique);IcmpType=@($IcmpType)
            Service=$Service;Reason=$Reason
        })
    }
    Add-Entry 'SMB' 'TCP' '445' 'Any' (@($Config.SmbClientSources)+@($Config.ScoringSources)) -Reason 'SMB clients and scoring'
    foreach ($port in $Config.ManagementTcpPorts) {
        Add-Entry "Management-$port" 'TCP' $port 'Any' $Config.ManagementSources -Reason 'Verified management access'
    }
    $v4=@($Config.PingSources | Where-Object {$_ -eq 'Any' -or $_ -notmatch ':'})
    $v6=@($Config.PingSources | Where-Object {$_ -eq 'Any' -or $_ -match ':'})
    if ($v4.Count) {Add-Entry 'Ping-v4' 'ICMPv4' 'Any' 'Any' $v4 '8' -Reason 'IPv4 echo request'}
    if ($NetworkFacts.IPv6Enabled -and $v6.Count) {Add-Entry 'Ping-v6' 'ICMPv6' 'Any' 'Any' $v6 '128' -Reason 'IPv6 echo request'}
    # Keep the control traffic needed for address configuration and path MTU.
    Add-Entry 'ICMPv4-errors' 'ICMPv4' 'Any' 'Any' 'Any' @('3','11') -Reason 'IPv4 errors and path MTU'
    if ($NetworkFacts.IPv6Enabled) {
        Add-Entry 'IPv6-neighbors' 'ICMPv6' 'Any' 'Any' 'LocalSubnet' @('133','134','135','136') -Reason 'IPv6 neighbor/router discovery'
        Add-Entry 'ICMPv6-errors' 'ICMPv6' 'Any' 'Any' 'Any' @('1','2','3','4') -Reason 'IPv6 errors and path MTU'
    }
    if ($NetworkFacts.DhcpV4) {Add-Entry 'DHCPv4-client' 'UDP' '68' '67' 'Any' -Service 'Dhcp' -Reason 'Detected DHCPv4 client'}
    if ($NetworkFacts.DhcpV6) {Add-Entry 'DHCPv6-client' 'UDP' '546' '547' 'Any' -Service 'Dhcp' -Reason 'Detected DHCPv6 client'}
    foreach ($extra in $Config.AdditionalInbound) {
        Add-Entry "Extra-$($extra.Name)" $extra.Protocol $extra.LocalPorts 'Any' $extra.RemoteAddresses -Reason $extra.Reason
    }
    $sha=[Security.Cryptography.SHA256]::Create()
    try {
        $json=$entries.ToArray() | ConvertTo-Json -Depth 10 -Compress
        $digest=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($json)))).Replace('-','').Substring(0,12)
    } finally {$sha.Dispose()}
    $plan=@(foreach ($e in $entries) {
        [pscustomobject]@{Name="SF-PvP-$digest-$($e.Key)";Spec=$e}
    })
    if (@($plan.Name | Sort-Object -Unique).Count -ne $plan.Count) {throw 'Duplicate additional allowance names.'}
    return $plan
}
function ConvertTo-PvPProtocol {
    param($Value)
    switch ([string]$Value) {'6' {'TCP'} '17' {'UDP'} '1' {'ICMPv4'} '58' {'ICMPv6'} '256' {'Any'} default {[string]$Value}}
}
function Get-PvPRuleCore {
    param($Rule)
    $p=$Rule | Get-NetFirewallPortFilter -ErrorAction Stop
    $a=$Rule | Get-NetFirewallAddressFilter -ErrorAction Stop
    $svc=$Rule | Get-NetFirewallServiceFilter -ErrorAction Stop
    $app=$Rule | Get-NetFirewallApplicationFilter -ErrorAction Stop
    $ifc=$Rule | Get-NetFirewallInterfaceFilter -ErrorAction Stop
    $ift=$Rule | Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop
    $security=$Rule | Get-NetFirewallSecurityFilter -ErrorAction Stop
    return [pscustomobject]@{
        Rule=$Rule;Protocol=(ConvertTo-PvPProtocol $p.Protocol)
        LocalPort=@($p.LocalPort | ForEach-Object {[string]$_} | Sort-Object)
        RemotePort=@($p.RemotePort | ForEach-Object {[string]$_} | Sort-Object)
        IcmpType=@($p.IcmpType | ForEach-Object {([string]$_) -replace ':\*$',''} | Sort-Object)
        RemoteAddress=@($a.RemoteAddress | ForEach-Object {
            if ($_ -in @('Any','LocalSubnet')) {[string]$_} else {ConvertTo-PvPSource $_}
        } | Sort-Object)
        LocalAddress=@($a.LocalAddress);Service=[string]$svc.Service;Program=[string]$app.Program
        Package=[string]$app.Package;InterfaceAlias=@($ifc.InterfaceAlias);InterfaceType=[string]$ift.InterfaceType
        Authentication=[string]$security.Authentication;Encryption=[string]$security.Encryption
        LocalUser=[string]$security.LocalUser;RemoteUser=[string]$security.RemoteUser;RemoteMachine=[string]$security.RemoteMachine
    }
}
function Assert-PvPPlannedRule {
    param($Rule,$Planned)
    $c=Get-PvPRuleCore $Rule;$s=$Planned.Spec
    if ([string]$Rule.Enabled -ne 'True' -or [string]$Rule.Direction -ne 'Inbound' -or [string]$Rule.Action -ne 'Allow' -or
        [string]$Rule.Profile -ne 'Any' -or $Rule.Group -ne 'Sunflower.PvP.RoleFirewall' -or $c.Protocol -ne $s.Protocol -or
        ($c.RemoteAddress -join ',') -ne (@($s.RemoteAddress | Sort-Object) -join ',') -or
        ($c.LocalAddress -join ',') -ne 'Any' -or $c.Service -ine $s.Service) {throw "Rule differs from plan: $($Planned.Name)"}
    if ($s.Protocol -in @('TCP','UDP')) {
        if (($c.LocalPort -join ',') -ne (@($s.LocalPort | Sort-Object) -join ',') -or
            ($c.RemotePort -join ',') -ne (@($s.RemotePort | Sort-Object) -join ',')) {throw "Port mismatch: $($Planned.Name)"}
    } elseif (($c.IcmpType -join ',') -ne (@($s.IcmpType | Sort-Object) -join ',')) {throw "ICMP mismatch: $($Planned.Name)"}
    foreach ($v in @($c.Program,$c.Package,$c.InterfaceType,$c.LocalUser,$c.RemoteUser,$c.RemoteMachine)+@($c.InterfaceAlias)) {
        if (-not [string]::IsNullOrWhiteSpace($v) -and $v -ne 'Any') {throw "Unexpected extra filter: $($Planned.Name)"}
    }
    if ($c.Authentication -notin @('NotRequired','NotConfigured') -or $c.Encryption -notin @('NotRequired','NotConfigured')) {
        throw "Unexpected IPsec requirement: $($Planned.Name)"
    }
}
function New-PvPPlannedRule {
    param($Planned)
    $s=$Planned.Spec
    $params=@{
        PolicyStore='PersistentStore';Name=$Planned.Name
        DisplayName="Sunflower: $($s.Key)";Group='Sunflower.PvP.RoleFirewall'
        Description=$s.Reason;Direction='Inbound';Action='Allow';Enabled='True';Profile='Any'
        Protocol=$s.Protocol;RemoteAddress=$s.RemoteAddress;Service=$s.Service;ErrorAction='Stop'
    }
    if ($s.Protocol -in @('TCP','UDP')) {$params.LocalPort=$s.LocalPort;$params.RemotePort=$s.RemotePort}
    else {$params.IcmpType=$s.IcmpType}
    New-NetFirewallRule @params | Out-Null
}
function Assert-PvPPolicyReady {
    param($Config,$Plan,[switch]$ForLockdown)
    foreach ($service in Get-Service -Name MpsSvc,BFE -ErrorAction Stop) {
        if ([string]$service.Status -ne 'Running') {throw "Firewall dependency not running: $($service.Name)"}
    }
    $profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
    if ($profiles.Count -ne 3 -or @('Domain','Private','Public' | Where-Object {$_ -notin @($profiles.Name)}).Count) {
        throw 'Could not verify all three effective firewall profiles.'
    }
    foreach ($p in $profiles) {
        if ([string]$p.AllowLocalFirewallRules -eq 'False' -or [string]$p.AllowInboundRules -eq 'False') {
            throw "Group Policy/profile '$($p.Name)' prevents local inbound allowances."
        }
    }
    $active=@(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Inbound -ErrorAction Stop)
    foreach ($block in @($active | Where-Object {[string]$_.Action -eq 'Block'})) {
        $port=$block | Get-NetFirewallPortFilter
        $address=$block | Get-NetFirewallAddressFilter
        $proto=ConvertTo-PvPProtocol $port.Protocol
        $relevant=$false
        foreach ($entry in $Plan) {
            if ($proto -ne 'Any' -and $proto -ne $entry.Spec.Protocol) {continue}
            $portOverlap=$proto -in @('Any','ICMPv4','ICMPv6')
            if (-not $portOverlap) {
                foreach ($left in @($port.LocalPort)) {foreach ($right in $entry.Spec.LocalPort) {
                    if (Test-PvPPortOverlap $left $right) {$portOverlap=$true}
                }}
            }
            if (-not $portOverlap) {continue}
            foreach ($left in @($address.RemoteAddress)) {foreach ($right in $entry.Spec.RemoteAddress) {
                if (Test-PvPSourceOverlap $left $right) {$relevant=$true}
            }}
        }
        if ($relevant -and $block.Name -notin @($Config.ReviewedInboundBlockRuleNames)) {
            throw "Existing block may affect a required flow: '$($block.Name)'. Inspect its filters; fix it or explicitly record its review in configuration."
        }
    }
    if ($ForLockdown) {
        $local=@(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop)
        $keep=@($Plan | ForEach-Object {$_.Name})+@($Config.PreserveInboundRuleNames)
        foreach ($name in $Config.PreserveInboundRuleNames) {
            if (-not @($active | Where-Object {$_.Name -eq $name -and [string]$_.Action -eq 'Allow'}).Count) {throw "Preserved rule is not an enabled inbound allow: $name"}
        }
        foreach ($r in @($active | Where-Object {[string]$_.Action -eq 'Allow' -and $_.Name -notin $keep})) {
            if ([string]$r.PolicyStoreSourceType -ne 'Local' -or $r.Name -notin @($local | ForEach-Object {$_.Name})) {
                throw "Unapproved non-local/GPO inbound allow cannot be closed locally: $($r.Name)"
            }
        }
        foreach ($entry in $Plan) {
            $match=@($active | Where-Object Name -eq $entry.Name)
            if ($match.Count -ne 1 -or [string]$match[0].PolicyStoreSourceType -ne 'Local') {throw "Stage the planned local rule first: $($entry.Name)"}
            Assert-PvPPlannedRule $match[0] $entry
        }
        # Existing remote admin sessions must fit the declared replacement rules.
        foreach ($conn in @(Get-NetTCPConnection -ErrorAction Stop | Where-Object {
            [string]$_.State -eq 'Established' -and $_.LocalPort -in @(22,3389,5985,5986)
        })) {
            $covered=$false
            foreach ($entry in $Plan) {
                if ($entry.Spec.Protocol -ne 'TCP') {continue}
                foreach ($port in $entry.Spec.LocalPort) {foreach ($source in $entry.Spec.RemoteAddress) {
                    if ((Test-PvPPortOverlap ([string]$conn.LocalPort) $port) -and
                        (Test-PvPSourceOverlap ($conn.RemoteAddress -replace '%\d+$','') $source)) {$covered=$true}
                }}
            }
            if (-not $covered) {throw "Current management peer is not covered: $($conn.RemoteAddress):$($conn.LocalPort). Correct the config before lockdown."}
        }
    }
}
function New-PvPFirewallBackup {
    param([string]$Purpose)
    $root=Initialize-DefenseStore
    $folder=Join-Path $root ("pvp-$Purpose-"+(Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $folder -ErrorAction Stop | Out-Null
    $file=Join-Path $folder 'firewall-before.wfw'
    $output=& "$env:SystemRoot\System32\netsh.exe" advfirewall export $file 2>&1
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $file)) {throw "Firewall export failed: $($output -join ' ')"}
    if ((Get-Item -LiteralPath $file).Length -lt 1) {throw 'Firewall export is empty.'}
    Get-NetFirewallProfile -PolicyStore PersistentStore | Export-Clixml -LiteralPath (Join-Path $folder 'profiles-before.xml')
    Get-NetFirewallRule -PolicyStore PersistentStore | Export-Clixml -LiteralPath (Join-Path $folder 'rules-before.xml')
    return $folder
}
function Invoke-PvPTransactionStep {
    param([string]$StateFile,[string[]]$ExpectedStatus,[scriptblock]$Action)
    $folder=Split-Path -Parent $StateFile
    $handle=$null;$until=[DateTime]::UtcNow.AddSeconds(30)
    while (-not $handle -and [DateTime]::UtcNow -lt $until) {
        try {$handle=[IO.File]::Open((Join-Path $folder 'state.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)}
        catch [IO.IOException] {Start-Sleep -Milliseconds 200}
    }
    if (-not $handle) {throw 'Firewall transaction is busy; use console recovery if necessary.'}
    try {
        $record=Get-Content -LiteralPath $StateFile -Raw -ErrorAction Stop | ConvertFrom-Json
        if ($record.Status -notin $ExpectedStatus) {throw "Transaction state changed to '$($record.Status)'; stop."}
        & $Action $record | Out-Host
        $temp=Join-Path $folder 'state-write.tmp'
        $record | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath $temp -Encoding UTF8 -ErrorAction Stop
        Move-Item -LiteralPath $temp -Destination $StateFile -Force -ErrorAction Stop
    } finally {$handle.Dispose()}
}
function Get-PvPTransaction {
    param([string]$StateFile)
    $root=[IO.Path]::GetFullPath((Join-Path $env:ProgramData 'SunflowerDefense'))+[IO.Path]::DirectorySeparatorChar
    $file=Get-Item -LiteralPath $StateFile -Force -ErrorAction Stop
    if ($file.PSIsContainer -or $file.Length -gt 2097152 -or
        -not $file.FullName.StartsWith($root,[StringComparison]::OrdinalIgnoreCase)) {throw 'Use the original private transaction state file.'}
    $p=$file
    while ($p -and $p.FullName.StartsWith($root.TrimEnd('\'),[StringComparison]::OrdinalIgnoreCase)) {
        if ($p.Attributes -band [IO.FileAttributes]::ReparsePoint) {throw 'Redirected state paths are refused.'}
        $p=if($p -is [IO.DirectoryInfo]){$p.Parent}else{$p.Directory}
    }
    $state=Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
    if ($state.SchemaVersion -ne 2 -or $state.ComputerName -ine $env:COMPUTERNAME -or
        $state.MachineGuid -ne (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid) {throw 'Wrong host or unsupported state.'}
    $worker=Join-Path $file.DirectoryName 'recovery-worker.ps1'
    $w=Get-Item -LiteralPath $worker -Force
    if ($w.Attributes -band [IO.FileAttributes]::ReparsePoint -or
        (Get-FileHash -LiteralPath $worker -Algorithm SHA256).Hash -ne $state.WorkerSHA256) {throw 'Recovery worker changed after capture.'}
    return [pscustomobject]@{State=$state;StateFile=$file.FullName;Worker=$worker}
}
function Assert-PvPLockdownEffective {
    param($Plan,[string[]]$KeepRuleNames)
    $profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
    if ($profiles.Count -ne 3 -or @('Domain','Private','Public' | Where-Object {$_ -notin @($profiles.Name)}).Count) {
        throw 'Could not verify all three effective firewall profiles.'
    }
    if (@($profiles | Where-Object {[string]$_.Enabled -ne 'True' -or [string]$_.DefaultInboundAction -ne 'Block'}).Count) {
        throw 'Effective firewall profiles are not all enabled with default inbound Block.'
    }
    $rules=@(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Inbound -Enabled True -Action Allow -ErrorAction Stop)
    $extra=@($rules | Where-Object {$_.Name -notin $KeepRuleNames})
    if ($extra.Count) {throw "Unexpected effective inbound allowance(s): $($extra.Name -join ', ')"}
    foreach ($entry in $Plan) {
        $match=@($rules | Where-Object Name -eq $entry.Name)
        if ($match.Count -ne 1) {throw "Missing/ambiguous effective allowance: $($entry.Name)"}
        Assert-PvPPlannedRule $match[0] $entry
    }
}
Export-ModuleMember -Function *-PvP*

