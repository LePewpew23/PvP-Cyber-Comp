# Sunflower Windows SMB hardening

This runbook is for **sunflower**, Windows Server **2019**, build **17763**, using **64-bit Windows PowerShell 5.1 as Administrator**. The scripts refuse other Windows builds and domain controllers. Sunflower is `sunflower.misty.view`, internal `192.168.1.51`, team-facing `172.16.XX.51`. Verify your actual team address.

The goal is to keep the scored SMB service available while restricting inbound access to its users, scoring clients, management, ping and required network functions. The firewall restricts reachability; it does not uninstall services or make every listening socket disappear. A passing ping alone does not prove that a scorer can authenticate and access its required file.

## What each file does

| File | Purpose | Change trigger |
|---|---|---|
| `00_backup.ps1` | Inventory and private configuration baseline | `-Save` writes a baseline |
| `01_windows_hardening.ps1` | Inspect host, enable Defender, require RDP NLA, or configure auditing | Select one control and `-Apply` |
| `02_firewall_initial.ps1` | Add explicit SMB, management, ping and network allowances | `-Apply` |
| `03_firewall_lockdown.ps1` | Disable other local inbound allow rules; enable default-deny inbound; arm timed recovery | `-Apply -ConsoleRecoveryAvailable` |
| `04_smb_hardening.ps1` | Inspect SMB, disable SMB1, require signing, change one share permission, or require share encryption | Select one control and `-Apply` |
| `05_verify.ps1` | Inspect local state and commit a remotely verified firewall change | `-Commit -RemoteChecksPassed -StateFile …` |
| `06_restore_firewall.ps1` | Restore the entire local policy saved immediately before lockdown | `-Apply -StateFile …` |
| `10-Restore-Change.ps1` | Restore a supported individual change made by the original modules | Follow the printed `change.json` record |
| `11-Block-RemoteIPs.ps1` | Block verified exact remote IPs; no scanning | `-Apply` |
| `12-Change-LocalPasswords.ps1` | Original password script, unchanged | `-Apply` and hidden prompts |
| `13-Remove-UnapprovedLocalUsers.ps1` | Show account decisions; optionally delete listed unprotected candidates | `-Apply` |
| `Test-SmbFromClient.ps1` | Fresh authenticated read of a known file from another Windows client | Run from that client |
| `Test-ToolkitSyntax.ps1` | Parse all PowerShell files without executing changes | Read-only |

`Modules` contains the retained individual controls. `Lib` contains shared helpers and the recovery worker. Use the numbered top-level runbook for the new firewall workflow; do not mix it with the older firewall-scope/profile modules.

## 1. Establish the baseline

Review the downloaded code, extract the whole folder, and open Windows PowerShell as Administrator. If your execution policy blocks the files, follow your team's approved script-signing/unblocking process. The scripts do not bypass execution policy.

```powershell
cd C:\Competition\scripts\windowsHardening
.\Test-ToolkitSyntax.ps1
.\00_backup.ps1
.\00_backup.ps1 -Save
.\01_windows_hardening.ps1
.\04_smb_hardening.ps1
```

The baseline is stored under `C:\ProgramData\SunflowerDefense` with access restricted to Administrators and SYSTEM. It contains firewall policy, SMB configuration, share access and account metadata. It is **not** a recoverable backup of passwords, user SIDs, data, NTFS ACLs or the whole machine.

Record the actual data share, scored identity and authority (local versus domain), required file/path and operation, client/scorer source IPs as seen by Sunflower, and your management path. Keep `C:\Windows\flag.txt` and other competition files untouched. The scripts do not remove flags or recursively rewrite NTFS ACLs.

**Tip:** Review running services and scheduled tasks for unexpected executable paths and accounts. An unfamiliar task is a review item; it may be a scoring or application dependency. Check Windows updates and Defender health, then schedule patches/reboots with the team instead of restarting during a scored operation.

## 2. Fill the firewall configuration

```powershell
Copy-Item .\config\firewall.example.json .\config\firewall.json
notepad .\config\firewall.json
```

| Field | Enter |
|---|---|
| `SmbClientSources` | Verified legitimate SMB client IPs/CIDRs |
| `ScoringSources` | Verified source IPs/CIDRs used by the scorer, including any NAT address actually seen by the server |
| `ManagementSources` | Your admin workstation/jump-host addresses |
| `ManagementTcpPorts` | Required inbound admin ports; the example starts with TCP 3389 for RDP |
| `ConsoleOnlyManagement` | `true` only if you use console access exclusively; then empty both management arrays |
| `PingSources` | `["Any"]` permits echo requests from any routed source; use verified IPs/CIDRs to narrow it |
| `AdditionalInbound` | Other confirmed inbound dependencies, with a reason for each |
| `PreserveInboundRuleNames` | Exact existing rule **Names** you intentionally retain after reviewing every filter |
| `ReviewedInboundBlockRuleNames` | Exact block rule Names you inspected and accepted despite a potential overlap |

Do not invent the scoring IP or use the entire competition network as a shortcut. Both client and scorer arrays are required; they can contain the same verified address if appropriate. Address lists support literal IPv4/IPv6 and CIDRs. Hostnames, wildcards and `Any` are rejected for SMB/management sources.

Use the live connection list as supporting evidence, not proof of the scorer's identity:

```powershell
Get-SmbSession | Select-Object ClientComputerName,ClientUserName,Dialect
Get-NetTCPConnection -State Established |
    Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort
Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Inbound |
    Select-Object Name,DisplayName,Action,PolicyStoreSourceType
```

Confirm the scorer's details through Quotient/organizer documentation. If the scorer also checks HTTP, WinRM or another listener, add that exact dependency before lockdown. Domain authentication, DNS, time and management dependencies still matter even when they are not scored.

Example shape for an **additional dependency**, using documentation-only values:

```json
{
  "Name": "VerifiedScoringAgent",
  "Protocol": "TCP",
  "LocalPorts": ["8443"],
  "RemoteAddresses": ["192.0.2.25"],
  "Reason": "Replace with the verified scorer requirement"
}
```

Place such an object inside `AdditionalInbound` only when the dependency exists, replacing both the port and source. No additional dependency is enabled by default.

**Tip:** A preserved rule can be broad. Keeping an existing “allow all” rule defeats the purpose of lockdown. Existing explicit block rules can override the new allowances; recording that you reviewed a block does **not** remove its effect.

## 3. Understand the port policy

| Traffic | New policy | Why |
|---|---|---|
| TCP 445 inbound | SMB clients plus scoring sources | Modern SMB2/3 file access |
| TCP management ports | Your configured admin sources | Retain your selected remote administration path |
| ICMPv4 echo request, type 8 | `PingSources` | Device can answer ping; ICMP has no TCP/UDP port |
| ICMPv6 echo request, type 128 | `PingSources` when IPv6 is active | IPv6 ping |
| ICMP error/path-MTU messages | Selected v4/v6 types | Network error and packet-size handling |
| IPv6 neighbor/router discovery | Selected types from local subnet | Keep active IPv6 functioning |
| UDP 68 from UDP 67 | Added when DHCPv4 is detected, restricted to DHCP service | Address renewal |
| UDP 546 from UDP 547 | Added when DHCPv6 is detected, restricted to DHCP service | IPv6 address configuration |
| Confirmed additional inbound dependencies | Explicit configured ports and sources | Actual application/scoring needs |
| Other local inbound allow rules | Disabled unless explicitly preserved | Reduce exposed services |
| Outbound policy, rules and stateful return traffic | Existing outbound policy retained | Avoid cutting off DNS, authentication, updates and other dependencies without an inventory |

TCP 139 and UDP 137/138 are not opened by the new plan: direct-hosted SMB2/3 uses TCP 445. Test whether your environment actually depends on legacy NetBIOS before removing its reachability. RDP UDP 3389 is not enabled by default; RDP over the configured TCP port remains the intended management path.

A listening service may remain visible locally after its inbound allowance is disabled. A blocked port may appear **filtered** from a remote client rather than **closed**. The intended result is restricted remote access.

## 4. Stage, lock down, verify, commit

First preview and stage the explicit allow rules. Staging does not disable existing rules or enable a currently disabled firewall.

```powershell
.\02_firewall_initial.ps1
.\02_firewall_initial.ps1 -Apply
.\03_firewall_lockdown.ps1
```

Read the KEEP and DISABLE lists. Verify a working hypervisor/physical console and coordinate an exclusive firewall-change window. Then apply:

```powershell
.\03_firewall_lockdown.ps1 -Apply -ConsoleRecoveryAvailable
```

The script saves the current local policy, tests a scheduled SYSTEM recovery worker, and arms a **10-minute rollback** before restricting access. It refuses unreviewed overlapping blocks, unapproved non-local/GPO allows, local-rule merging restrictions, altered staged rules, and uncovered observed RDP/WinRM/SSH management peers.

It disables other local inbound Allow rules and enables Domain/Private/Public profiles with default inbound Block. It does not change outbound defaults or remove existing blocks. You can select `-RollbackMinutes 15` when you need more test time; the supported range is 5–30 minutes.

While the timer is active, use a **separate authorized client and fresh login**:

1. Ping the actual address/FQDN used in the competition.
2. Open a new management session through your intended path.
3. Authenticate as the scored user and read the exact expected share/file.
4. Test any required write operation on the team's designated test file.
5. Confirm passing Quotient checks and any dependency checks.

Example from the permitted Windows client; replace the two file/share values:

```powershell
Test-Connection sunflower.misty.view -Count 2
Test-NetConnection sunflower.misty.view -Port 445
.\Test-SmbFromClient.ps1 -Server sunflower.misty.view -ShareName 'ACTUAL_SHARE' -RelativeFile 'ACTUAL_REQUIRED_FILE'
```

That helper performs a read only, hashes the file without printing its contents and removes its own temporary PSDrive. It does not prove write access. Cached connections can mask bad passwords or compatibility issues, so use a fresh client sign-in.

After every required check passes, copy the **exact state path printed by 03**:

```powershell
.\05_verify.ps1 -StateFile 'C:\ProgramData\SunflowerDefense\pvp-lockdown-...\state.json'
.\05_verify.ps1 -StateFile 'C:\ProgramData\SunflowerDefense\pvp-lockdown-...\state.json' -Commit -RemoteChecksPassed
```

The `...` above is a placeholder, not a real directory. Inspection alone does not cancel rollback. `-RemoteChecksPassed` is your confirmation of the real remote tests; the script cannot observe Quotient.

**Recovery:** If access breaks, do not commit. The task attempts to restore the **complete local firewall snapshot from immediately before lockdown**, including the staged rules. From the console you can restore sooner:

```powershell
.\06_restore_firewall.ps1 -StateFile 'ACTUAL_STATE_PATH'
.\06_restore_firewall.ps1 -StateFile 'ACTUAL_STATE_PATH' -Apply
```

Manual restore also works after a commit. It replaces later local firewall edits, including new blocks. Domain Group Policy is not replaced. Do not delete the private transaction folder. If Task Scheduler or the worker cannot run, console recovery is still necessary; a timer cannot guarantee recovery on a broken/offline host.

Last-resort console command, using the verified original backup file:

```powershell
netsh advfirewall import "C:\ProgramData\SunflowerDefense\ACTUAL_TRANSACTION_FOLDER\firewall-before.wfw"
```

## 5. Apply SMB and Windows controls one at a time

Run each command without `-Apply` first. Then apply just that control and recheck the actual scored operation.

```powershell
.\04_smb_hardening.ps1 -Control SMB1
.\04_smb_hardening.ps1 -Control SMB1 -Apply
.\04_smb_hardening.ps1 -Control Signing
.\04_smb_hardening.ps1 -Control Signing -Apply

.\01_windows_hardening.ps1 -Control Defender
.\01_windows_hardening.ps1 -Control Defender -Apply
.\01_windows_hardening.ps1 -Control Auditing
.\01_windows_hardening.ps1 -Control Auditing -Apply
```

The SMB1 module preserves your original two commands. It does not disable SMB2/3. `-NoRestart` prevents an automatic reboot but does not guarantee the servicing change is complete; inspect pending/restart state and coordinate any reboot.

Signing protects SMB message integrity. Encryption also protects contents but needs compatible SMB3 clients. Encryption is an optional per-share step, not an automatic default:

```powershell
.\04_smb_hardening.ps1 -Control SharePermissions -ShareName 'ACTUAL_SHARE'
.\04_smb_hardening.ps1 -Control SharePermissions -ShareName 'ACTUAL_SHARE' -Action SetAllow -Principal 'sunflower\jalapeno' -AccessRight Read
.\04_smb_hardening.ps1 -Control Encryption -ShareName 'ACTUAL_SHARE'
```

Those examples preview only. Choose the right actually needed by the scored user; a write check needs more than Read. Share permissions and NTFS permissions both affect access. The permission module changes one selected principal's Allow entries, preserving other principals, Deny entries, NTFS ACLs and file contents. Encryption enforcement also sets server-wide `RejectUnencryptedAccess`, affecting all encryption-required shares.

For RDP NLA, first verify compatible clients and console recovery:

```powershell
.\01_windows_hardening.ps1 -Control RdpNla
.\01_windows_hardening.ps1 -Control RdpNla -Apply
```

**Tip:** Watch Security events 4624/4625 (logons), 4720 (user creation), 4732 (local group membership), 4719 (audit changes) and 5140 (share access), plus SMBServer/Audit 3000 for SMB1 use when enabled. An absence of events does not prove an absence of attacks. Detailed file events require additional auditing/SACL configuration.

## 6. Keep the original password script

`12-Change-LocalPasswords.ps1` is unchanged. It resets **only** these local human users:

- `Administrator`
- `jalapeno`
- `coffeebean`
- `pepperpult`

It never embeds a default password. For the shared password you previously selected, enter it twice in the masked prompts:

```powershell
.\12-Change-LocalPasswords.ps1 -SamePasswordForAll -MinimumLength 13
.\12-Change-LocalPasswords.ps1 -SamePasswordForAll -MinimumLength 13 -Apply
```

The first line previews; the second changes the selected accounts. `-MinimumLength 13` permits your chosen length but does not weaken Windows' own password policy. Without `-SamePasswordForAll`, the script prompts separately for each user. You can target a subset with `-UserName 'jalapeno'`.

Coordinate each scored-user reset with the required **PCR in Quotient** and update legitimate consumers. Password resets are not rolled back by the firewall timer or change-restoration script. Administrative resets can affect EFS/DPAPI-protected material.

Review accounts separately:

```powershell
.\13-Remove-UnapprovedLocalUsers.ps1
```

It prints account names, SIDs, authorization status, KEEP/DELETE candidate decisions and reasons. `-Apply` deletes the listed unprotected candidates and prints `DELETED: name (SID)`, with a private outcome report. It retains the four authorized names, built-in accounts, your current operator, and detected service/task dependencies for review. A protected unknown account is not automatically legitimate. Investigate its purpose before removing its dependencies.

**Tip:** Deleting an account is permanent for that SID/password identity. Metadata is evidence, not a restorable account backup. This script does not delete profiles or flag files.

## 7. Optional exact-IP blocks

Use the retained IP-block module only for **verified** attacker/Kali addresses. Do not discover Kali by scanning it; Kali and routers are outside the target scope. Protect scorer, client, DNS/authentication and management addresses, especially shared NAT addresses.

```powershell
$blocked = Read-Host 'Verified attacker IP to block'
$protected = (Read-Host 'Exact scorer/admin/client IPs, comma separated').Split(',').Trim()
.\11-Block-RemoteIPs.ps1 -RemoteAddress $blocked -ProtectedAddress $protected -Traffic SMB
.\11-Block-RemoteIPs.ps1 -RemoteAddress $blocked -ProtectedAddress $protected -Traffic SMB -Apply
```

`-Traffic SMB` blocks inbound TCP 445 from those addresses. The module's default `-Traffic All` blocks every inbound protocol, **including ping from the blocked address**. `-Direction Both` additionally blocks outbound traffic to it; use only after checking dependencies. CIDRs and automatic target discovery are intentionally unsupported.

An explicit block normally overrides an allow. Do not add blocks while a lockdown transaction is pending: first finish its validation/commit, then add and verify blocks as a separate change. Use the printed `change.json` with `10-Restore-Change.ps1` to remove blocks created by that action.

## Troubleshooting and limits

| Symptom | Check |
|---|---|
| Ping works but scoring fails | Credentials/PCR, exact share/file, read versus write, NTFS/share ACLs, signing/encryption compatibility |
| SMB works internally but scorer fails | Actual routed/NAT source, firewall profile, route and scoreboard check details |
| Old admin session works but new one fails | Correct source/port and fresh authentication; existing sessions are not sufficient validation |
| Stage/lockdown refuses a GPO rule | Review the owning domain policy; local scripts cannot reliably override it |
| Firewall state reverts after ten minutes | Validation was not committed, or failed; read the private state and recheck configuration |
| New IP block breaks ping | All-protocol block includes ICMP; inspect scope and whether SMB-only blocking fits the requirement |

The toolkit is a controlled set of changes and inspections, not a full vulnerability scanner or assurance that Sunflower is secure. Server-specific scored dependencies remain an on-host verification step.
