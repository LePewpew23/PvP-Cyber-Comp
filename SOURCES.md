# Sources and implementation references

Prepared 2026-11-14. These references guide the design; they do not certify the scripts or establish the server's current configuration.

## Competition context

- User-supplied **PvP (2026) – Briefing Packet.pdf**: Sunflower's Server 2019/SMB role, four authorized human users, addressing pattern, flags, no-access grace period and excluded router/Kali targets. The packet leaves the final team range and actual scoring-source/share details unspecified.
- [Intro to PvP Lab slides](https://docs.google.com/presentation/d/1JFomBwkCGBemC9OmnHa2ZABhsR3fGzMQLbxHE2TifzE/edit?usp=sharing): read through the deck's public text export; used its Quotient/PCR, inventory, dependency and host-firewall overview. The layout/images were not reviewed.
- [Swift-Poly-scripts repository](https://github.com/tydominicmontgomery-creator/Swift-Poly-scripts): read-only review of the existing CentOS runbook and numbered scripts informed the new folder/runbook structure.
- Prior **Sunflower_SMB_Hardening.zip**: original password script and shared helpers retained; original controls reused behind staged wrappers.

## Microsoft references

- [Windows Firewall overview](https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall): profile/default-action behavior.
- [Firewall rule precedence](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules): explicit blocks and rule evaluation.
- [Firewall configuration, including ICMP](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/configure).
- [Secure SMB traffic](https://learn.microsoft.com/windows-server/storage/file-server/smb-secure-traffic): modern direct-hosted SMB uses TCP 445. Newer-version defaults must not be assumed on Server 2019.
- [Windows services and network ports](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements): service dependencies.
- [netsh advfirewall](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-advfirewall): local firewall export/import.
- [New-NetFirewallRule, Server 2019](https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule?view=windowsserver2019-ps).
- [New-ScheduledTaskSettingsSet](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtasksettingsset): recovery task settings.
- [Detect/enable/disable SMB versions](https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3).
- [Disable-WindowsOptionalFeature](https://learn.microsoft.com/en-us/powershell/module/dism/disable-windowsoptionalfeature): servicing and restart handling.
- [Set-SmbServerConfiguration, Server 2019](https://learn.microsoft.com/en-us/powershell/module/smbshare/set-smbserverconfiguration?view=windowsserver2019-ps).
- [Share access](https://learn.microsoft.com/en-us/powershell/module/smbshare/grant-smbshareaccess) and [revoking allow entries](https://learn.microsoft.com/en-us/powershell/module/smbshare/revoke-smbshareaccess?view=windowsserver2019-ps).
- [Auditpol](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol) and [subcategory constants](https://learn.microsoft.com/en-us/windows/win32/secauthz/auditing-constants).
- [Set-LocalUser](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/set-localuser?view=powershell-5.1) and [Remove-LocalUser](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/remove-localuser?view=powershell-5.1).
- [RDP NLA method](https://learn.microsoft.com/en-us/windows/win32/termserv/setuserauthenticationrequired-win32-tsgeneralsetting).
- [Defender real-time protection](https://learn.microsoft.com/en-us/defender-endpoint/configure-real-time-protection-microsoft-defender-antivirus).

## Nmap references

- [smb-protocols](https://nmap.org/nsedoc/scripts/smb-protocols.html).
- [smb2-security-mode](https://nmap.org/nsedoc/scripts/smb2-security-mode.html).
- [smb2-capabilities](https://nmap.org/nsedoc/scripts/smb2-capabilities.html).
- [smb-vuln-ms17-010](https://nmap.org/nsedoc/scripts/smb-vuln-ms17-010.html).

The runner selects these individual scripts; it does not execute all scripts in a category. Nmap's “safe” categorization does not guarantee zero impact on every service. Preview defaults, scope validation, rate/time limits, evidence handling and rollback guards are choices made for this package.
