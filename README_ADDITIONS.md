# Swift-Poly scripts: Windows SMB hardening and enumeration

These additions follow the repository's numbered backup → host hardening → firewall staging → firewall lockdown → service hardening workflow.

| Folder | Run on | Start here |
|---|---|---|
| `scripts/windowsHardening` | Sunflower, Windows Server 2019 | [Windows runbook](scripts/windowsHardening/README.md) |
| `scripts/redTeamEnumeration` | Designated competition Kali, after grace ends | [Enumeration runbook](scripts/redTeamEnumeration/README.md) |

Copy these two folders into the existing repository's `scripts` folder. Keep the existing CentOS files and root README. Add links to the two runbooks in the root README if desired. The GitHub connection was read-only, so this package has not been pushed to the repository.

Windows changes preview by default. Firewall configuration deliberately has empty scorer/client/management source lists: the supplied packet does not identify those addresses. Enter verified addresses before staging. The existing `12-Change-LocalPasswords.ps1` is preserved byte for byte, including its masked prompts and four-user restriction.

The red-team folder provides bounded service discovery, SMB configuration checks, an optional specific MS17-010 probe, and offline findings reports. It requires explicit final scope, exact target hosts, the end of the grace period, and Kali for live runs.

Read [VALIDATION.md](VALIDATION.md) for what was tested and [SOURCES.md](SOURCES.md) for references. No hardening was applied to your server and no competition systems were scanned while preparing this package.
