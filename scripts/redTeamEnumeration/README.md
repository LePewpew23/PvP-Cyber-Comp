# Competition enumeration from Kali

Use this folder on the **designated competition Kali machine**, after the organizer ends the no-access grace period. It inventories other authorized teams' services and flags selected SMB weaknesses for verification. It does not change the target's files, accounts, firewall or service configuration.

## Scope comes first

The supplied PvP briefing permits competition host addresses **172.16.XX.50–54**. It excludes routers and Kali targets, and prohibits accessing/viewing other teams during the initial **30-minute grace period**. The final authorized team-number range is not specified in the supplied packet, so this package does not guess it.

Copy the template and fill it from the final organizer instructions:

```bash
cp scope.example.json scope.json
nano scope.json
```

| Setting | Meaning |
|---|---|
| `own_team_id` | Your team's third IPv4 octet, as an integer |
| `authorized_team_ids` | Other team IDs explicitly authorized by the final rules |
| `authorization_reference` | The rule/organizer notice establishing that scope |

The example is deliberately incomplete and cannot scan. The runner rejects your own team, unlisted teams, routers (`.1`), Kali (`.2`), addresses outside the five host addresses, DNS names, CIDRs, IP ranges and more than 20 targets per run. You must independently verify that the machine you run from is the designated Kali and that the final rules still permit the activity.

## Quick overview from the slides

The linked *Intro to PvP Lab* deck presents this sequence: understand Quotient checks, inventory users and services, map dependencies, then harden and investigate weaknesses. Scoring can depend on a particular login or file; a successful ping is not the whole check. The deck also explains password-change requests and why host firewall rules must account for where traffic originates.

For enumeration, use observations from your own authorized environment to guide **specific checks** on authorized opponent hosts. Collect evidence before deciding a weakness exists. These tools cover discovery and vulnerability triage; later attacking topics in the deck are outside this folder's implementation.

## 1. Preview service discovery

Requires Python **3.10+** and Nmap on Kali. Preview does not need Nmap installed and sends no traffic. There is no pip dependency.

```bash
read -r -p "One exact authorized target IP: " target_ip
python3 01_enumerate.py --scope scope.json --targets "$target_ip" --profile services
```

The default TCP ports cover common file, web, management, authentication and database services:

`21,22,53,80,88,135,139,389,443,445,636,1433,3306,3389,5432,5985,5986,8000,8080,8443`

You can supply up to 32 individual TCP ports:

```bash
python3 01_enumerate.py --scope scope.json --targets "$target_ip" --profile services --ports 22,80,443,445
```

Read the printed command and verify scope. Once the organizer has ended grace:

```bash
python3 01_enumerate.py --scope scope.json --targets "$target_ip" --profile services --run --grace-period-ended
```

The runner uses TCP connects, light version detection, one host at a time, bounded retries and timeouts. It skips DNS resolution and host discovery, so a filtered ping does not automatically exclude a host from testing. Port probes use a 40-per-second cap; NSE/version negotiations have their own protocol exchanges, so this is not a guaranteed total traffic cap.

There is no broad subnet scan, arbitrary Nmap argument passthrough, credential guessing, exploit, denial-of-service or persistence module. These are still active probes that may appear in logs and affect fragile services; stop if the organizer or observed service health requires it.

**Tip:** An open port identifies an exposed service. A version string may be incomplete, misleading or patched by a vendor without a major version change. Check the exact build and advisory before calling it vulnerable.

## 2. Inspect SMB configuration

```bash
python3 01_enumerate.py --scope scope.json --targets "$target_ip" --profile smb
python3 01_enumerate.py --scope scope.json --targets "$target_ip" --profile smb --run --grace-period-ended
```

This profile uses TCP **445** and only these named NSE scripts:

| Check | What it can establish | Limit |
|---|---|---|
| `smb-protocols` | Advertised SMB dialects, including legacy SMB1 when accepted | Does not prove a particular remote-code-execution vulnerability |
| `smb2-security-mode` | Whether signing is required for tested SMB2/3 dialects | Authentication/relay risk still depends on other conditions |
| `smb2-capabilities` | Advertised SMB2/3 capabilities | A capability is not proof that every share requires encryption |

Optional targeted MS17-010 probe:

```bash
python3 01_enumerate.py --scope scope.json --targets "$target_ip" --profile smb --check-ms17-010
python3 01_enumerate.py --scope scope.json --targets "$target_ip" --profile smb --check-ms17-010 --run --grace-period-ended
```

This adds `smb-vuln-ms17-010`, a specific detection probe rather than an exploit. It is especially relevant when investigating a potentially affected older SMB implementation; do not assume it applies to Server 2019 simply because TCP 445 is open. Verify any positive result against the precise OS/build and updates. A negative/inconclusive result does not establish overall security.

**Tip:** Start with configuration observations such as SMB1 availability or optional signing. Treat probe errors, missing script output and timeouts as unassessed checks, not successful security tests.

## 3. Review evidence offline

Each live run gets a new private folder under `reports` containing native Nmap `.xml`, `.nmap` and `.gnmap` files, runner logs and a manifest recording target scope and commands. Passwords are neither requested nor placed on command lines.

Point the offline reviewer at the actual XML paths printed by the run:

```bash
python3 02_review_findings.py reports/ACTUAL_RUN/ACTUAL_TARGET.xml
python3 02_review_findings.py reports/ACTUAL_RUN/ACTUAL_TARGET.xml --output reports/ACTUAL_RUN/findings.md
```

Replace the `ACTUAL_*` placeholders. Multiple XML files can be supplied, up to 20 per invocation. Existing report files are not overwritten.

The report separates service inventory from targeted observations, retains script evidence, flags incomplete runs and escapes untrusted banner text. It does not infer CVEs solely from banners or treat an empty scan as a clean bill of health.

For each useful finding, record: target/service, timestamp, exact evidence, confidence, missing confirmation, and the defensive fix you would test on your own host. Keep reports and filled scope files out of public Git; the folder's `.gitignore` excludes their default locations.

## Offline self-test

```bash
python3 -m unittest discover -s tests -v
```

The tests use synthetic targets and mock the Nmap process. They check scope boundaries, preview/grace behavior, bounded commands, findings classification and evidence escaping without scanning a network.

See [shared references](../../SOURCES.md) and [validation limits](../../VALIDATION.md).
