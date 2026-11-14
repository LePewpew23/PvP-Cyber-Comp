# Validation and remaining checks

Prepared 2026-11-14. No production/competition system was modified or scanned.

## Completed offline checks

| Area | Result |
|---|---|
| PowerShell syntax | All 26 PowerShell scripts/modules parsed with PowerShell 7.7.0 on Linux |
| New firewall workflow | 49 assertions passed with Windows APIs mocked: address/port validation, deterministic allowances, preview/WhatIf, idempotent staging, console/probe guards, lockdown, outbound preservation, commit, timer/manual recovery, failed-apply recovery, policy conflicts and state/worker drift |
| Original account and IP-block modules | Existing mocked regression suite passed for preview/WhatIf, protected IPs, inbound/outbound SMB block directions, selective restore, password allowlist/hidden prompts, deletion protections and outcome reporting |
| Enumeration | 11 offline Python unittest cases passed, including rejected scope, exact allowed hosts, grace/preview guards, bounded commands, mocked sequential execution and XML interpretation |
| Password preservation | Original script retained byte for byte; SHA-256: `c75438956e7f80b964fdd69f91236a76a80751ed29769315b1b8156551b1d825` |
| Shared original helpers | Retained byte for byte |

The Windows workflow tests use simulated services, profiles, rules, scheduler calls and firewall imports. They exercise the real planning, wrapper and state-transition logic; they do not validate Windows CIM behavior, actual Task Scheduler permissions, execution policy, Group Policy or network reachability. No real Nmap process ran in the enumeration tests.

## Required on Sunflower

1. Parse the package with the included `Test-ToolkitSyntax.ps1` in actual 64-bit Windows PowerShell 5.1.
2. Verify the host/build, current services, shares, identities, dependencies and recovery console.
3. Fill the configuration with verified addresses, including the scorer's source as seen through any NAT.
4. Stage and preview the firewall plan. Resolve policy/block conflicts and intentional exceptions.
5. Apply with the timed rollback available; test a fresh remote ping, management login, SMB authentication and the exact scored file operation.
6. Check Quotient, then explicitly commit the firewall transaction. A local pass or an existing connection is insufficient.
7. Test each additional SMB/Windows/account change separately and coordinate any password PCR.

A scheduled task can fail on a broken/offline machine. Console recovery remains necessary. Rollback restores the full pre-lockdown local firewall policy and replaces concurrent local firewall changes. Password resets and account deletion are not covered by that rollback.

## Enumeration limits

The tooling covers selected TCP services and named SMB checks, not every port, UDP, credentialed patch assessment, application authorization or every vulnerability. Findings require interpretation and vendor/host confirmation. The authorized team range and end of grace must be established from the final competition instructions.

`SHA256SUMS.txt` records the package files (except itself). It can detect later differences when compared with a trusted copy; it is not a digital signature or publisher authentication.
