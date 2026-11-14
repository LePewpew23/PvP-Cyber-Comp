#!/usr/bin/env python3
"""Preview or run limited discovery from competition Kali after the grace period."""
from __future__ import annotations
import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from enum_common import build_command, is_kali, parse_ports, read_scope, validate_targets

def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--scope", type=Path, default=Path(__file__).with_name("scope.json"))
    p.add_argument("--targets", nargs="+", required=True, help="Explicit authorized 172.16.TEAM.50–54 IPs")
    p.add_argument("--profile", choices=("services", "smb"), default="services")
    p.add_argument("--ports", help="Services profile: at most 32 single TCP ports, comma separated")
    p.add_argument("--check-ms17-010", action="store_true", help="Add one targeted non-exploit SMB vulnerability probe")
    p.add_argument("--run", action="store_true", help="Send the displayed discovery probes")
    p.add_argument("--grace-period-ended", action="store_true", help="Confirm the organizer has ended the no-access period")
    p.add_argument("--output-dir", type=Path, default=Path(__file__).with_name("reports"))
    return p

def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        scope = read_scope(args.scope)
        targets = validate_targets(args.targets, scope)
        ports = parse_ports(args.ports)
        if args.profile == "smb" and args.ports is not None:
            raise ValueError("The SMB profile is fixed to TCP 445; omit --ports.")
        if args.check_ms17_010 and args.profile != "smb":
            raise ValueError("--check-ms17-010 requires --profile smb.")
        for ip in targets:
            command = build_command("nmap", ip, args.profile, ports, args.check_ms17_010,
                                    f"<private-run-directory>/{ip}")
            print(shlex.join(command))
        if not args.run:
            print("PREVIEW ONLY: no network traffic and no report files. Review final scope before --run.")
            return 0
        if not args.grace_period_ended:
            raise ValueError("Do not access other teams during grace. Add --grace-period-ended only after the organizer ends it.")
        if not is_kali():
            raise ValueError("Run live enumeration from the designated competition Kali machine.")
        nmap = shutil.which("nmap")
        if not nmap:
            raise ValueError("Nmap is not installed or is not in PATH on Kali.")
        # Private unique evidence folder; no existing evidence is replaced.
        os.umask(0o077)
        args.output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        run_dir = Path(tempfile.mkdtemp(prefix=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-"),
                                     dir=args.output_dir)).resolve()
        manifest = {"started_utc": datetime.now(timezone.utc).isoformat(), "scope": scope,
                    "profile": args.profile, "targets": targets, "results": []}
        manifest_path = run_dir / "manifest.json"
        def save_manifest() -> None:
            manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        save_manifest()
        failed = False
        for ip in targets:  # Sequential, one target at a time.
            command = build_command(nmap, ip, args.profile, ports, args.check_ms17_010, str(run_dir / ip))
            row = {"target": ip, "argv": command, "status": "running"}
            manifest["results"].append(row)
            save_manifest()
            print(f"Enumerating {ip}; evidence directory: {run_dir}", flush=True)
            # Keep remote banners/control sequences in evidence files.
            with (run_dir / f"{ip}-runner.log").open("wb") as log:
                try:
                    result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                                            timeout=150, check=False)
                    row.update(status="completed" if result.returncode == 0 else "failed",
                               returncode=result.returncode)
                    failed |= result.returncode != 0
                except subprocess.TimeoutExpired:
                    row.update(status="timed_out", returncode=None)
                    failed = True
                except KeyboardInterrupt:
                    row.update(status="interrupted", returncode=None)
                    save_manifest()
                    print(f"Interrupted. Partial evidence: {run_dir}", file=sys.stderr)
                    return 130
            save_manifest()
        print(f"Evidence saved: {run_dir}")
        print("Review XML with 02_review_findings.py. A completed scan does not prove all services were assessed.")
        return 1 if failed else 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Stopped: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
