"""Bounded competition discovery helpers; importing this file sends no traffic."""
from __future__ import annotations
import ipaddress
import json
import re
from pathlib import Path
from typing import Any

MAX_TARGETS = 20
MAX_PORTS = 32
DEFAULT_PORTS = (21, 22, 53, 80, 88, 135, 139, 389, 443, 445, 636,
                 1433, 3306, 3389, 5432, 5985, 5986, 8000, 8080, 8443)
SMB_SCRIPTS = ("smb-protocols", "smb2-security-mode", "smb2-capabilities")
VULN_SCRIPT = "smb-vuln-ms17-010"

def read_scope(path: Path) -> dict[str, Any]:
    if path.stat().st_size > 32768:
        raise ValueError("Scope file is unexpectedly large.")
    scope = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(scope, dict) or type(scope.get("schema_version")) is not int or scope["schema_version"] != 1:
        raise ValueError("Use schema_version 1 from scope.example.json.")
    own, teams = scope.get("own_team_id"), scope.get("authorized_team_ids")
    if type(own) is not int or not 0 <= own <= 255:
        raise ValueError("Set your verified own_team_id (the third IP octet).")
    if not isinstance(teams, list) or not teams or any(type(x) is not int or not 0 <= x <= 255 for x in teams):
        raise ValueError("List only team IDs explicitly authorized by the final rules.")
    if len(teams) != len(set(teams)) or own in teams:
        raise ValueError("Remove duplicate IDs and your own team from authorized_team_ids.")
    reference = scope.get("authorization_reference")
    if not isinstance(reference, str) or not reference.strip():
        raise ValueError("Record the final rule/organizer reference authorizing these teams.")
    return scope

def validate_targets(values: list[str], scope: dict[str, Any]) -> list[str]:
    if not 1 <= len(values) <= MAX_TARGETS:
        raise ValueError(f"Use 1–{MAX_TARGETS} explicit target IPs per run.")
    checked = []
    for value in values:
        try:
            address = ipaddress.IPv4Address(value)
        except ipaddress.AddressValueError as exc:
            raise ValueError(f"Use one exact IPv4 address, without DNS/CIDR/ranges: {value!r}") from exc
        parts = address.packed
        if parts[0:2] != bytes((172, 16)) or parts[3] not in (50, 51, 52, 53, 54):
            raise ValueError(f"Out of competition host scope: {value}. Only 172.16.TEAM.50–54 are permitted.")
        if parts[2] == scope["own_team_id"] or parts[2] not in scope["authorized_team_ids"]:
            raise ValueError(f"Target team was not explicitly authorized for this run: {value}.")
        if str(address) not in checked:
            checked.append(str(address))
    return checked

def parse_ports(value: str | None) -> tuple[int, ...]:
    if value is None:
        return DEFAULT_PORTS
    tokens = value.split(",")
    if not 1 <= len(tokens) <= MAX_PORTS or any(not re.fullmatch(r"[0-9]{1,5}", x) for x in tokens):
        raise ValueError(f"Use at most {MAX_PORTS} comma-separated single TCP ports; no ranges.")
    ports = tuple(sorted(set(int(x) for x in tokens)))
    if any(not 1 <= p <= 65535 for p in ports):
        raise ValueError("TCP ports must be between 1 and 65535.")
    return ports

def build_command(nmap: str, target: str, profile: str, ports: tuple[int, ...],
                  check_ms17: bool, output_prefix: str) -> list[str]:
    # argv list, never a shell command. No arbitrary NSE arguments or scripts.
    if profile not in ("services", "smb"):
        raise ValueError("Unknown enumeration profile.")
    if check_ms17 and profile != "smb":
        raise ValueError("--check-ms17-010 requires --profile smb.")
    if not ports or len(ports) > MAX_PORTS or any(type(p) is not int or not 1 <= p <= 65535 for p in ports):
        raise ValueError("Invalid bounded port list.")
    chosen = (445,) if profile == "smb" else ports
    command = [nmap, "-n", "-Pn", "-sT", "-sV", "--version-light", "-T3",
               "--max-retries", "1", "--max-rate", "40", "--max-parallelism", "4",
               "--host-timeout", "90s", "-p", ",".join(map(str, chosen))]
    if profile == "smb":
        scripts = SMB_SCRIPTS + ((VULN_SCRIPT,) if check_ms17 else ())
        command += ["--script", ",".join(scripts), "--script-timeout", "30s"]
    return command + ["-oA", output_prefix, target]

def is_kali(path: Path = Path("/etc/os-release")) -> bool:
    # Exact OS ID, not ID_LIKE. Never execute os-release as shell code.
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith("ID="):
                return line[3:].strip().strip('"').strip("'") == "kali"
    except OSError:
        pass
    return False
