#!/usr/bin/env python3
"""Turn existing Nmap XML into an offline, evidence-based review. No network use."""
from __future__ import annotations
import argparse
import html
import ipaddress
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
MAX_XML_BYTES = 8 * 1024 * 1024

def clean(value: str, limit: int = 1200) -> str:
    # Banner/script output is data: strip controls and escape Markdown.
    text = "".join(c for c in value if c in "\n\t" or 32 <= ord(c) < 127)
    text = html.escape(text[:limit], quote=False)
    return re.sub(r"([\\\x60*_\[\]{}()#!|>])", r"\\\1", text).replace("\n", " / ")

def script_text(script: ET.Element) -> str:
    return script.get("output", "") + " " + " ".join(script.itertext())

def finding_rows(script: ET.Element) -> list[tuple[str, str, str]]:
    name, output = script.get("id", ""), script_text(script)
    rows = []
    if name == "smb-protocols" and re.search(r"NT LM 0\.12", output, re.I):
        rows.append(("Review", "SMB1 dialect advertised", "Check whether SMB1 is required; prefer SMB2/3 after client/scoring validation."))
    if name == "smb2-security-mode" and re.search(r"signing\s+(enabled but not required|disabled|not required)", output, re.I):
        rows.append(("Review", "SMB signing is not required for at least one tested dialect",
                     "Confirm on the host, then require signing after testing client compatibility."))
    if name == "smb-vuln-ms17-010":
        # Anchor the state marker: 'NOT VULNERABLE' must never become a positive.
        if re.search(r"(?:^|\n)\s*(?:State:\s*)?VULNERABLE\s*:?\s*(?:\n|$)", script.get("output", ""), re.I):
            rows.append(("High / verify", "MS17-010 probe reported VULNERABLE",
                         "Confirm the exact OS/build, updates and Microsoft advisory; this is a probe result, not proof of exploitation."))
        elif re.search(r"NOT VULNERABLE", output, re.I):
            rows.append(("Info", "MS17-010 probe reported NOT VULNERABLE",
                         "This only covers that probe; it does not establish general SMB security."))
        else:
            rows.append(("Unknown", "MS17-010 probe was inconclusive",
                         "Check raw output, filtering and service compatibility; do not infer a pass."))
    if "ERROR" in output.upper():
        rows.append(("Unknown", f"{name} returned an error", "Read the evidence; the check did not establish a result."))
    return rows

def review(path: Path) -> list[str]:
    if path.stat().st_size > MAX_XML_BYTES:
        raise ValueError(f"XML exceeds the 8 MiB review limit: {path}")
    data = path.read_bytes()
    # Nmap's ordinary <!DOCTYPE nmaprun> is allowed; external entities are not.
    if b"<!ENTITY" in data.upper() or re.search(br"<!DOCTYPE[^>]*(?:SYSTEM|PUBLIC|\[)", data, re.I):
        raise ValueError("External/entity-bearing XML is not accepted.")
    root = ET.fromstring(data)
    if root.tag != "nmaprun":
        raise ValueError(f"Not Nmap XML: {path}")
    lines = [f"## Evidence: {clean(path.name)}", ""]
    finished = root.find("runstats/finished")
    completion = finished.get("exit", "unknown") if finished is not None else "missing/incomplete"
    lines += [f"Scan completion marker: **{clean(completion)}**. Review timeouts and untested ports separately.", ""]
    for host in root.findall("host"):
        address = host.find("address[@addrtype='ipv4']")
        raw_ip = address.get("addr", "") if address is not None else "unknown"
        try:
            ip = str(ipaddress.IPv4Address(raw_ip))
        except ipaddress.AddressValueError:
            ip = "unknown"
        lines += [f"### Host {ip}", ""]
        status = host.find("status")
        lines += [f"Host status: {clean(status.get('state', 'unknown') if status is not None else 'unknown')}.", ""]
        rows = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            state_name = state.get("state", "unknown") if state is not None else "unknown"
            service = port.find("service")
            banner = " ".join(service.get(x, "") for x in ("name", "product", "version", "extrainfo")) if service is not None else ""
            if state_name in ("open", "open|filtered"):
                rows.append((f"{port.get('protocol', '?')}/{port.get('portid', '?')}", state_name, banner.strip()))
        if rows:
            lines += ["| Endpoint | State | Service/version evidence |", "|---|---|---|"]
            lines += [f"| {clean(a)} | {clean(b)} | {clean(c)} |" for a, b, c in rows]
            lines += ["", "An open port or version banner is inventory evidence, not a confirmed vulnerability.", ""]
        else:
            lines += ["No open endpoint was reported in the selected ports. Filtering, timeouts or omitted ports can explain this.", ""]
        findings, scripts = [], host.findall(".//script")
        for script in scripts:
            findings.extend(finding_rows(script))
        if findings:
            lines += ["| Priority | Observation | Next check |", "|---|---|---|"]
            lines += [f"| {clean(a)} | {clean(b)} | {clean(c)} |" for a, b, c in findings]
            lines.append("")
        else:
            lines += ["No targeted weakness was extracted. Missing/inconclusive script output does not mean the host is secure.", ""]
        for script in scripts:
            lines += [f"- Evidence ({clean(script.get('id', 'unknown'))}): {clean(script.get('output', ''), 1600)}"]
        lines.append("")
    if not root.findall("host"):
        lines += ["No host results were present; this scan did not establish reachability or security.", ""]
    return lines

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("xml", type=Path, nargs="+")
    p.add_argument("--output", type=Path, help="New Markdown file; existing files are never overwritten")
    args = p.parse_args(argv)
    if len(args.xml) > 20:
        p.error("Review at most 20 XML files per invocation.")
    lines = ["# Competition enumeration review", "",
             "Offline interpretation of existing Nmap evidence. No exploitation is performed.",
             "Validate findings against host configuration, patch level and current vendor guidance.", ""]
    try:
        for path in args.xml:
            lines.extend(review(path))
        result = "\n".join(lines) + "\n"
        if args.output:
            import os
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(result)
            print(f"Review saved: {args.output}")
        else:
            print(result, end="")
        return 0
    except (OSError, ValueError, ET.ParseError) as exc:
        print(f"Stopped: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
