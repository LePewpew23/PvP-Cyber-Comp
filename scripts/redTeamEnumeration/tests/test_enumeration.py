"""Offline regression tests: no scanning, network use or real Nmap process."""
import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from enum_common import read_scope, validate_targets, parse_ports, build_command, is_kali

def load_file(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

runner = load_file("enumerate_runner", "01_enumerate.py")
reviewer = load_file("reviewer", "02_review_findings.py")

class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.scope = {"schema_version": 1, "own_team_id": 7, "authorized_team_ids": [8],
                      "authorization_reference": "Synthetic offline fixture"}

    def test_accept_only_explicit_competition_hosts(self):
        self.assertEqual(validate_targets(["172.16.8.51", "172.16.8.51"], self.scope), ["172.16.8.51"])
        for target in ["172.16.8.1", "172.16.8.2", "172.16.8.55", "172.16.7.51",
                       "172.16.9.51", "10.0.0.51", "172.16.8.0/24", "example.com",
                       "172.16.8.50-54", "172.16.008.51", "--script=all", "::1"]:
            with self.subTest(target=target), self.assertRaises(ValueError):
                validate_targets([target], self.scope)

    def test_target_count_bound(self):
        with self.assertRaises(ValueError):
            validate_targets(["172.16.8.51"] * 21, self.scope)

    def test_incomplete_scope_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "scope.json"
            p.write_text(json.dumps(self.scope))
            self.assertEqual(read_scope(p), self.scope)
            for field, value in [("own_team_id", None), ("own_team_id", True),
                                 ("authorized_team_ids", [7]), ("authorized_team_ids", []),
                                 ("authorized_team_ids", [8, 8]), ("authorization_reference", "")]:
                p.write_text(json.dumps({**self.scope, field: value}))
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    read_scope(p)

    def test_bounded_ports_and_script_allowlist(self):
        self.assertEqual(parse_ports("445,80,445"), (80, 445))
        for text in ["1-65535", "0", "65536", "445;id", ",".join(str(x) for x in range(1, 34))]:
            with self.assertRaises(ValueError):
                parse_ports(text)
        c = build_command("nmap", "172.16.8.51", "smb", (445,), False, "evidence")
        self.assertEqual(c[c.index("--script") + 1], "smb-protocols,smb2-security-mode,smb2-capabilities")
        self.assertNotIn("smb-vuln-ms17-010", ",".join(c))
        self.assertNotIn("-A", c)
        self.assertNotIn("--script-args", c)
        c = build_command("nmap", "172.16.8.51", "smb", (445,), True, "evidence")
        self.assertIn("smb-vuln-ms17-010", c[c.index("--script") + 1])
        with self.assertRaises(ValueError):
            build_command("nmap", "172.16.8.51", "services", (445,), True, "evidence")

    def test_preview_and_grace_guard_send_no_traffic(self):
        with tempfile.TemporaryDirectory() as d:
            scope = Path(d) / "scope.json"
            scope.write_text(json.dumps(self.scope))
            out = Path(d) / "evidence"
            args = ["--scope", str(scope), "--targets", "172.16.8.51", "--output-dir", str(out)]
            with patch.object(runner.subprocess, "run", side_effect=AssertionError("Network attempted")):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(runner.main(args), 0)
                    self.assertEqual(runner.main(args + ["--run"]), 2)
                self.assertFalse(out.exists())

    def test_live_runner_mocked_and_sequential(self):
        with tempfile.TemporaryDirectory() as d:
            scope = Path(d) / "scope.json"
            scope.write_text(json.dumps(self.scope))
            calls = []
            def fake_run(command, **kwargs):
                calls.append(command)
                self.assertNotIn("shell", kwargs)
                self.assertEqual(kwargs["timeout"], 150)
                return type("Result", (), {"returncode": 0})()
            with patch.object(runner, "is_kali", return_value=True), \
                 patch.object(runner.shutil, "which", return_value="/mock/nmap"), \
                 patch.object(runner.subprocess, "run", side_effect=fake_run), \
                 contextlib.redirect_stdout(io.StringIO()):
                result = runner.main(["--scope", str(scope), "--targets", "172.16.8.51", "172.16.8.54",
                                      "--output-dir", str(Path(d) / "reports"), "--run", "--grace-period-ended"])
            self.assertEqual(result, 0)
            self.assertEqual([c[-1] for c in calls], ["172.16.8.51", "172.16.8.54"])
            self.assertEqual(len(list((Path(d) / "reports").glob("*/manifest.json"))), 1)

    def test_exact_kali_id(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "os-release"
            p.write_text('ID=debian\nID_LIKE=kali\n')
            self.assertFalse(is_kali(p))
            p.write_text('ID="kali"\n')
            self.assertTrue(is_kali(p))

class ReportTests(unittest.TestCase):
    def test_findings_distinguish_negative_and_positive(self):
        for text, expected in [("State: VULNERABLE\n", "High / verify"),
                               ("State: NOT VULNERABLE\n", "Info"),
                               ("ERROR: negotiation failed", "Unknown")]:
            s = ET.Element("script", id="smb-vuln-ms17-010", output=text)
            self.assertEqual(reviewer.finding_rows(s)[0][0], expected)

    def test_smb_configuration(self):
        weak = ET.Element("script", id="smb2-security-mode", output="3:1:1: Message signing enabled but not required")
        strong = ET.Element("script", id="smb2-security-mode", output="3:1:1: Message signing enabled and required")
        self.assertTrue(reviewer.finding_rows(weak))
        self.assertEqual(reviewer.finding_rows(strong), [])
        smb1 = ET.Element("script", id="smb-protocols", output="NT LM 0.12 (SMBv1) [dangerous]")
        self.assertTrue(reviewer.finding_rows(smb1))
        error = ET.Element("script", id="smb-protocols", output="ERROR: SMB1 negotiation failed")
        self.assertFalse(any("advertised" in row[1] for row in reviewer.finding_rows(error)))

    def test_normal_nmap_xml_and_incomplete_result(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "fixture.xml"
            p.write_text('<!DOCTYPE nmaprun><nmaprun><host><status state="up"/><address addr="172.16.8.51" addrtype="ipv4"/>'
                         '<ports><port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/></port></ports>'
                         '</host></nmaprun>')
            report = "\n".join(reviewer.review(p))
            self.assertIn("missing/incomplete", report)
            self.assertIn("not a confirmed vulnerability", report)

    def test_reject_entities_and_escape_banner(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "bad.xml"
            p.write_text('<!DOCTYPE x [<!ENTITY foo SYSTEM "file:///etc/passwd">]><nmaprun/>')
            with self.assertRaises(ValueError):
                reviewer.review(p)
        self.assertNotIn("<script>", reviewer.clean("<script>|[link](url)\x1b[31m"))
        self.assertNotIn("\x1b", reviewer.clean("\x1b"))
        self.assertIn(r"\|", reviewer.clean("|"))

if __name__ == "__main__":
    unittest.main()
