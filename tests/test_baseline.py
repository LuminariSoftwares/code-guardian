"""Baseline + new-findings-only gate. A baseline is the committed list of finding fingerprints
(sha256 of code | level | relpath | normalised evidence line; no line numbers). scan --baseline marks each finding new
or known, --fail-on counts only new ones, and the scores still count every finding."""
import json
import re
import subprocess
import sys

import pytest

from conftest import ROOT

from code_guardian import baseline, mcp_server, outputs, report

APP = "import os\n\n\ndef run():\n    os.system('ls')\n    os.system('pwd')\n"


def cli(*args):
    return subprocess.run([sys.executable, "-m", "code_guardian", *map(str, args)], capture_output=True, text=True,
                          timeout=120)


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "proj"
    (root / "app").mkdir(parents=True)
    (root / "app" / "__init__.py").write_text("", encoding="utf-8")
    (root / "app" / "main.py").write_text(APP, encoding="utf-8")
    out = tmp_path / "base.json"
    assert cli("baseline", root, "--out", out).returncode == 0
    return root, out


def scan(root, base):
    return report.scan(str(root), baseline=str(base))


def shell(rep):
    return sorted((f["node"], f["new"]) for f in rep["findings"] if f["code"] == "exec.shell")


def test_fingerprint_ignores_line_numbers_and_whitespace():
    a = baseline.fingerprint("exec.shell", "WARN", "app/main.py", "    os.system('ls')  ")
    b = baseline.fingerprint("exec.shell", "WARN", "app/main.py", "os.system( 'ls')".replace("( ", "("))
    assert a == b and re.fullmatch(r"[0-9a-f]{64}", a)
    assert a != baseline.fingerprint("exec.shell", "FAIL", "app/main.py", "os.system('ls')")
    assert a != baseline.fingerprint("exec.shell", "WARN", "app/other.py", "os.system('ls')")
    key = "sk-" + "K" * 30
    assert baseline.normalise("x = '%s'\t\t# k" % key) == "x = '<redacted key>' # k"


def test_baseline_file_is_sorted_versioned_and_deterministic(repo, tmp_path):
    root, out = repo
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["tool"] == "code-guardian" and data["version"] and data["fingerprints"] == sorted(data["fingerprints"])
    assert len(data["fingerprints"]) == len(report.scan(str(root))["findings"])
    again = tmp_path / "again.json"
    cli("baseline", root, "--out", again)
    assert again.read_bytes() == out.read_bytes()


def test_default_output_is_inside_path(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    r = cli("baseline", tmp_path)
    assert r.returncode == 0 and (tmp_path / baseline.FILENAME).is_file(), r.stderr


def test_unchanged_repo_is_all_known(repo):
    root, out = repo
    rep = scan(root, out)
    assert all(f["new"] is False for f in rep["findings"] + rep["hygiene"]["findings"])
    assert rep["baseline"]["new"] == 0 and rep["baseline"]["known"] == len(rep["findings"])


def test_code_moved_down_10_lines_is_still_known(repo):
    root, out = repo
    (root / "app" / "main.py").write_text("X = 0\n" * 10 + APP, encoding="utf-8")
    rep = scan(root, out)
    assert shell(rep) == [("app/main.py:15", False), ("app/main.py:16", False)]
    assert report.exit_code(rep["findings"], "WARN", rep["status"], rep.get("baseline")) == 0


def test_an_edited_evidence_line_is_new(repo):
    root, out = repo
    (root / "app" / "main.py").write_text(APP.replace("'ls'", "'ls -la'"), encoding="utf-8")
    rep = scan(root, out)
    assert shell(rep) == [("app/main.py:5", True), ("app/main.py:6", False)]
    assert rep["baseline"]["new"] == 1
    assert report.exit_code(rep["findings"], "WARN", rep["status"], rep.get("baseline")) == 1
    assert "1 new, " in report.render(rep) and "[new]" in report.render(rep)
    assert "1 new, " in outputs.to_markdown(rep)


def test_a_deleted_finding_disappears_and_the_baseline_is_not_rewritten(repo):
    root, out = repo
    before = out.read_bytes()
    (root / "app" / "main.py").write_text(APP.replace("    os.system('pwd')\n", ""), encoding="utf-8")
    rep = scan(root, out)
    assert shell(rep) == [("app/main.py:5", False)]
    assert out.read_bytes() == before
    r = cli("scan", root, "--baseline", out, "--fail-on", "WARN")
    assert r.returncode == 0 and out.read_bytes() == before, r.stdout


def test_a_duplicate_line_beyond_the_baseline_count_is_new(repo):
    root, out = repo
    (root / "app" / "main.py").write_text(APP + "    os.system('ls')\n", encoding="utf-8")
    rep = scan(root, out)
    assert [new for _, new in shell(rep)].count(True) == 1


def test_scores_count_every_finding_whatever_the_baseline(repo):
    root, out = repo
    (root / "app" / "main.py").write_text(APP.replace("'ls'", "'ls -la'"), encoding="utf-8")
    assert scan(root, out)["scores"] == report.scan(str(root))["scores"]


def test_cli_gate_counts_only_new(repo):
    root, out = repo
    assert cli("scan", root, "--fail-on", "WARN").returncode == 1
    assert cli("scan", root, "--fail-on", "WARN", "--baseline", out).returncode == 0
    (root / "app" / "main.py").write_text(APP.replace("'pwd'", "'whoami'"), encoding="utf-8")
    r = cli("scan", root, "--fail-on", "WARN", "--baseline", out, "--json")
    assert r.returncode == 1 and json.loads(r.stdout)["baseline"]["new"] == 1


def test_a_bad_baseline_file_is_a_usage_error(repo, tmp_path):
    root, _ = repo
    bad = tmp_path / "bad.json"
    bad.write_text("[1, 2]", encoding="utf-8")
    assert cli("scan", root, "--baseline", bad).returncode == 2
    assert cli("scan", root, "--baseline", tmp_path / "missing.json").returncode == 2


def test_sarif_carries_fingerprints_and_new(repo):
    root, out = repo
    res = outputs.to_sarif(scan(root, out))["runs"][0]["results"]
    assert all(re.fullmatch(r"[0-9a-f]{64}", r["partialFingerprints"]["codeGuardian/v1"]) for r in res)
    assert all(r["properties"]["new"] is False for r in res)


def test_mcp_scan_takes_a_baseline(repo):
    root, out = repo
    rep = mcp_server.default_tools()["scan"]({"path": str(root), "baseline": str(out), "fail_on": "WARN"})
    assert rep["baseline"]["new"] == 0 and rep["exit_code"] == 0
    spec = [t for t in mcp_server.TOOL_SPECS if t["name"] == "scan"][0]
    assert "baseline" in spec["inputSchema"]["properties"]


def test_action_and_pre_commit_support_a_baseline():
    action = (ROOT / "action.yml").read_text(encoding="utf-8")
    assert re.search(r"(?m)^  baseline:\n", action) and "--baseline" in action
    hooks = (ROOT / ".pre-commit-hooks.yaml").read_text(encoding="utf-8")
    assert re.search(r"(?m)^- id: code-guardian-new$", hooks)
    assert "--baseline code-guardian.baseline.json" in hooks
