"""code-guardian scanned by itself: grade A, no FAIL, and no dead code against its own goal contract."""
import json
import subprocess
import sys

from conftest import ROOT

from code_guardian import report


def test_self_scan_grade_a_and_no_dead_code():
    rep = report.scan(str(ROOT))
    assert rep["goal_file"] == "code-guardian.goal.toml"
    assert rep["threat"]["grade"] == "A", rep["threat"]
    assert not [f for f in rep["findings"] if f["level"] == "FAIL"]
    assert rep["hygiene"]["source"] == "contract"
    dead = [f for f in rep["hygiene"]["findings"] if f["code"] == "orphan.dead"]
    assert dead == [], [f["summary"] for f in dead]


def test_self_scan_cli_exit_0():
    r = subprocess.run([sys.executable, "-m", "code_guardian", "scan", str(ROOT), "--json"],
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr
    body = json.loads(r.stdout)
    assert body["threat"]["grade"] == "A" and body["hygiene"]["counts"]["orphan.dead"] == 0
