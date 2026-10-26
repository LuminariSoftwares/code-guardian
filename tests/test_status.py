"""Scan status: COMPLETE, PARTIAL or INVALID. Can I trust this scan? Every check reports an outcome (ran, skipped or
crashed); a PARTIAL scan caps the grade at B and says why; an INVALID scan prints no grade; exit 3 = incomplete."""
import json
import os
import re
import shutil
import subprocess
import sys

import pytest

from conftest import FIXTURES

from code_guardian import mcp_server, outputs, report, scanners, walk, works


def cli(*args):
    return subprocess.run([sys.executable, "-m", "code_guardian", *map(str, args)], capture_output=True, text=True,
                          timeout=120)


@pytest.fixture
def clean(tmp_path):
    dest = tmp_path / "clean_repo"
    shutil.copytree(FIXTURES / "clean_repo", dest)
    return dest


def test_a_normal_repo_is_complete(clean):
    rep = report.scan(str(clean))
    assert rep["status"] == "COMPLETE" and rep["status_reasons"] == []
    assert rep["schema_version"] == 3
    assert rep["scores"]["grade"] == "A"
    outcomes = {o["check"]: o for o in rep["outcomes"]}
    assert {"walk", "secrets", "manifests", "works", "complete", "supply", "orphans"} <= set(outcomes)
    assert all(code in outcomes for code, _ in scanners.PY_SCANNERS)
    assert all(o["outcome"] == "ran" and o["reason"] is None for o in rep["outcomes"])
    assert report.exit_code(rep["findings"], "FAIL", rep["status"]) == 0


def test_a_crashing_check_gives_partial_and_caps_at_b(clean, monkeypatch):
    def boom(project):
        raise RuntimeError("kaput")
    monkeypatch.setattr(works, "check", boom)
    rep = report.scan(str(clean))
    assert rep["status"] == "PARTIAL"
    assert rep["status_reasons"] == ["check works crashed (RuntimeError)"]
    assert {"check": "works", "outcome": "crashed", "reason": "RuntimeError: kaput"} in rep["outcomes"]
    assert [f["code"] for f in rep["findings"] if f["code"] == "check.crashed"] == ["check.crashed"]
    s = rep["scores"]
    assert s["overall"] >= 90 and s["grade_uncapped"] == "A" and s["grade"] == "B" and s["capped"]
    assert "PARTIAL" in s["cap_reason"]
    assert report.exit_code(rep["findings"], "FAIL", rep["status"]) == 3


def test_a_crashing_python_scanner_gives_partial(clean, monkeypatch):
    table = [("boom", lambda pf: 1 / 0)] + list(scanners.PY_SCANNERS)
    monkeypatch.setattr(scanners, "PY_SCANNERS", table)
    rep = report.scan(str(clean))
    assert rep["status"] == "PARTIAL"
    crashed = [o for o in rep["outcomes"] if o["outcome"] == "crashed"]
    assert [o["check"] for o in crashed] == ["boom"] and crashed[0]["reason"].startswith("ZeroDivisionError on ")


def test_an_empty_directory_is_invalid_and_has_no_grade(tmp_path):
    rep = report.scan(str(tmp_path))
    assert rep["status"] == "INVALID"
    assert rep["status_reasons"] == ["no Python files, no JavaScript/TypeScript files and no manifests to judge"]
    assert rep["scores"]["grade"] is None and rep["scores"]["grade_uncapped"] is None
    text = report.render(rep)
    assert not re.search(r"grade [A-F]\b", text) and "/100" not in text
    assert "status: INVALID (no Python files, no JavaScript/TypeScript files and no manifests to judge)" in text and "no grade" in text
    md = outputs.to_markdown(rep)
    assert "INVALID" in md and "grade **" not in md
    r = cli("scan", tmp_path)
    assert r.returncode == 3, r.stdout + r.stderr


def test_an_unreadable_path_is_invalid(tmp_path, monkeypatch):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    real = os.listdir

    def denied(path="."):
        if os.path.abspath(path) == os.path.abspath(str(tmp_path)):
            raise PermissionError(13, "Permission denied")
        return real(path)
    monkeypatch.setattr(os, "listdir", denied)
    rep = report.scan(str(tmp_path))
    assert rep["status"] == "INVALID" and rep["status_reasons"][0].startswith("PATH is unreadable")
    assert rep["scores"]["grade"] is None


def test_an_unparsed_file_gives_partial(clean):
    (clean / "cleanpkg" / "old.py").write_text("print 'hello'\n", encoding="utf-8")
    rep = report.scan(str(clean))
    assert rep["status"] == "PARTIAL"
    assert "1 Python file(s) did not parse: cleanpkg/old.py" in rep["status_reasons"]


def test_a_too_large_python_file_gives_partial_but_a_large_asset_does_not(clean, monkeypatch):
    monkeypatch.setattr(walk, "MAX_BYTES", 400)
    (clean / "logo.ai").write_text("%!PS-Adobe\n" + "x" * 500, encoding="utf-8")
    assert report.scan(str(clean))["status"] == "COMPLETE"
    (clean / "cleanpkg" / "big.py").write_text("X = 1\n" * 100, encoding="utf-8")
    rep = report.scan(str(clean))
    assert rep["status"] == "PARTIAL"
    assert rep["status_reasons"] == ["1 file(s) too large to analyse: cleanpkg/big.py"]


def test_binary_files_do_not_make_a_scan_partial(clean):
    (clean / "logo.png").write_bytes(b"\x89PNG\0\0\0")
    assert report.scan(str(clean))["status"] == "COMPLETE"


def test_status_in_every_format(clean, monkeypatch):
    monkeypatch.setattr(works, "check", lambda p: 1 / 0)
    rep = report.scan(str(clean))
    text = report.render(rep)
    assert "status: PARTIAL (check works crashed (ZeroDivisionError))" in text
    md = outputs.to_markdown(rep)
    assert "**Status: PARTIAL**" in md and "check works crashed (ZeroDivisionError)" in md
    props = outputs.to_sarif(rep)["runs"][0]["properties"]
    assert props["status"] == "PARTIAL" and props["status_reasons"] == rep["status_reasons"]


def test_status_over_mcp(clean, tmp_path):
    tools = mcp_server.default_tools()
    rep = tools["scan"]({"path": str(clean)})
    assert rep["status"] == "COMPLETE" and rep["status_reasons"] == [] and rep["exit_code"] == 0
    empty = tmp_path / "empty"
    empty.mkdir()
    rep = tools["scan"]({"path": str(empty)})
    assert rep["status"] == "INVALID" and rep["exit_code"] == 3


def test_cli_exit_codes(clean):
    assert cli("scan", clean).returncode == 0
    body = json.loads(cli("scan", clean, "--json").stdout)
    assert body["status"] == "COMPLETE" and body["schema_version"] == 3
