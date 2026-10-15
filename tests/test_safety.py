"""The scan never executes, imports or installs what it reads, and never touches the network."""
import socket
import sys

import pytest
from conftest import FIXTURES, HTTP, tailnet

from code_guardian import report

TRAP = '''import pathlib
pathlib.Path(__file__).with_name("{marker}").write_text("ran")
raise SystemExit("this file must never run")
'''


def test_scanned_code_never_runs(tmp_path):
    (tmp_path / "pkg").mkdir()
    for name in ("setup.py", "conftest.py", "pkg/__init__.py", "pkg/__main__.py"):
        (tmp_path / name).write_text(TRAP.format(marker=name.replace("/", "_") + ".ran"), encoding="utf-8")
    before = set(sys.modules)
    rep = report.scan(str(tmp_path))
    report.orphans(str(tmp_path))
    assert rep["files"]["python"] == 4
    assert not list(tmp_path.rglob("*.ran"))
    assert not {m for m in set(sys.modules) - before if m == "pkg" or m.startswith("pkg.")}


def test_scan_makes_no_network_calls(monkeypatch, tmp_path):
    def refuse(*args, **kwargs):
        raise AssertionError("the scan opened a network connection")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    for name in ("clean_repo", "risky_repo", "orphan_repo"):
        report.scan(str(FIXTURES / name))
    report.scan(str(FIXTURES / "clean_repo"), explain=False, env={"CODE_GUARDIAN_LLM_URL": HTTP + tailnet(1) + ":9"})


def test_symlinks_are_not_followed(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "evil.py").write_text("eval(x)\n", encoding="utf-8")
    project = tmp_path / "project"
    project.mkdir()
    try:
        (project / "link").symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available here")
    rep = report.scan(str(project))
    assert rep["files"]["python"] == 0 and rep["findings"] == []


def test_unparseable_python_is_noted_not_fatal(tmp_path):
    (tmp_path / "old.py").write_text("print 'python 2'\n", encoding="utf-8")
    (tmp_path / "ok.py").write_text("eval(x)\n", encoding="utf-8")
    rep = report.scan(str(tmp_path))
    assert rep["files"]["unparsed"] == 1
    assert [(f["code"], f["node"]) for f in rep["findings"] if f["code"] != "works.tests_missing"] == [
        ("exec.dynamic", "ok.py:1"), ("works.syntax", "old.py:1")]


def test_gitignore_and_skip_dirs(tmp_path):
    (tmp_path / ".gitignore").write_text("generated/\n*.tmp.py\n", encoding="utf-8")
    for rel in ("generated/a.py", "x.tmp.py", "node_modules/b.py", ".venv/c.py", "keep.py"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("eval(x)\n", encoding="utf-8")
    rep = report.scan(str(tmp_path))
    assert [f["node"] for f in rep["findings"] if f["code"] == "exec.dynamic"] == ["keep.py:1"]
