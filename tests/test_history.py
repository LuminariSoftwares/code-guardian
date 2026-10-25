"""--history: the secret.key shape rules over the lines git history added (opt-in). A key that was committed and
later deleted is still in the history, and may still be valid."""
import hashlib
import os
import shutil
import subprocess
import sys

import pytest

from code_guardian import history, report
from make_risky import mixed_body

GIT = shutil.which("git")
needs_git = pytest.mark.skipif(GIT is None, reason="git is not on PATH (CI has it)")


def git(root, *args):
    env = dict(os.environ, GIT_AUTHOR_DATE="2026-01-01T00:00:00Z", GIT_COMMITTER_DATE="2026-01-01T00:00:00Z")
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, env=env)


def key():
    return "sk-" + mixed_body("history", 30)  # mixed, like a real key: a low-variety body is graded INFO


def make_repo(root):
    root.mkdir()
    git(root, "init", "-q")
    git(root, "config", "user.name", "t")
    git(root, "config", "user.email", "t@example.com")
    git(root, "config", "commit.gpgsign", "false")
    # git's own background housekeeping after a commit (maintenance.lock, gc) would race the .git snapshot below
    git(root, "config", "maintenance.auto", "false")
    git(root, "config", "gc.auto", "0")
    (root / "app").mkdir()
    (root / "app" / "__init__.py").write_text("", encoding="utf-8")
    (root / "app" / "settings.py").write_text("API = '%s'\nDEBUG = False\n" % key(), encoding="utf-8")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "add settings")
    (root / "app" / "settings.py").write_text("import os\nAPI = os.environ.get('API')\nDEBUG = False\n",
                                              encoding="utf-8")
    git(root, "commit", "-q", "-am", "read the key from the environment")
    return root


def snapshot(root):
    out = {}
    for dirpath, _, files in os.walk(root / ".git"):
        for name in files:
            full = os.path.join(dirpath, name)
            with open(full, "rb") as fh:
                out[os.path.relpath(full, root)] = hashlib.sha256(fh.read()).hexdigest()
    return out


@needs_git
def test_history_finds_a_deleted_key_and_a_plain_scan_does_not(tmp_path):
    root = make_repo(tmp_path / "repo")
    plain = report.scan(str(root))
    assert not [f for f in plain["findings"] if f["code"].startswith("secret.")]
    rep = report.scan(str(root), history=True)
    found = [f for f in rep["findings"] if f["code"] == "secret.history"]
    assert len(found) == 1, rep["findings"]
    f = found[0]
    first = subprocess.run(["git", "-C", str(root), "rev-list", "--max-parents=0", "HEAD"], capture_output=True,
                           text=True).stdout.strip()
    assert f["level"] == "FAIL" and f["node"] == "app/settings.py"
    assert f["summary"] == ("a key shape was committed in %s and may still be valid even if the file no longer has it"
                            % first[:7])
    assert "commit: %s" % first[:7] in f["evidence"]
    assert rep["scores"]["safe"] == 70 and rep["scores"]["grade"] == "D"  # weight 30, and a Safe FAIL caps at D
    assert {"check": "history", "outcome": "ran", "reason": None} in rep["outcomes"]
    import json
    assert key() not in json.dumps(rep) and key() not in report.render(rep)


@needs_git
def test_history_never_modifies_the_repo(tmp_path):
    root = make_repo(tmp_path / "repo")
    before = snapshot(root)
    report.scan(str(root), history=True)
    assert snapshot(root) == before


@needs_git
def test_depth_limits_the_commits_read(tmp_path):
    root = make_repo(tmp_path / "repo")
    rep = report.scan(str(root), history=True, history_depth=1)  # only the commit that removed it
    assert not [f for f in rep["findings"] if f["code"] == "secret.history"]


@needs_git
def test_a_key_still_in_the_tree_is_left_to_secret_key(tmp_path):
    root = make_repo(tmp_path / "repo")
    (root / "app" / "settings.py").write_text("API = '%s'\n" % key(), encoding="utf-8")
    git(root, "commit", "-q", "-am", "put it back")
    rep = report.scan(str(root), history=True)
    assert [f["code"] for f in rep["findings"] if f["code"].startswith("secret.")] == ["secret.key"]


@needs_git
def test_the_byte_cap_stops_the_read_with_a_note(tmp_path, monkeypatch):
    root = make_repo(tmp_path / "repo")
    found, notes, skipped = history.scan(str(root), depth=500, byte_cap=10)
    assert found == [] and skipped is None and any("byte cap" in n for n in notes)


@needs_git
def test_cli_history_flag(tmp_path):
    root = make_repo(tmp_path / "repo")
    r = subprocess.run([sys.executable, "-m", "code_guardian", "scan", str(root), "--history", "--history-depth", "5"],
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 1 and "secret.history" in r.stdout and key() not in r.stdout


def test_not_a_repo_is_skipped_with_a_note(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    rep = report.scan(str(tmp_path), history=True)
    row = [o for o in rep["outcomes"] if o["check"] == "history"][0]
    assert row["outcome"] == "skipped" and "not a git repository" in row["reason"]
    assert any(n.startswith("history:") for n in rep["notes"])


def test_missing_git_is_skipped_with_a_note(tmp_path, monkeypatch):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setattr(history.shutil, "which", lambda name: None)
    rep = report.scan(str(tmp_path), history=True)
    row = [o for o in rep["outcomes"] if o["check"] == "history"][0]
    assert row == {"check": "history", "outcome": "skipped", "reason": "git is not on PATH"}


def test_the_git_command_is_an_argument_list_and_read_only():
    cmd = history.command("/some/path", 500)
    assert isinstance(cmd, list) and cmd[0] == "git"
    joined = " ".join(cmd)
    for flag in ("log", "-p", "--no-color", "--no-ext-diff", "--format=%H", "--no-textconv", "--max-count=500"):
        assert flag in cmd, flag
    for writer in ("commit", "checkout", "reset", "gc", "fetch", "push", "config --add"):
        assert " %s " % writer not in " %s " % joined
