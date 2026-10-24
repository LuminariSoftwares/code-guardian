"""P76 S7 acceptance -- release 0.4.0 (code-guardian-mcp, PyPI), with P78 (app v1.1) and P76 S6b folded in.

Written by the overseer BEFORE the build session. The build session must add this file to the PR byte-for-byte and
must not edit it; a PR that changes it fails the section. This file is pure ASCII on purpose.

Also here, as P78 deviation (14): the owner's initials and an example user name built from them are scrubbed from
the tree (the overseer's own acceptance files are replaced with amended copies in the same PR); and the ADR 0009 list
gets its missing "and" (the S4 nit).

Amended by the overseer after PR #41: the README is the PyPI page, so its release line, sample output and the two
pinned refs (`@v...` and `rev: v...`) must name 0.4.0 before the tag.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
VERSION = "0.4.0"


def _read(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def test_every_version_field_is_040():
    assert re.search(r'^version\s*=\s*"%s"' % re.escape(VERSION), _read("pyproject.toml"), re.M)
    assert re.search(r'^__version__\s*=\s*"%s"' % re.escape(VERSION), _read("code_guardian/__init__.py"), re.M)
    assert re.search(r'^VERSION\s*=\s*"%s"' % re.escape(VERSION), _read("code_guardian/mcp_server.py"), re.M)
    server = json.loads(_read("server.json"))
    found = []

    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if k == "version":
                    found.append(v)
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
    walk(server)
    assert found and set(found) == {VERSION}, found


def test_cli_prints_the_version():
    r = subprocess.run([sys.executable, "-m", "code_guardian", "--version"], cwd=str(ROOT), capture_output=True,
                       text=True, timeout=60)
    assert r.returncode == 0 and VERSION in (r.stdout + r.stderr), r.stdout + r.stderr


def test_changelog_names_the_release():
    text = _read("CHANGELOG.md")
    head = re.search(r"^## .*\b%s\b.*\(20\d\d-\d\d-\d\d\)\s*$" % re.escape(VERSION), text, re.M)
    assert head, "no '## ... 0.4.0 ... (YYYY-MM-DD)' heading"
    unreleased = re.search(r"^## Unreleased\s*$(.*?)(?=^## |\Z)", text, re.M | re.S)
    assert unreleased is None or not unreleased.group(1).strip(), "## Unreleased still has entries"
    body = text[head.end():]
    nxt = re.search(r"^## ", body, re.M)
    body = (body[:nxt.start()] if nxt else body).lower()
    for word in ("save this check", "settings", "every file", "browse", "phone"):
        assert word in body, word


def test_readme_says_what_explain_sends():
    text = re.sub(r"\s+", " ", _read("README.md"))
    assert "### Settings" in _read("README.md") and "From a phone" in text
    assert re.search(r"(the|those) lines you (pick|select|chose)", text, re.I), "the explain-sends-lines sentence"


def test_no_owner_initials_in_the_tree():
    r = subprocess.run(["git", "grep", "-n", "-I", "-E", r"\bTJ\b|\btj\b", "--", ".", ":!*.png"], cwd=str(ROOT),
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 1 and not r.stdout.strip(), r.stdout[:800]


def test_adr_0009_list_reads_right():
    adr = next((ROOT / "docs" / "adr").glob("0009-*.md")).read_text(encoding="utf-8")
    flat = re.sub(r"\s+", " ", adr)
    assert "3 when this Python has no `tkinter`, and 4 when there is no display" in flat, \
        "the exit-code list needs 'and' before its last item"


def test_readme_names_the_release():
    text = _read("README.md")
    old = [m.group(0) for m in re.finditer(r"[^\n]*\b0\.3\.\d+\b[^\n]*", text)]
    assert not old, "README still names 0.3.x: %s" % old[:5]
    assert "**%s is the current release.**" % VERSION in text
    assert "code-guardian@v%s" % VERSION in text and "rev: v%s" % VERSION in text
    assert "code-guardian %s  scan of" % VERSION in text
