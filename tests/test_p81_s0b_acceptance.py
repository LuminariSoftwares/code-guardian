"""P81 S0b acceptance -- the golden harness, the four JS fixtures, make_risky_js and the pinned calibration set
(plan P81 C5, C7, the S0b proof row).

Written by the overseer BEFORE the build session. The build session must add this file to the PR byte-for-byte and
must not edit it; a PR that changes it fails the section. Pure ASCII on purpose; no key-shaped value anywhere (the
patterns below are built from pieces).

Contract fixed here (the plan leaves these names open; the build follows them):
  tests/test_golden.py defines
    EXCLUDED        the keys dropped from both sides: exactly version, schema_version, weights, path (C5)
    ADDITIVE        exactly {"files.javascript", "files.generated", "coverage.languages"} (C5)
    GOLDEN_FIXTURES every Python-only fixture: all of tests/fixtures except js_clean, js_risky, js_broken,
                    jsx_torture. Overseer deviation: that is NINE today, not the plan's eight -- P88 S1 added
                    backup_repo (2026-10-24), and it gets a golden too.
    canonical(path) the `scan --json` report of an LF-normalised temporary copy of `path` (CRLF -> LF in every text
                    file) with EXCLUDED dropped. Overseer deviation: P88 found that a Windows CRLF checkout changes
                    complete_bare's report (its README byte count), so one golden must serve every OS.
  tests/golden/<fixture>.json  json.dumps(canonical(...), indent=1, sort_keys=True) + newline, risky_repo built by
                    tests/make_risky.build (C5); the risky_repo delta file is S4's, not this section's.
  tests/make_risky_js.py  build(dest) -> Path: copies tests/fixtures/js_risky and writes the one key-shaped value at
                    test time (C7); no key shape is ever committed.
  calibration.md    a section headed "JavaScript / TypeScript calibration set (P81)" with one row per pinned repo
                    (expressjs/express, fastify/fastify, the create-vite react-ts template, the create-next-app
                    TypeScript app-router template, juice-shop/juice-shop) each with a 40-hex commit SHA, the Juice
                    Shop `vuln-code-snippet` marker check (present or absent), and both ground-truth lists with
                    file:line entries (C5's calibration paragraph). The exact lines are the overseer's pins.

"Before" values on today's main (the S0b proof row; S4 flips them, so these checks stand down once
code_guardian/scanners_js.py exists): js_clean and js_risky (keys built) PARTIAL, grade B or lower, no exec.*
finding; jsx_torture PARTIAL with no Safe or Works finding (only complete.* checks); a folder holding only index.js
INVALID, exit 3. Overseer deviation: measured on main a5b50b7, jsx_torture with only the C7 source files is INVALID
(no Python file and no manifest), so the fixture carries a minimal package.json to be PARTIAL as the plan says.

The weight-flip proof of C5 is run here as a mutation instead: `weights` is an excluded key, so flipping one weight
reds only the fixtures that carry that check; changing score.WEIGHTS_RULE (a key every report prints) in a scratch
copy must turn test_golden red for every golden fixture.
"""
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
FIXTURES = HERE / "fixtures"
GOLDEN = HERE / "golden"
JS_FIXTURES = ("js_clean", "js_risky", "js_broken", "jsx_torture")
FOUR_KEYS = {"version", "schema_version", "weights", "path"}
ADDITIVE_SET = {"files.javascript", "files.generated", "coverage.languages"}
GRADES_B_OR_LOWER = {"B", "C", "D", "F"}
KEY_SHAPE = re.compile(r"(?<![A-Za-z0-9_\-])(?:%s)[A-Za-z0-9_\-]{12,}" % "|".join(
    re.escape(p) for p in ("s" + "k-", "t" + "vly-", "gh" + "p_", "github" + "_pat_", "nv" + "api-", "gs" + "k_",
                           "AI" + "za")))
TAILNET = re.compile(r"\b100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.(\d{1,3})\.(\d{1,3})\b")
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
HOME_PATH = re.compile(r"[A-Za-z]:\\\\?Users\\\\?[A-Za-z]|/home/(?!user\b)[a-z]+/|/Users/(?!user\b)[A-Za-z]+/")
C7_FILES = {
    "js_clean": ["package.json", "src/index.js", "src/util.js", "test/index.test.js", "README.md", "LICENSE",
                 ".github/workflows/ci.yml", ".env.example", "package-lock.json"],
    "js_risky": ["package.json", "server.js"],
    "js_broken": ["package.json", "src/index.ts", "src/half.js"],
    "jsx_torture": ["App.jsx", "util.tsx", "bin.mjs", "Quote.jsx", "package.json"],
}
PLANTED = ("<p>a</p>{eval(location.hash)}<p>b</p>", "<p>Don't</p>{eval(location.hash)}",
           "https://example.org</a>{eval(location.hash)}", "<p>Don't</p>{eval(location.hash)}<p>didn't</p>")


def _golden_mod():
    sys.path.insert(0, str(HERE))
    import test_golden
    return test_golden


def _scan(path, *extra):
    p = subprocess.run([sys.executable, "-m", "code_guardian", "scan", str(path), "--json"] + list(extra),
                       cwd=str(ROOT), capture_output=True, text=True, encoding="utf-8", timeout=300,
                       env=dict(os.environ, PYTHONPATH=str(ROOT)))
    return p.returncode, json.loads(p.stdout)


def _copy(src, dest, eol):
    shutil.copytree(src, dest)
    for dirpath, _, files in os.walk(dest):
        for name in files:
            f = Path(dirpath) / name
            data = f.read_bytes()
            if b"\0" in data:
                continue
            data = data.replace(b"\r\n", b"\n")
            f.write_bytes(data.replace(b"\n", b"\r\n") if eol == "crlf" else data)
    return dest


def _python_fixtures():
    return sorted(p.name for p in FIXTURES.iterdir() if p.is_dir() and p.name not in JS_FIXTURES)


def _before_values_apply():
    return importlib.util.find_spec("code_guardian.scanners_js") is None


# ---- C5: the golden harness ----------------------------------------------------------------------------------------

def test_harness_constants():
    g = _golden_mod()
    assert set(g.EXCLUDED) == FOUR_KEYS and len(g.EXCLUDED) == 4, g.EXCLUDED
    assert set(g.ADDITIVE) == ADDITIVE_SET, g.ADDITIVE
    assert sorted(g.GOLDEN_FIXTURES) == _python_fixtures(), (g.GOLDEN_FIXTURES, _python_fixtures())


@pytest.mark.parametrize("name", ["backup_repo", "clean_repo", "complete_app", "complete_bare", "orphan_repo",
                                  "risky_repo", "supply_repo", "works_broken", "works_weak_tests"])
def test_golden_file_exists(name):
    path = GOLDEN / ("%s.json" % name)
    assert path.is_file(), "missing %s" % path.name
    data = json.loads(path.read_text(encoding="utf-8"))
    assert not FOUR_KEYS & set(data), "an excluded key is in %s" % path.name
    assert "findings" in data and "scores" in data


def test_golden_is_green():
    g = _golden_mod()
    p = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", str(HERE / "test_golden.py")],
                       cwd=str(ROOT), capture_output=True, text=True, timeout=900,
                       env=dict(os.environ, PYTHONPATH=str(ROOT)))
    tail = p.stdout.strip().splitlines()[-1] if p.stdout.strip() else p.stderr[-400:]
    assert p.returncode == 0 and ("%d passed" % len(g.GOLDEN_FIXTURES)) in tail, tail


@pytest.mark.parametrize("name", ["clean_repo", "complete_bare"])
def test_golden_rederived_by_the_overseer(name, tmp_path):
    _, rep = _scan(_copy(FIXTURES / name, tmp_path / name, "lf"))
    for k in FOUR_KEYS:
        rep.pop(k, None)
    golden = json.loads((GOLDEN / ("%s.json" % name)).read_text(encoding="utf-8"))
    assert rep == golden, "%s: the recorded golden is not today's report" % name


def test_canonical_does_not_depend_on_line_endings(tmp_path):
    g = _golden_mod()
    crlf = _copy(FIXTURES / "complete_bare", tmp_path / "complete_bare", "crlf")
    golden = json.loads((GOLDEN / "complete_bare.json").read_text(encoding="utf-8"))
    assert g.canonical(crlf) == golden


def test_golden_catches_a_change_in_every_report(tmp_path):
    g = _golden_mod()
    copy = tmp_path / "repo"
    shutil.copytree(ROOT, copy, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc", "dist", "build",
                                                              ".venv", "node_modules"))
    score = copy / "code_guardian" / "score.py"
    text = score.read_text(encoding="utf-8")
    new, n = re.subn(r'(WEIGHTS_RULE\s*=\s*\(?\s*")', r'\1P81 mutation: ', text, count=1)
    assert n == 1, "score.WEIGHTS_RULE not found"
    score.write_text(new, encoding="utf-8")
    p = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/test_golden.py"],
                       cwd=str(copy), capture_output=True, text=True, timeout=900,
                       env=dict(os.environ, PYTHONPATH=str(copy)))
    tail = p.stdout.strip().splitlines()[-1] if p.stdout.strip() else p.stderr[-400:]
    assert p.returncode != 0 and ("%d failed" % len(g.GOLDEN_FIXTURES)) in tail, tail


# ---- C7: the four JS fixtures and make_risky_js ----------------------------------------------------------------------

@pytest.mark.parametrize("fixture", sorted(C7_FILES))
def test_js_fixture_files(fixture):
    missing = [f for f in C7_FILES[fixture] if not (FIXTURES / fixture / f).is_file()]
    assert not missing, "%s lacks %s" % (fixture, missing)


def test_js_fixture_content():
    server = (FIXTURES / "js_risky" / "server.js").read_text(encoding="utf-8")
    for needle in ("eval(req.query.code)", "child_process", "innerHTML", "location.hash", "rejectUnauthorized",
                   "0.0.0.0", "example.org", "atob(", "/etc/motd", "console.log(password)"):
        assert needle in server, "js_risky/server.js lacks %r" % needle
    pkg = json.loads((FIXTURES / "js_risky" / "package.json").read_text(encoding="utf-8"))
    assert "postinstall" in pkg.get("scripts", {}) and "*" in pkg.get("dependencies", {}).values()
    assert "Example Author" in (FIXTURES / "js_clean" / "LICENSE").read_text(encoding="utf-8")
    jsx = "\n".join((FIXTURES / "jsx_torture" / n).read_text(encoding="utf-8") for n in ("App.jsx", "Quote.jsx"))
    for line in PLANTED:
        assert line in jsx, "jsx_torture lacks the planted line %r" % line
    assert "`" in (FIXTURES / "jsx_torture" / "Quote.jsx").read_text(encoding="utf-8")
    assert (FIXTURES / "jsx_torture" / "bin.mjs").read_text(encoding="utf-8").startswith("#!")


def _text_files():
    roots = [FIXTURES / f for f in JS_FIXTURES] + [HERE / "make_risky_js.py"]
    for root in roots:
        files = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file()]
        for p in files:
            yield p, p.read_bytes().decode("utf-8", "replace")


def test_js_fixtures_hold_no_key_shape_and_no_private_detail():
    hits = []
    for p, text in _text_files():
        rel = p.relative_to(ROOT).as_posix()
        if KEY_SHAPE.search(text):
            hits.append((rel, "key shape"))
        for m in TAILNET.finditer(text):
            if not (m.group(2) == "0" and 1 <= int(m.group(3)) <= 20 and m.group(0).startswith("100.64.")):
                hits.append((rel, "tailnet address"))
        for m in EMAIL.finditer(text):
            if not re.search(r"(example\.(com|org)|users\.noreply\.github\.com)$", m.group(0)):
                hits.append((rel, "email"))
        if HOME_PATH.search(text):
            hits.append((rel, "personal path"))
    assert not hits, hits


def test_make_risky_js_writes_its_key_at_test_time(tmp_path):
    sys.path.insert(0, str(HERE))
    import make_risky_js
    built = Path(make_risky_js.build(tmp_path / "js_risky"))
    assert any(KEY_SHAPE.search(p.read_text(encoding="utf-8", errors="replace"))
               for p in built.rglob("*") if p.is_file()), "the built copy holds no key-shaped value"
    assert not any(KEY_SHAPE.search(t) for _, t in _text_files())


# ---- the "before" values S4 flips (stand down once scanners_js exists) -----------------------------------------------

def _no_exec(rep):
    return not [f for f in rep["findings"] if f["code"].startswith("exec.")]


@pytest.mark.skipif(not _before_values_apply(), reason="JS analysis is in (S2+): S4's acceptance owns these values")
def test_before_js_clean():
    _, rep = _scan(FIXTURES / "js_clean")
    assert rep["status"] == "PARTIAL" and rep["scores"]["grade"] in GRADES_B_OR_LOWER and _no_exec(rep), (
        rep["status"], rep["scores"]["grade"])


@pytest.mark.skipif(not _before_values_apply(), reason="JS analysis is in (S2+): S4's acceptance owns these values")
def test_before_js_risky(tmp_path):
    sys.path.insert(0, str(HERE))
    import make_risky_js
    _, rep = _scan(make_risky_js.build(tmp_path / "js_risky"))
    assert rep["status"] == "PARTIAL" and rep["scores"]["grade"] in GRADES_B_OR_LOWER and _no_exec(rep), (
        rep["status"], rep["scores"]["grade"])


@pytest.mark.skipif(not _before_values_apply(), reason="JS analysis is in (S2+): S4's acceptance owns these values")
def test_before_jsx_torture():
    _, rep = _scan(FIXTURES / "jsx_torture")
    other = [(f["code"], f["level"]) for f in rep["findings"] if not f["code"].startswith("complete.")]
    assert rep["status"] == "PARTIAL" and not other, (rep["status"], other)


@pytest.mark.skipif(not _before_values_apply(), reason="JS analysis is in (S2+): S4's acceptance owns these values")
def test_before_index_js_only_is_invalid(tmp_path):
    (tmp_path / "only").mkdir()
    (tmp_path / "only" / "index.js").write_text("console.log(1)\n", encoding="utf-8")
    code, rep = _scan(tmp_path / "only")
    assert code == 3 and rep["status"] == "INVALID", (code, rep["status"])


# ---- the calibration pins ------------------------------------------------------------------------------------------

def _calibration_section():
    text = (ROOT / "calibration.md").read_text(encoding="utf-8")
    head = r"^#+ JavaScript / TypeScript calibration set \(P81\)\s*$"
    m = re.search(head + r"(.*?)(?=^#{1,3} |\Z)", text, re.M | re.S)
    assert m, "calibration.md has no 'JavaScript / TypeScript calibration set (P81)' section"
    return m.group(1)


def test_calibration_pins_five_repos_with_shas():
    sec = _calibration_section()
    rows = [ln for ln in sec.splitlines() if ln.startswith("|")]
    for repo in ("expressjs/express", "fastify/fastify", "create-vite", "create-next-app", "juice-shop/juice-shop"):
        row = [r for r in rows if repo in r]
        assert row and re.search(r"\b[0-9a-f]{40}\b", row[0]), "no pinned 40-hex SHA for %s" % repo


def test_calibration_has_the_marker_check_and_both_lists():
    sec = _calibration_section()
    assert re.search(r"vuln-code-snippet.*\b(present|absent)\b", sec, re.S | re.I), "marker check"
    assert re.search(r"vuln-line", sec), "the marked vuln-line list"
    assert len(re.findall(r"\b[\w./-]+\.(?:ts|js|tsx|jsx):\d+\b", sec)) >= 1, "file:line ground-truth entries"
    assert re.search(r"\bin-category\b", sec, re.I), "the grep hits are classified"
