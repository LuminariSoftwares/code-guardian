"""P81 S5 acceptance -- the plain-language layer and the page for JavaScript / TypeScript (P81 C6).

Written by the overseer on main (9a9d7e1) BEFORE the build session. The build session adds this file to the PR
byte-for-byte and never edits it. Pure ASCII on purpose (the em dash the sentences use is written as \\u2014).

C6, with the overseer's precisions marked P:
  checked_lines gains, after the Python entry and before the per-extension entries, a "JavaScript / TypeScript" entry
  (depth "tokens") when the report analysed JS/TS files, and a "JavaScript (minified or generated)" entry (depth
  "tokens") when it saw generated files. The Python entry's text is unchanged on every existing fixture.
  P1 The C6 text uses " -- "; plain.py's sentences use an em dash there (a test forbids an ASCII double dash), so the
     entry reads "JavaScript / TypeScript: <n> files \\u2014 analysed at token level: ...".
  P2 C6 says generated files are "secrets only", but C2 also runs obfuscation and exec.dynamic on them, so that would
     be false. The generated entry says what ran: GENERATED_TEXT below.
  P3 When a report has no Python file but did analyse JavaScript / TypeScript, the Python entry is left out (it would
     say "there was no Python here for the Safe and Works checks to read" while those checks ran on the JavaScript).
     With no Python and no JavaScript the Python entry stays as it is.
  P4 file_rows: an analysed JS/TS file with no Safe finding is "No known risks found"; one with a works.syntax FAIL
     (it stops tokenising) is "Partly checked" with a why_partly that says so; a generated file with no Safe finding is
     "Partly checked" with a why_partly naming "minified or generated". "JavaScript code is not analysed yet" never
     appears for a .js/.mjs/.cjs/.jsx/.ts/.tsx file. Other languages are unchanged (Go: "Go code is not analysed yet").
  P5 The page shows a depth as a chip: full -> "in depth", tokens -> "token level" (app.js), and index.html carries
     "token level" too. No new CSS token in either theme block; tools/contrast_check.py passes on app.css.
  P6 Four screenshots, made in the build session's container against tests/fixtures/js_risky (keys built by
     make_risky_js): docs/screenshots/result_js_{dark,light}_390x844.png and findings_js_{dark,light}_1280x800.png. The
     overseer looks at all four.
"""
import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
FIXTURES = HERE / "fixtures"
sys.path.insert(0, str(HERE))

DASH = "\u2014"
JS_TEXT = ("analysed at token level: what the code calls, what it imports and loads, where it sends data, how it "
           "starts, and the text itself; not checked: how values move between functions, types, unused code")
GENERATED_TEXT = "read for key shapes and for code that runs text or decodes hidden text; nothing else was checked"
PYTHON_LINES = {
    "backup_repo": "Python: 5 files \u2014 every Safe and Works check ran on these.",
    "clean_repo": "Python: 4 files \u2014 every Safe and Works check ran on these.",
    "complete_app": "Python: 3 files \u2014 every Safe and Works check ran on these.",
    "complete_bare": "Python: 1 file \u2014 every Safe and Works check ran on these.",
    "orphan_repo": "Python: 6 files \u2014 every Safe and Works check ran on these.",
    "risky_repo": "Python: 7 files \u2014 every Safe and Works check ran on these.",
    "supply_repo": "Python: 2 files \u2014 every Safe and Works check ran on these.",
    "works_broken": ("Python: 3 files \u2014 the Safe and Works checks ran on these, except where the first line says "
                     "otherwise."),
    "works_weak_tests": "Python: 2 files \u2014 every Safe and Works check ran on these.",
}
CSS_TOKENS_SHA = "63a37f4121499b65f3253a2caeae325f3101df64fdc668dc4bbb90d6e524f198"  # 18 names, both blocks, on main
JS_EXT = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")


def plain():
    from code_guardian import plain as p
    return p


def scan(path):
    from code_guardian import report
    return report.scan(str(path))


def source(name, tmp_path):
    if name == "risky_repo":
        import make_risky
        return make_risky.build(tmp_path / name)
    if name == "js_risky":
        import make_risky_js
        return make_risky_js.build(tmp_path / name)
    return FIXTURES / name


def make(tmp_path, files, name="proj"):
    root = tmp_path / name
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text if isinstance(text, str) else json.dumps(text, indent=2), encoding="utf-8")
    return root


def rows_of(root):
    from code_guardian import walk
    return {r["rel"]: r for r in plain().file_rows(scan(root), walk.walk(str(root)))}


# ---- checked_lines -----------------------------------------------------------------------------------------------------

def test_js_clean_checked_lines():
    lines = plain().checked_lines(scan(FIXTURES / "js_clean"))
    assert [e["label"] for e in lines] == ["JavaScript / TypeScript"], lines
    e = lines[0]
    assert (e["files"], e["depth"]) == (3, "tokens")
    assert e["text"] == "JavaScript / TypeScript: 3 files %s %s." % (DASH, JS_TEXT)


def test_order_and_the_generated_entry(tmp_path):
    root = make(tmp_path, {"app.py": "print(1)\n", "tests/test_app.py": "def test_a():\n    assert 1\n",
                           "web/a.js": "module.exports = 1;\n", "web/tool.go": "package main\n",
                           "vendor/lib.min.js": "var a = 1;\n"})
    lines = plain().checked_lines(scan(root))
    labels = [e["label"] for e in lines if e["label"] != "Not fully checked"]
    assert labels == ["Python", "JavaScript / TypeScript", "JavaScript (minified or generated)", "Go"], labels
    gen = [e for e in lines if e["label"] == "JavaScript (minified or generated)"][0]
    assert (gen["files"], gen["depth"]) == (1, "tokens")
    assert gen["text"] == "JavaScript (minified or generated): 1 file %s %s." % (DASH, GENERATED_TEXT)


def test_no_python_and_no_javascript_keeps_the_python_line(tmp_path):
    root = make(tmp_path, {"package.json": {"name": "p", "version": "1.0.0"}, "main.go": "package main\n"})
    labels = [e["label"] for e in plain().checked_lines(scan(root))]
    assert "Python" in labels and "JavaScript / TypeScript" not in labels


@pytest.mark.parametrize("name", sorted(PYTHON_LINES))
def test_python_entry_unchanged(name, tmp_path):
    py = [e for e in plain().checked_lines(scan(source(name, tmp_path))) if e["label"] == "Python"]
    assert len(py) == 1 and py[0]["text"] == PYTHON_LINES[name], py


# ---- harm, verdict words -----------------------------------------------------------------------------------------------

def test_harm_on_the_js_fixtures(tmp_path):
    p = plain()
    assert p.harm(scan(source("js_risky", tmp_path)))["level"] == p.HIGH
    clean = p.harm(scan(FIXTURES / "js_clean"))
    assert clean["level"] == p.NONE_FOUND and clean["partial"] is False
    assert p.harm(scan(FIXTURES / "js_broken"))["level"] == p.NONE_FOUND


ALL_FIXTURES = sorted(p.name for p in FIXTURES.iterdir() if p.is_dir())


@pytest.mark.parametrize("name", ALL_FIXTURES)
def test_no_verdict_phrase_anywhere(name, tmp_path):
    from code_guardian import walk
    p = plain()
    root = source(name, tmp_path)
    rep = scan(root)
    texts = [e["text"] for e in p.checked_lines(rep)] + [p.harm(rep)["why"]]
    texts += [p.score_sentence(d, rep) for d in ("safe", "works", "complete", "overall")]
    texts += [r["why_partly"] or "" for r in p.file_rows(rep, walk.walk(str(root)))]
    bad = [t for t in texts if p.VERDICT_PHRASES.search(t or "") or " -- " in (t or "")]
    assert not bad, bad


# ---- file rows (P4) ----------------------------------------------------------------------------------------------------

def test_file_rows_for_javascript(tmp_path):
    p = plain()
    clean = rows_of(FIXTURES / "js_clean")
    for rel in ("src/index.js", "src/util.js", "test/index.test.js"):
        assert clean[rel]["risk"] == p.NONE_FOUND and not clean[rel]["why_partly"], clean[rel]
    half = rows_of(FIXTURES / "js_broken")["src/half.js"]
    assert half["risk"] == "Partly checked" and half["why_partly"], half
    root = make(tmp_path, {"app.js": "module.exports = 1;\n", "vendor/lib.min.js": "var a = 1;\n",
                           "tool.go": "package main\n", "package.json": {"name": "p", "version": "1.0.0"}})
    rows = rows_of(root)
    assert rows["app.js"]["risk"] == p.NONE_FOUND
    assert rows["vendor/lib.min.js"]["risk"] == "Partly checked"
    assert "minified or generated" in rows["vendor/lib.min.js"]["why_partly"]
    assert rows["tool.go"]["risk"] == "Partly checked" and "Go code is not analysed yet" in rows["tool.go"]["why_partly"]
    for fx in ("js_clean", "js_broken", "jsx_torture"):
        for rel, r in rows_of(FIXTURES / fx).items():
            if rel.endswith(JS_EXT):
                assert "not analysed yet" not in (r["why_partly"] or ""), (fx, rel, r)


# ---- the page (P5, P6) -------------------------------------------------------------------------------------------------

def _read(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def test_depth_chip_words():
    app = _read("code_guardian/ui/app.js")
    assert '"token level"' in app and '"in depth"' in app
    assert "token level" in _read("code_guardian/ui/index.html")


def test_no_new_css_token_and_contrast_holds():
    css = _read("code_guardian/ui/app.css")
    blocks = re.findall(r':root(?:\[data-theme="([^"]*)"\])?\s*\{(.*?)\}', css, re.S)
    assert len(blocks) == 2, [b[0] for b in blocks]
    for theme, body in blocks:
        names = sorted(set(re.findall(r"(--[\w-]+)\s*:", body)))
        assert hashlib.sha256(" ".join(names).encode()).hexdigest() == CSS_TOKENS_SHA, (theme or "dark", names)
    r = subprocess.run([sys.executable, "tools/contrast_check.py", "code_guardian/ui/app.css"], cwd=str(ROOT),
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stdout[-800:] + r.stderr[-800:]


def _png_width(path):
    with open(path, "rb") as fh:
        head = fh.read(24)
    assert head[:8] == b"\x89PNG\r\n\x1a\n", path
    return struct.unpack(">II", head[16:24])


@pytest.mark.parametrize("name,widths", [("result_js_dark_390x844.png", (390, 780)),
                                         ("result_js_light_390x844.png", (390, 780)),
                                         ("findings_js_dark_1280x800.png", (1280, 2560)),
                                         ("findings_js_light_1280x800.png", (1280, 2560))])
def test_screenshots(name, widths):
    path = ROOT / "docs" / "screenshots" / name
    assert path.is_file(), name
    w, h = _png_width(path)
    assert w in widths and h >= 800, (name, w, h)
