"""P81 S5b acceptance -- the owner's design reaction to the JavaScript screens (2026-10-26).

Written by the overseer on main (05aefaa) BEFORE the build session. The build session adds this file to the PR
byte-for-byte and never edits it. Pure ASCII on purpose (the em dash is written as \\u2014).

The reader is someone who built a project with AI and does not read code. The owner's reaction, in short: the "What was
checked" section should say that the scores come from it, should not use the word "token", and the JavaScript entry
should be two plain bullet lists (looked at / not looked at); and advice must be for the right language.

P81-S5b-1  "What was checked"
  * plain.checked_lines: the JavaScript / TypeScript entry and the generated entry gain two lists, "looked_at" and
    "not_looked_at", with exactly the wording below; their "text" says the same thing in one sentence; "depth" stays
    "tokens" (the JSON shape does not change). Every other entry has no lists (the key is absent or empty), and the
    Python entry's text is unchanged (P81 S5's test_python_entry_unchanged still holds).
  * The page: the depth chip for "tokens" reads "line by line" (never "token level"); an entry with lists shows them
    as a "Looked at" bullet list and a "Not looked at" bullet list instead of the sentence; under the section title,
    one line: INTRO below. The legend's "token level" entry becomes "line by line" with a plain explanation.
  * No new CSS token; contrast_check passes; the four JS screenshots are made again (they must differ from S5's).
P81-S5b-2  advice for the right language
  * catalogue.FIX_JS {code: text} for the codes whose Python advice is wrong in a JavaScript / TypeScript file;
    catalogue.js_only(rep) -> bool (JavaScript / TypeScript analysed and no Python file); catalogue.fix_for(code,
    locations, js_only_repo=False) -> the JS text when every location is JS, the Python text when none is, and
    "Python: <fix> JavaScript / TypeScript: <fix_js>" when both; a code with no FIX_JS row always gets its catalogue
    fix; an unknown code gets None. A location is "path:line" or a path; it is JS when the path ends in a JS / TS
    extension or its file name is package.json, tsconfig.json or jsconfig.json; "." (the project) is JS only when
    js_only_repo is true.
  * plain.finding_card(f, rep)["how"] and verify.plan(rep)["items"][i]["fix"] (so the Fix first screen and the MCP
    fix plan too) use fix_for. A finding's own "fix" field still wins in finding_card, as today.
"""
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
FIXTURES = HERE / "fixtures"
sys.path.insert(0, str(HERE))

DASH = "—"
INTRO = "The Safe and Works scores above come only from what is listed here as looked at."
JS_LOOKED_AT = [
    "what the code tells the computer to do, such as running a command, deleting a file or putting text on a web page",
    "which other code and packages it pulls in",
    "where it sends information, such as websites, servers and logs",
    "how it starts: what runs by itself when it is installed, and whether the file it starts from is there",
    "passwords, keys and hidden or scrambled text written into the files",
]
JS_NOT_LOOKED_AT = [
    "how information travels from one part of the code to another, such as from a form a visitor fills in to a line "
    "several steps later",
    "whether each piece of data is the kind the code expects, such as a number where a number belongs",
    "code that is written but never used",
]
GEN_LOOKED_AT = ["passwords and keys written into the files", "code that runs text as code, or unscrambles hidden text"]
GEN_NOT_LOOKED_AT = ["everything else"]
JS_TEXT = "read line by line. Looked at: %s. Not looked at: %s" % ("; ".join(JS_LOOKED_AT), "; ".join(JS_NOT_LOOKED_AT))
GEN_TEXT = "read only for two things. Looked at: %s. Not looked at: %s" % ("; ".join(GEN_LOOKED_AT),
                                                                          "; ".join(GEN_NOT_LOOKED_AT))
CSS_TOKENS_SHA = "63a37f4121499b65f3253a2caeae325f3101df64fdc668dc4bbb90d6e524f198"  # P81 S5's: 18 names, both blocks
S5_SHOTS = {  # sha256 of the four screenshots P81 S5 merged (main 05aefaa); S5b makes them again
    "result_js_dark_390x844.png": "04e4f947f5c3d68dd42b7eff0cf842c284a9ea512861320720b603195ea54d98",
    "result_js_light_390x844.png": "ee10547c9937d005c21e12c44ed395eef2024ea4c371e48d7bcc717497f69fda",
    "findings_js_dark_1280x800.png": "7e0fdba0c782239512ee03fab7906b6c8ff93f717ac8ccbe95e6727e06ca1e15",
    "findings_js_light_1280x800.png": "248f8c0778ba0c618d2d06b970adf13406b8474dd1b4ac85cb6ba7dbffb319b0",
}
# Python-only advice: none of it may reach a finding in a JavaScript / TypeScript file.
PY_ONLY = re.compile(r"ast\.literal_eval|shell=True|pytest|ImportError|Python 2|Python 3|abc\.abstractmethod|"
                     r"module:function|safetensors|yaml\.safe_load|subprocess|os\.system|tests/ folder")
JS_EXT = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")
JS_FILES = {"package.json", "tsconfig.json", "jsconfig.json"}
NEEDS_JS = ("exec.dynamic", "exec.shell", "deser.unsafe", "works.entry_missing", "works.import_unresolved",
            "works.syntax", "works.tests_missing")


def plain():
    from code_guardian import plain as p
    return p


def cat():
    from code_guardian import catalogue
    return catalogue


def scan(path):
    from code_guardian import report
    return report.scan(str(path))


def make(tmp_path, files, name="proj"):
    root = tmp_path / name
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text if isinstance(text, str) else json.dumps(text, indent=2), encoding="utf-8")
    return root


def js_risky(tmp_path):
    import make_risky_js
    return make_risky_js.build(tmp_path / "js_risky")


# A JavaScript-only project that sets off every NEEDS_JS code: works.entry_missing (package.json main), works.syntax
# (an unclosed template), works.import_unresolved (an undeclared package), works.tests_missing (no tests),
# exec.shell, exec.dynamic and deser.unsafe.
WORKS_JS = {
    "package.json": {"name": "p", "version": "1.0.0", "main": "gone.js", "dependencies": {"node-serialize": "0.0.4"}},
    "src/a.js": "const x = require('left-pad');\nmodule.exports = x;\n",
    "src/b.js": "const s = `never closed\n",
    "src/c.js": ("const cp = require('child_process');\nconst s = require('node-serialize');\n"
                 "module.exports = function (req) {\n  cp.exec('ls ' + req.query.dir);\n  eval(req.query.code);\n"
                 "  return s.unserialize(req.body);\n};\n"),
}


def _path(node):
    node = str(node or "")
    return re.sub(r":\d+$", "", node)


def _is_js(node, js_only):
    p = _path(node)
    if p in (".", ""):
        return js_only
    return p.endswith(JS_EXT) or p.rsplit("/", 1)[-1] in JS_FILES


# ---- P81-S5b-1: the checked lines ---------------------------------------------------------------------------------

def test_js_entry_is_two_plain_lists():
    e = [e for e in plain().checked_lines(scan(FIXTURES / "js_clean")) if e["label"] == "JavaScript / TypeScript"]
    assert len(e) == 1, e
    e = e[0]
    assert (e["files"], e["depth"]) == (3, "tokens")
    assert e["looked_at"] == JS_LOOKED_AT and e["not_looked_at"] == JS_NOT_LOOKED_AT
    assert e["text"] == "JavaScript / TypeScript: 3 files %s %s." % (DASH, JS_TEXT)


def test_generated_entry_is_two_plain_lists(tmp_path):
    root = make(tmp_path, {"web/a.js": "module.exports = 1;\n", "vendor/lib.min.js": "var a = 1;\n",
                           "package.json": {"name": "p", "version": "1.0.0", "scripts": {"test": "node t.js"}}})
    gen = [e for e in plain().checked_lines(scan(root)) if e["label"] == "JavaScript (minified or generated)"]
    assert len(gen) == 1, gen
    g = gen[0]
    assert (g["files"], g["depth"]) == (1, "tokens")
    assert g["looked_at"] == GEN_LOOKED_AT and g["not_looked_at"] == GEN_NOT_LOOKED_AT
    assert g["text"] == "JavaScript (minified or generated): 1 file %s %s." % (DASH, GEN_TEXT)


def test_other_entries_have_no_lists(tmp_path):
    root = make(tmp_path, {"app.py": "print(1)\n", "tests/test_app.py": "def test_a():\n    assert 1\n",
                           "web/a.js": "module.exports = 1;\n", "tool.go": "package main\n"})
    for e in plain().checked_lines(scan(root)):
        if e["label"] not in ("JavaScript / TypeScript", "JavaScript (minified or generated)"):
            assert not e.get("looked_at") and not e.get("not_looked_at"), e


@pytest.mark.parametrize("name", ["js_clean", "js_broken", "jsx_torture", "js_risky"])
def test_no_token_word_in_what_was_checked(name, tmp_path):
    root = js_risky(tmp_path) if name == "js_risky" else FIXTURES / name
    for e in plain().checked_lines(scan(root)):
        words = " ".join([e["text"]] + list(e.get("looked_at") or []) + list(e.get("not_looked_at") or []))
        assert "token" not in words.lower(), e


def _read(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def test_page_words():
    app, html = _read("code_guardian/ui/app.js"), _read("code_guardian/ui/index.html")
    assert '"line by line"' in app and "token level" not in app
    assert "looked_at" in app and "not_looked_at" in app
    assert '"Looked at"' in app and '"Not looked at"' in app
    assert INTRO in html
    assert "line by line" in html and "token level" not in html


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


@pytest.mark.parametrize("name", sorted(S5_SHOTS))
def test_screenshots_made_again(name):
    path = ROOT / "docs" / "screenshots" / name
    assert path.is_file(), name
    assert hashlib.sha256(path.read_bytes()).hexdigest() != S5_SHOTS[name], "%s is still P81 S5's" % name


# ---- P81-S5b-2: advice for the right language ---------------------------------------------------------------------

def test_fix_js_table():
    c = cat()
    assert set(NEEDS_JS) <= set(c.FIX_JS) <= set(c.CATALOGUE), sorted(c.FIX_JS)
    for code, text in c.FIX_JS.items():
        assert text and not PY_ONLY.search(text), (code, text)
        assert " -- " not in text and plain().VERDICT_PHRASES.search(text) is None, (code, text)
    assert "JSON.parse" in c.FIX_JS["exec.dynamic"]
    assert "execFile" in c.FIX_JS["exec.shell"] or "spawn" in c.FIX_JS["exec.shell"]
    assert "package.json" in c.FIX_JS["works.import_unresolved"]
    assert "package.json" in c.FIX_JS["works.entry_missing"]


def test_fix_for_rules():
    c = cat()
    py, js = c.CATALOGUE["exec.dynamic"]["fix"], c.FIX_JS["exec.dynamic"]
    assert c.fix_for("exec.dynamic", ["server.js:14"]) == js
    assert c.fix_for("exec.dynamic", ["src/App.tsx:3", "lib/x.mjs:9"]) == js
    assert c.fix_for("exec.dynamic", ["app.py:3"]) == py
    assert c.fix_for("exec.dynamic", []) == py
    assert c.fix_for("exec.dynamic", ["app.py:3", "web/a.js:2"]) == "Python: %s JavaScript / TypeScript: %s" % (py, js)
    assert c.fix_for("works.entry_missing", ["package.json:2"]) == c.FIX_JS["works.entry_missing"]
    assert c.fix_for("works.entry_missing", ["pyproject.toml:12"]) == c.CATALOGUE["works.entry_missing"]["fix"]
    assert c.fix_for("works.tests_missing", ["."]) == c.CATALOGUE["works.tests_missing"]["fix"]
    assert c.fix_for("works.tests_missing", ["."], True) == c.FIX_JS["works.tests_missing"]
    assert c.fix_for("tls.off", ["server.js:11"]) == c.CATALOGUE["tls.off"]["fix"]  # no FIX_JS row: unchanged
    assert c.fix_for("no.such.code", ["server.js:1"]) is None


def test_js_only():
    c = cat()
    assert c.js_only(scan(FIXTURES / "js_clean")) is True
    assert c.js_only(scan(FIXTURES / "clean_repo")) is False


def test_js_findings_get_js_advice(tmp_path):
    p, c = plain(), cat()
    seen = set()
    for root in (js_risky(tmp_path), FIXTURES / "js_broken", FIXTURES / "jsx_torture", make(tmp_path, WORKS_JS)):
        rep = scan(root)
        only = c.js_only(rep)
        for f in rep["findings"]:
            if not _is_js(f.get("node"), only):
                continue
            how = p.finding_card(f, rep)["how"]
            assert how and not PY_ONLY.search(how), (str(root.name), f["code"], f.get("node"), how)
            if f["code"] in c.FIX_JS:
                assert how == c.FIX_JS[f["code"]], (f["code"], how)
                seen.add(f["code"])
    assert set(NEEDS_JS) <= seen, sorted(set(NEEDS_JS) - seen)


def test_fix_first_and_the_mcp_plan_use_js_advice(tmp_path):
    from code_guardian import verify
    p, c = plain(), cat()
    rep = scan(make(tmp_path, WORKS_JS))
    items = verify.plan(rep, top=50)["items"]
    codes = {i["code"]: i for i in items}
    assert "exec.dynamic" in codes and codes["exec.dynamic"]["fix"] == c.FIX_JS["exec.dynamic"]
    for i in items:
        assert not PY_ONLY.search(i["fix"] or ""), (i["code"], i["fix"])
    for row in p.fix_first(rep, top=50):
        assert not PY_ONLY.search(row["how"] or ""), row


def test_python_advice_unchanged(tmp_path):
    import make_risky
    p, c = plain(), cat()
    for root in (make_risky.build(tmp_path / "risky_repo"), FIXTURES / "works_broken", FIXTURES / "supply_repo"):
        rep = scan(root)
        for f in rep["findings"]:
            if _is_js(f.get("node"), c.js_only(rep)):
                continue
            entry = c.CATALOGUE.get(f["code"]) or {}
            assert p.finding_card(f, rep)["how"] == (f.get("fix") or entry.get("fix")), (f["code"], f.get("node"))
