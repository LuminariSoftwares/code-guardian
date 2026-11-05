"""P81 S4 acceptance -- JavaScript / TypeScript wired into the scan: walk, report, coverage v3, outputs, CI, README,
CHANGELOG, ADR (P81 C4 C5 C8 C9 C10 C11).

Written by the overseer on main (c024b0f) BEFORE the build session. The build session adds this file to the PR
byte-for-byte and never edits it. Pure ASCII on purpose; no key-shaped value anywhere.

The overseer's precisions, marked P:
  P1 tests/golden/risky_repo.delta.json is written by the build session from its first real run, and THIS file checks
     it against C5's list value by value (the plan had the overseer record it; a mechanical check of every allowed
     key is stronger than a hand copy). Its "replace" keys must be a subset of DELTA_ALLOWED.
  P2 files.javascript and files.generated are always present (0 when none); coverage.languages is present whenever a
     language has files (a Python-only report gains only languages.python).
  P3 works.tests_missing fires once for the repo: works_js fires it only with no Python files (S3), and report.scan
     drops the Python one when the JS side has a test signal (a test file or a non-default scripts.test).
  P4 The CHANGELOG entry goes under "## code-guardian-mcp 0.5.0 (unreleased)" (S6 dates it): two release tests already
     in the repo require "## Unreleased" to be empty.
  P5 The ADR is docs/adr/0011-javascript-typescript-at-token-level.md (0008 to 0010 are taken).
  P7 The overseer amended eight of its earlier test files for this section (step 1 of the prompt): P76 S1 / S3b use
     Go, not JavaScript, as the secret-scan-only language; P76 S4's explain digest and P78 S3's web/setup.js row allow
     the one finding P81 S4 adds; P81 S0b and P88 S1/S3/S4 compare reports the way test_golden does. The two amended
     P76 checksums below are the amended files'.
  P6 The calibration table (C9) is the overseer's run on the five pinned repos after this PR is green; it is sent as a
     follow-up and is not checked here.
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
GOLDEN = HERE / "golden"
sys.path.insert(0, str(HERE))

C2_CODES = {"exec.dynamic", "exec.shell", "deser.unsafe", "net.egress", "net.bind_all", "tls.off", "obfuscation",
            "fs.outside", "privacy.pii_log", "dom.html_sink"}
GENERATED_CHECKS = ["secret.key", "obfuscation", "exec.dynamic"]
DELTA_ALLOWED = {"files.other", "other_languages", "coverage.other_source", "coverage.other_source_files",
                 "coverage.analysed", "outcomes", "findings", "egress", "dimensions.safe.checks"}
UNCHANGED_LF_MD5 = {"code_guardian/scanners.py": "b7012b49f8b94b43c90246aa630c4773",
                    "code_guardian/works.py": "689717efa537e72b1bc43ec258cd496e",
                    "tests/test_p76_s1_acceptance.py": "d33c19491d77acdca858b9e1c9c3bff7",
                    "tests/test_p76_s2_acceptance.py": "6a2c930d1263a7d45f3e6f8de2e44696",
                    "tests/test_p76_s3_acceptance.py": "8b8c1ec7a72b542d821d1ad168abda76",
                    "tests/test_p76_s4_acceptance.py": "daffeea5fa6e5b5024e91c2758fe3c18",
                    "tests/test_p76_s5_acceptance.py": "14f41ea24dbd2fddf9f9a0ed4adfa50d"}
JSX_STRAY = "after a stray backtick in JSX text"
JSX_INFO = "code-like text inside JSX text was not analysed"


def scan(path, *extra):
    from code_guardian import report
    return report.scan(str(path), *extra)


def cli(*args):
    return subprocess.run([sys.executable, "-m", "code_guardian"] + list(args), cwd=str(ROOT), capture_output=True,
                          text=True, encoding="utf-8", timeout=600)


def triples(rep, code=None):
    return {(f["code"], f["level"], f["node"]) for f in rep["findings"] if code is None or f["code"] == code}


def make(tmp_path, files, name="proj"):
    root = tmp_path / name
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text if isinstance(text, str) else json.dumps(text, indent=2), encoding="utf-8")
    return root


def js_only(tmp_path):
    """The CI job's JavaScript-only repo (ci.yml), built the same way."""
    return make(tmp_path, {"package.json": '{"name": "demo", "version": "1.0.0"}\n',
                           "src/index.js": 'const app = require("express")();\n'
                                           'app.get("/", (q, r) => r.send(eval(q.query.x)));\n',
                           "README.md": "# demo\n"}, "js_only")


# ---- schema, Python-only reports ---------------------------------------------------------------------------------------

def test_schema_version_is_3():
    from code_guardian import report
    assert report.SCHEMA_VERSION == 3
    assert scan(FIXTURES / "clean_repo")["schema_version"] == 3


def test_python_only_report_gains_only_the_additive_keys():
    rep = scan(FIXTURES / "clean_repo")
    checks = {o["check"] for o in rep["outcomes"]}
    assert not checks & {"javascript", "js_works"}, checks
    assert rep["files"]["javascript"] == 0 and rep["files"]["generated"] == 0
    assert rep["coverage"]["languages"] == {"python": {"files": rep["coverage"]["python"], "depth": "full"}}
    assert rep["coverage"]["analysed"] == "python"


# ---- the risky_repo delta (P1) -----------------------------------------------------------------------------------------

def _golden(name):
    return json.loads((GOLDEN / ("%s.json" % name)).read_text(encoding="utf-8"))


def _drop(rows, extra):
    rows = list(rows)
    for x in extra:
        rows.remove(x)
    return rows


def test_risky_delta_is_exactly_c5s_list():
    path = GOLDEN / "risky_repo.delta.json"
    assert path.is_file(), "tests/golden/risky_repo.delta.json is missing"
    delta = json.loads(path.read_text(encoding="utf-8"))["replace"]
    assert set(delta) <= DELTA_ALLOWED, sorted(set(delta) - DELTA_ALLOWED)
    g = _golden("risky_repo")
    assert delta["files.other"] == g["files"]["other"] - 1
    assert ".js" not in delta["other_languages"] and ".js" in g["other_languages"]
    assert delta["coverage.other_source"] == {k: v for k, v in g["coverage"]["other_source"].items() if k != ".js"}
    assert delta["coverage.other_source_files"] == g["coverage"]["other_source_files"] - 1
    assert delta["coverage.analysed"] == "python+javascript"
    new_rows = [o for o in delta["outcomes"] if o not in g["outcomes"]]
    assert sorted(o["check"] for o in new_rows) == ["javascript", "js_works"]
    assert all(o["outcome"] == "ran" for o in new_rows) and len(delta["outcomes"]) == len(g["outcomes"]) + 2
    added = [f for f in delta["findings"] if f not in g["findings"]]
    assert [(f["code"], f["level"], f["node"]) for f in added] == [("net.egress", "INFO", "web/setup.js:1")]
    assert _drop(delta["findings"], added) == g["findings"]
    eg = [e for e in delta["egress"] if e not in g["egress"]]
    assert [(e["node"], e["level"]) for e in eg] == [("web/setup.js:1", "INFO")]
    assert _drop(delta["egress"], eg) == g["egress"]
    if "dimensions.safe.checks" in delta:
        old = {(c["code"], c["level"]): c for c in g["dimensions"]["safe"]["checks"]}
        new = {(c["code"], c["level"]): c for c in delta["dimensions.safe.checks"]}
        moved = {k for k in set(old) | set(new) if old.get(k) != new.get(k)}
        assert moved == {("net.egress", "INFO")}, moved
        row = new[("net.egress", "INFO")]
        assert row["weight"] == 0 and "web/setup.js:1" in json.dumps(row)


def test_risky_report_scores_and_coverage(tmp_path):
    import make_risky
    rep = scan(make_risky.build(tmp_path / "risky_repo"))
    g = _golden("risky_repo")
    for key in ("scores", "status", "hygiene"):
        assert rep[key] == g[key], key
    assert rep["files"]["javascript"] == 1 and rep["files"]["generated"] == 0
    from code_guardian import report
    assert report.coverage_line(rep["coverage"]) == (
        "coverage: %d Python analysed; 1 JavaScript/TypeScript analysed (token level)" % rep["coverage"]["python"])


# ---- the JavaScript fixtures -------------------------------------------------------------------------------------------

def test_js_only_ci_case(tmp_path):
    root = js_only(tmp_path)
    rep = scan(root)
    assert rep["status"] == "COMPLETE", rep["status_reasons"]
    assert ("exec.dynamic", "FAIL", "src/index.js:2") in triples(rep)
    assert rep["scores"]["works"] is not None
    js = rep["coverage"]["languages"]["javascript"]
    assert js["depth"] == "tokens" and js["files"] == 1
    assert "python" not in rep["coverage"]["languages"]
    assert {"javascript", "js_works"} <= {o["check"] for o in rep["outcomes"] if o["outcome"] == "ran"}
    assert cli("scan", str(root)).returncode == 1


def test_js_clean_is_complete_and_a():
    rep = scan(FIXTURES / "js_clean")
    assert rep["status"] == "COMPLETE" and rep["scores"]["grade"] == "A", (rep["status"], rep["scores"])
    assert rep["coverage"]["partial"] is False
    from code_guardian import plain, report
    assert plain.harm(rep)["level"] == plain.NONE_FOUND and plain.harm(rep)["partial"] is False
    assert report.coverage_line(rep["coverage"]) == "coverage: 3 JavaScript/TypeScript analysed (token level)"


def test_js_risky_is_high_and_f(tmp_path):
    import make_risky_js
    rep = scan(make_risky_js.build(tmp_path / "js_risky"))
    assert rep["status"] == "COMPLETE"
    assert rep["scores"]["safe"] == 0 and rep["scores"]["grade"] == "F", rep["scores"]
    from code_guardian import plain
    assert plain.harm(rep)["level"] == plain.HIGH
    t = triples(rep)
    for want in (("exec.dynamic", "FAIL", "server.js:14"), ("exec.shell", "FAIL", "server.js:15"),
                 ("dom.html_sink", "FAIL", "server.js:21"), ("tls.off", "FAIL", "server.js:11"),
                 ("obfuscation", "FAIL", "server.js:17"), ("secret.key", "FAIL", "config.js:1"),
                 ("install.hook", "WARN", "package.json:7"), ("works.tests_missing", "WARN", ".")):
        assert want in t, want
    js = rep["coverage"]["languages"]["javascript"]
    assert set(js) >= {"files", "generated", "depth", "checks", "generated_checks", "not_checked"}
    assert js["files"] == 2 and js["generated"] == 0 and js["generated_checks"] == GENERATED_CHECKS
    assert C2_CODES <= set(js["checks"])
    nc = json.dumps(js["not_checked"])
    for word in ("privacy.pii_prompt", "works.test_no_assert", "orphan"):
        assert word in nc, word


def test_js_broken_works_findings():
    rep = scan(FIXTURES / "js_broken")
    assert rep["status"] == "COMPLETE"
    assert {("works.entry_missing", "FAIL", "package.json:5"), ("works.import_unresolved", "WARN", "src/index.ts:1"),
            ("works.relative_missing", "FAIL", "src/index.ts:2"), ("works.syntax", "FAIL", "src/half.js:2"),
            ("works.tests_missing", "WARN", ".")} <= triples(rep)
    assert not [f for f in rep["findings"] if f["code"] in C2_CODES and f["level"] in ("WARN", "FAIL")]
    assert rep["scores"]["works"] is not None and rep["scores"]["works"] <= 40


def test_jsx_torture_four_fails_and_one_info():
    rep = scan(FIXTURES / "jsx_torture")
    assert rep["status"] == "COMPLETE"
    assert triples(rep, "exec.dynamic") == {("exec.dynamic", "FAIL", "App.jsx:22"), ("exec.dynamic", "FAIL", "App.jsx:23"),
                                           ("exec.dynamic", "FAIL", "App.jsx:24"), ("exec.dynamic", "FAIL", "Quote.jsx:6"),
                                           ("exec.dynamic", "INFO", "App.jsx:25")}
    assert not triples(rep, "works.syntax")
    quote = [f for f in rep["findings"] if f["node"] == "Quote.jsx:6"][0]
    assert JSX_STRAY in quote["evidence"]


# ---- inventory, generated files, status --------------------------------------------------------------------------------

def test_generated_files(tmp_path):
    long_line = "var a=0;" + "a+=1;" * 500 + 'eval("1");\n'
    root = make(tmp_path, {
        "package.json": {"name": "p", "version": "1.0.0", "scripts": {"test": "node --test"}},
        "src/app.js": "module.exports = 1;\n",
        "vendor/lib.min.js": 'eval("1");\n',
        "vendor/app.bundle.js": "require('./nowhere');\n",
        "types/x.d.ts": "export declare const x: number;\n",
        "assets/out.js": long_line,
    })
    rep = scan(root)
    assert rep["files"]["javascript"] == 1 and rep["files"]["generated"] == 4, rep["files"]
    js = rep["coverage"]["languages"]["javascript"]
    assert js["files"] == 1 and js["generated"] == 4
    t = triples(rep)
    assert ("exec.dynamic", "INFO", "vendor/lib.min.js:1") in t and ("exec.dynamic", "INFO", "assets/out.js:1") in t
    assert not [x for x in t if x[2].startswith(("vendor/", "types/", "assets/")) and x[0].startswith("works.")]
    assert not [x for x in t if x[1] in ("WARN", "FAIL") and x[2].startswith(("vendor/", "types/", "assets/"))]


def test_index_js_alone_is_not_invalid(tmp_path):
    rep = scan(make(tmp_path, {"index.js": "console.log(1);\n"}))
    assert rep["status"] != "INVALID", rep["status_reasons"]


def test_no_analysable_source_reason(tmp_path):
    rep = scan(make(tmp_path, {"package.json": {"name": "p", "version": "1.0.0"}, "README.md": "# p\n",
                               "main.go": "package main\n"}))
    assert rep["coverage"]["reason"] == "no Python or JavaScript source: Works not scored, Safe partial"
    assert rep["coverage"]["works_scored"] is False and rep["coverage"]["safe_partial"] is True


def test_js_extensions_leave_other_source(tmp_path):
    rep = scan(make(tmp_path, {"app.py": "print(1)\n", "tests/test_app.py": "def test_a():\n    assert 1\n",
                               "web/a.ts": "export const a = 1;\n", "web/b.vue": "<template></template>\n"}))
    assert ".ts" not in rep["other_languages"] and ".ts" not in rep["coverage"]["other_source"]
    assert rep["coverage"]["other_source"].get(".vue") == 1
    assert rep["coverage"]["analysed"] == "python+javascript"


def test_tests_missing_fires_once_for_the_repo(tmp_path):
    js_tests = make(tmp_path, {"app.py": "print(1)\n", "src/a.js": "module.exports = 1;\n",
                               "package.json": {"name": "p", "version": "1.0.0", "scripts": {"test": "vitest"}}},
                    "js_tests")
    assert not [f for f in scan(js_tests)["findings"] if f["code"] == "works.tests_missing"]
    none = make(tmp_path, {"app.py": "print(1)\n", "src/a.js": "module.exports = 1;\n",
                           "package.json": {"name": "p", "version": "1.0.0"}}, "none")
    got = [(f["level"], f["node"]) for f in scan(none)["findings"] if f["code"] == "works.tests_missing"]
    assert got == [("WARN", ".")], got


# ---- outputs -----------------------------------------------------------------------------------------------------------

def test_sarif_and_markdown_carry_the_coverage(tmp_path):
    from code_guardian import outputs
    rep = scan(js_only(tmp_path))
    props = outputs.to_sarif(rep)["runs"][0]["properties"]
    assert props["coverage"]["languages"]["javascript"]["depth"] == "tokens"
    assert "1 JavaScript/TypeScript analysed (token level)" in outputs.to_markdown(rep)


# ---- docs, CI, ADR -----------------------------------------------------------------------------------------------------

def _read(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def _section(text, heading):
    m = re.search(r"^(#+) %s\s*$" % re.escape(heading), text, re.M)
    assert m, "no heading %r" % heading
    nxt = re.search(r"^#{1,%d} " % len(m.group(1)), text[m.end():], re.M)
    return text[m.end():m.end() + nxt.start()] if nxt else text[m.end():]


def test_readme_limitations_and_upgrading():
    readme = _read("README.md")
    lim = _section(readme, "Limitations")
    assert JSX_STRAY in lim and JSX_INFO in lim
    assert "lower confidence" not in readme.lower()
    for text in (readme, _read("CHANGELOG.md")):
        up = _section(text, "Upgrading to 0.5.0")
        for word in ("code-guardian baseline", "--baseline", "--fail-on"):
            assert word in up, word


def test_changelog_heading_and_unreleased():
    text = _read("CHANGELOG.md")
    # amended by the overseer for P81 S6: the release dates the heading
    assert re.search(r"^## code-guardian-mcp 0\.5\.0 \((?:unreleased|20\d\d-\d\d-\d\d)\)\s*$", text, re.M)
    unreleased = re.search(r"^## Unreleased\s*$(.*?)(?=^## |\Z)", text, re.M | re.S)
    assert unreleased is None or not unreleased.group(1).strip()


def test_ci_js_only_job_and_wheel_job():
    ci = _read(".github/workflows/ci.yml")
    assert 'test "$STATUS" = COMPLETE' in ci and 'test "$RC" = 1' in ci
    assert "exec.dynamic" in ci and "tokens" in ci and "js_risky" in ci
    assert 'test "$STATUS" = PARTIAL' not in ci


def test_adr_0011():
    adr = ROOT / "docs" / "adr" / "0011-javascript-typescript-at-token-level.md"
    assert adr.is_file()
    assert "0011-javascript-typescript-at-token-level.md" in _read("docs/adr/README.md")
    text = adr.read_text(encoding="utf-8").lower()
    for word in ("tree-sitter", "tokens", "golden"):
        assert word in text, word


# ---- untouched -------------------------------------------------------------------------------------------------------

def test_untouched_files():
    for rel in UNCHANGED_LF_MD5:
        data = (ROOT / rel).read_bytes().replace(b"\r\n", b"\n")
        assert hashlib.md5(data).hexdigest() == UNCHANGED_LF_MD5[rel], rel
