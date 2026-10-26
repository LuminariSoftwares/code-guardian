"""Coverage: code-guardian analyses Python and JavaScript / TypeScript (at token level), and the report must not claim
checks that never ran.

A repo with neither gets Works "not scored" (null in JSON), a partial Safe, status PARTIAL and an Overall from the
scored dimensions only. A JavaScript-only repo is COMPLETE with Works scored. A mixed repo whose source is mostly in
other languages is PARTIAL with a coverage line; a Python repo with a few stray .js helpers stays COMPLETE with
exactly the 0.3.1 scores."""
import json
import shutil
import subprocess
import sys

import pytest

from conftest import FIXTURES

from code_guardian import outputs, report

# Built at runtime: the self-scan and the privacy workflow read literals.
STRIPE_LIVE = "sk_" + "live_" + "a1B2c3D4e5F6g7H8i9J0k1L2"


def cli(*args):
    return subprocess.run([sys.executable, "-m", "code_guardian", *map(str, args)], capture_output=True, text=True,
                          timeout=120)


def put(root, rel, text):
    path = root.joinpath(*rel.split("/"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8"))  # exact bytes: write_text would give \r\n on Windows


@pytest.fixture
def js_only(tmp_path):
    """The 0.3.1 bug report: package.json, src/index.js (a live-key shape and eval of request input), a 7-byte README."""
    root = tmp_path / "js_only"
    put(root, "package.json", '{"name": "demo", "version": "1.0.0"}\n')
    put(root, "src/index.js", 'const stripe = require("stripe")("%s");\n'
                              'const app = require("express")();\n'
                              'app.get("/", (q, r) => r.send(eval(q.query.x)));\n' % STRIPE_LIVE)
    put(root, "README.md", "# demo\n")
    assert root.joinpath("README.md").stat().st_size == 7
    return root


def overall_line(text):
    return next(ln for ln in text.splitlines() if ln.strip().startswith("Overall"))


def test_js_only_repo_is_complete_with_works_scored(js_only):
    rep = report.scan(str(js_only))
    s, dims = rep["scores"], rep["dimensions"]
    # Works ran on the JavaScript: a number, and the JSON says it was scored
    assert s["works"] == 72 and dims["works"].get("scored") is True
    assert rep["status"] == "COMPLETE" and rep["status_reasons"] == []
    # the secret scan and the token-level scan both find what is there, and both gate
    found = {(f["code"], f["level"], f["node"]) for f in rep["findings"]}
    assert ("secret.key", "FAIL", "src/index.js:1") in found and ("exec.dynamic", "FAIL", "src/index.js:3") in found
    assert report.exit_code(rep["findings"], "FAIL", report.gate_status(rep)) == 1
    # Safe is no longer partial: Safe 100 - 40 (secret.key) - 30 (exec.dynamic) = 30
    assert dims["safe"].get("scored") is True and dims["safe"].get("partial") is False
    # Works: tests_missing 15, import_unresolved x2 (10 + 25% of 10 rounded up = 13): 100 - 28 = 72
    # Overall (5 x 30 + 3 x 72 + 2 x 60) / 10 = 48.6 -> 49; the Safe FAIL caps at D
    assert (s["safe"], s["works"], s["complete"], s["overall"], s["grade"]) == (30, 72, 60, 49, "D")
    cov = rep["coverage"]
    assert cov["python"] == 0 and cov["other_source"] == {} and cov["analysed"] == "javascript"
    assert cov["works_scored"] is True and cov["safe_partial"] is False and cov["partial"] is False

    text = report.render(rep)
    assert "not scored" not in overall_line(text) and "n/a" not in text
    assert "status: COMPLETE" in text and "coverage: 1 JavaScript/TypeScript analysed (token level)" in text
    assert "partial" not in next(ln for ln in text.splitlines() if ln.strip().startswith("Safe"))

    body = json.loads(cli("scan", js_only, "--json").stdout)
    assert body["scores"]["works"] == 72 and body["dimensions"]["works"]["scored"] is True

    # the job summary opens with the status and the coverage, before the score table
    md = outputs.to_markdown(rep)
    head = md.split("| | score | |")[0]
    assert "**Status: COMPLETE**" in head and "1 JavaScript/TypeScript analysed (token level)" in head
    assert "n/a" not in md and "not scored" not in md
    # SARIF: the coverage in the run properties is the report's
    props = outputs.to_sarif(rep)["runs"][0]["properties"]
    assert props["status"] == "COMPLETE" and props["coverage"] == rep["coverage"]


def test_a_repo_with_no_analysed_source_does_not_claim_works(tmp_path):
    """The 0.3.1 bug report with the source in a language that is only secret-scanned (Go): Works is not scored."""
    root = tmp_path / "go_only"
    put(root, "package.json", '{"name": "demo", "version": "1.0.0"}\n')
    put(root, "main.go", 'package main\n\nvar token = "%s"\n' % STRIPE_LIVE)
    put(root, "README.md", "# demo\n")
    rep = report.scan(str(root))
    s, dims = rep["scores"], rep["dimensions"]
    assert s["works"] is None and dims["works"].get("scored") is False
    assert rep["status"] == "PARTIAL"
    assert ("secret.key", "FAIL", "main.go:3") in {(f["code"], f["level"], f["node"]) for f in rep["findings"]}
    assert report.exit_code(rep["findings"], "FAIL", rep["status"]) == 1
    assert dims["safe"].get("scored") is True and dims["safe"].get("partial") is True
    # Overall from Safe (60) and Complete (60) only: (5*60 + 2*60) / 7 = 60; the Safe FAIL still caps at D
    assert (s["safe"], s["complete"], s["overall"], s["grade"]) == (60, 60, 60, "D")
    assert rep["coverage"]["python"] == 0 and rep["coverage"]["other_source"] == {".go": 1}
    assert rep["coverage"]["reason"] == "no Python or JavaScript source: Works not scored, Safe partial"
    assert rep["coverage"]["languages"] == {}

    text = report.render(rep)
    assert "Works not scored: no Python or JavaScript source" in overall_line(text)
    assert "n/a (no Python or JavaScript)" in text and "Works    100/100" not in text
    assert "status: PARTIAL" in text and "coverage: 1 .go secret-scan only" in text
    safe_line = next(ln for ln in text.splitlines() if ln.strip().startswith("Safe"))
    assert "60/100" in safe_line and "partial" in safe_line

    body = json.loads(cli("scan", root, "--json").stdout)
    assert body["scores"]["works"] is None and body["dimensions"]["works"]["scored"] is False

    md = outputs.to_markdown(rep)
    head = md.split("| | score | |")[0]
    assert "**Status: PARTIAL**" in head and "1 .go secret-scan only" in head
    assert "n/a (no Python or JavaScript)" in md and "Works not scored: no Python or JavaScript source" in md
    props = outputs.to_sarif(rep)["runs"][0]["properties"]
    assert props["status"] == "PARTIAL" and props["coverage"] == rep["coverage"]


def mixed(root, py, other):
    """py Python files plus {ext: count} other source files, in a package with tests, README and licence."""
    put(root, "pyproject.toml", '[project]\nname = "mixed"\nversion = "1.0"\n')
    put(root, "LICENSE", "MIT\n")
    put(root, "README.md", "# mixed\n")
    put(root, "tests/test_a.py", "def test_a():\n    assert True\n")
    for i in range(py - 1):
        put(root, "mixed/m%d.py" % i, "X = %d\n" % i)
    for ext, n in other.items():
        for i in range(n):
            put(root, "web/f%d%s" % (i, ext), "export const x = %d;\n" % i)
    return root


def test_mixed_repo_threshold(tmp_path):
    # the README's rule: PARTIAL when there are 5 or more source files in other languages and more than twice as many
    # as the Python and JavaScript / TypeScript files together (those are under a third of the source)
    at = report.scan(str(mixed(tmp_path / "at", 3, {".go": 6})))           # 6 is not more than 2 x 3
    over = report.scan(str(mixed(tmp_path / "over", 3, {".go": 7})))       # 7 is
    few = report.scan(str(mixed(tmp_path / "few", 1, {".sh": 4})))         # under 5: a handful of scripts
    assert at["status"] == "COMPLETE" and few["status"] == "COMPLETE"
    assert over["status"] == "PARTIAL"
    # the scores stay as they are: every dimension scored, the same numbers either side of the line
    assert all(over["dimensions"][d]["scored"] for d in ("safe", "works", "complete"))
    assert over["dimensions"]["safe"]["partial"] is False
    assert [over["scores"][k] for k in ("safe", "works", "complete", "overall")] == \
        [at["scores"][k] for k in ("safe", "works", "complete", "overall")]
    assert "coverage: 3 Python analysed; 7 .go secret-scan only" in report.render(over)
    assert "coverage: 3 Python analysed; 6 .go secret-scan only" in report.render(at)
    # coverage alone never gates: with nothing at or above FAIL the exit code is 0, not 3
    assert not [f for f in over["findings"] if f["level"] == "FAIL"]
    assert cli("scan", tmp_path / "over").returncode == 0

    big = report.scan(str(mixed(tmp_path / "big", 40, {".rs": 112, ".go": 9})))
    assert big["status"] == "PARTIAL"
    assert "coverage: 40 Python analysed; 112 .rs, 9 .go secret-scan only" in report.render(big)


def test_mixed_threshold_counts_javascript_with_python(tmp_path):
    # 1 Python + 2 JavaScript / TypeScript = 3 analysed files: 6 other files are not more than 2 x 3, 7 are
    at = report.scan(str(mixed(tmp_path / "at", 1, {".js": 1, ".ts": 1, ".go": 6})))
    over = report.scan(str(mixed(tmp_path / "over", 1, {".js": 1, ".ts": 1, ".go": 7})))
    assert at["status"] == "COMPLETE" and over["status"] == "PARTIAL"
    assert over["status_reasons"] == [
        "Python and JavaScript/TypeScript are under a third of the source: 7 file(s) in other languages got the "
        "secret scan only"]
    assert over["coverage"]["analysed"] == "python+javascript"
    assert over["coverage"]["languages"]["javascript"]["files"] == 2
    assert "coverage: 1 Python analysed; 2 JavaScript/TypeScript analysed (token level); 7 .go secret-scan only" \
        in report.render(over)
    # the extension sets differ: .js and .ts never count as "other"
    assert over["coverage"]["other_source"] == {".go": 7} and over["other_languages"] == {".go": 7}


SCORES_031 = {
    # code-guardian 0.3.1 on each fixture plus one stray docs/build.js: status and scores
    "clean_repo": ("COMPLETE", {"safe": 100, "works": 100, "complete": 100, "overall": 100, "grade": "A",
                                "grade_uncapped": "A", "capped": False, "cap_reason": None}),
    "orphan_repo": ("COMPLETE", {"safe": 100, "works": 97, "complete": 50, "overall": 89, "grade": "B",
                                 "grade_uncapped": "B", "capped": False, "cap_reason": None}),
}


@pytest.mark.parametrize("name", sorted(SCORES_031))
def test_python_repo_with_a_stray_js_file_is_unchanged(tmp_path, name):
    root = tmp_path / name
    shutil.copytree(FIXTURES / name, root)
    put(root, "docs/build.js", "module.exports = { title: 'docs' };\n")
    rep = report.scan(str(root))
    status, scores = SCORES_031[name]
    assert (rep["status"], rep["scores"]) == (status, scores)
    assert all(rep["dimensions"][d].get("scored", True) for d in ("safe", "works", "complete"))
    assert not rep["dimensions"]["safe"].get("partial", False)
    assert report.exit_code(rep["findings"], "FAIL", rep["status"]) == 0
