"""P76 S1 acceptance -- the plain-language layer (code_guardian/plain.py) and ADR 0007.

Written by the overseer from plan P76 contracts C2-C6 and C12 BEFORE the build session. The build session must add
this file to the PR byte-for-byte and must not edit it; a PR that changes it fails the section.

Harm labels below were computed by hand on main (cc0faf2, 2026-10-21) with score.dimension_of over each scan's
findings, exactly as contract C2 defines them. They are pinned here so plain.harm cannot drift from the scanner.

Verdict-phrase rule (C2): matched case-insensitively; single words are matched as whole words (so "insecure" is
not "secure" and "cleanup" is not "clean"), phrases as written.
"""
import copy
import importlib
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from code_guardian import catalogue, report, verify
from code_guardian.finding import CONFIDENCES

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
FIXTURES = HERE / "fixtures"

LABELS = ("High", "Medium", "Low", "No known risks found", "Could not check")

# fixture -> (harm level, partial), from main by hand (see module docstring)
PINNED = {
    "risky_repo": ("High", False),
    "clean_repo": ("Low", False),
    "works_broken": ("No known risks found", True),
    "orphan_repo": ("No known risks found", False),
    "supply_repo": ("Medium", False),
    "complete_app": ("No known risks found", False),
}

VERDICT = re.compile(
    r"is safe|safe to run|\bsecure\b|\bclean\b|no risks|risk-free|\bharmless\b|\bguaranteed\b", re.IGNORECASE)

DIMENSIONS = ("safe", "works", "complete", "overall")


def plain():
    # Imported per test so that on main every test fails on the missing module, not at collection.
    return importlib.import_module("code_guardian.plain")


def _js_only(tmp_path):
    d = tmp_path / "js_only"
    d.mkdir()
    (d / "index.js").write_text("console.log('hi')\n", encoding="utf-8")
    return d


def _js_with_manifest(tmp_path):
    d = tmp_path / "js_manifest"
    d.mkdir()
    (d / "index.js").write_text("console.log('hi')\n", encoding="utf-8")
    (d / "package.json").write_text(json.dumps({"name": "x", "version": "1.0.0"}), encoding="utf-8")
    return d


def _all_reports(tmp_path):
    reps = {name: report.scan(str(FIXTURES / name)) for name in PINNED}
    reps["js_only"] = report.scan(str(_js_only(tmp_path)))
    reps["js_manifest"] = report.scan(str(_js_with_manifest(tmp_path)))
    empty = tmp_path / "empty"
    empty.mkdir()
    reps["empty"] = report.scan(str(empty))
    return reps


def _sentences(p, rep):
    """Every sentence plain.py itself produces for one report (C2's list, minus diff_sentence which is S5)."""
    h = p.harm(rep)
    out = [("harm.level", h["level"]), ("harm.why", h["why"])]
    out += [("score_sentence(%s)" % d, p.score_sentence(d, rep)) for d in DIMENSIONS]
    out += [("checked_lines.text", e["text"]) for e in p.checked_lines(rep)]
    return out


# ---- C2 harm ---------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("name", sorted(PINNED))
def test_harm_label_pinned_per_fixture(name):
    p = plain()
    h = p.harm(report.scan(str(FIXTURES / name)))
    assert set(h) >= {"level", "partial", "why", "counts"}
    assert (h["level"], h["partial"]) == PINNED[name]


def test_harm_shape(tmp_path):
    p = plain()
    for name, rep in _all_reports(tmp_path).items():
        h = p.harm(rep)
        assert h["level"] in LABELS, (name, h["level"])
        assert h["level"] is not None
        assert set(h["counts"]) == {"FAIL", "WARN", "INFO"}, name
        assert all(isinstance(v, int) and v >= 0 for v in h["counts"].values()), name
        assert isinstance(h["why"], str) and h["why"].strip(), name


def test_js_only_dir_is_partial(tmp_path):
    p = plain()
    h = p.harm(report.scan(str(_js_only(tmp_path))))
    # one index.js and nothing else: the scanner says INVALID (no Python, no manifests) and Safe partial
    assert h["partial"] is True
    assert h["level"] == "Could not check"


def test_js_with_manifest_is_partial_not_invalid(tmp_path):
    p = plain()
    h = p.harm(report.scan(str(_js_with_manifest(tmp_path))))
    assert (h["level"], h["partial"]) == ("No known risks found", True)


def test_empty_dir_could_not_check_says_why(tmp_path):
    p = plain()
    empty = tmp_path / "empty"
    empty.mkdir()
    rep = report.scan(str(empty))
    assert rep["status"] == "INVALID" and rep["scores"]["grade"] is None
    h = p.harm(rep)
    assert h["level"] == "Could not check"
    assert rep["status_reasons"][0].lower() in h["why"].lower()


def test_high_why_names_a_safe_fail_title():
    p = plain()
    rep = report.scan(str(FIXTURES / "risky_repo"))
    h = p.harm(rep)
    from code_guardian import score
    fail_titles = {catalogue.CATALOGUE[f["code"]]["title"] for f in rep["findings"]
                   if score.dimension_of(f["code"]) == "safe" and f["level"] == "FAIL"
                   and f["code"] in catalogue.CATALOGUE}
    assert fail_titles, "fixture changed: risky_repo has no Safe FAIL"
    assert any(t in h["why"] for t in fail_titles), h["why"]
    assert h["counts"]["FAIL"] >= 1


def test_verdict_phrases_absent_from_every_plain_sentence(tmp_path):
    p = plain()
    hits = []
    for name, rep in _all_reports(tmp_path).items():
        for where, text in _sentences(p, rep):
            if VERDICT.search(text or ""):
                hits.append((name, where, text))
    for code, text in p.WHY.items():
        if VERDICT.search(text):
            hits.append(("WHY", code, text))
    assert not hits, hits


# ---- C3 score sentences ----------------------------------------------------------------------------------------

def test_overall_sentence_carries_grade_line_and_cap():
    p = plain()
    rep = report.scan(str(FIXTURES / "risky_repo"))
    s = p.score_sentence("overall", rep)
    sc = rep["scores"]
    assert "Overall %s (%s/100)" % (sc["grade"], sc["overall"]) in s, s
    assert sc["capped"] and sc["cap_reason"] in s, s


def test_null_dimension_says_not_scored_and_why(tmp_path):
    p = plain()
    rep = report.scan(str(_js_with_manifest(tmp_path)))
    assert rep["scores"]["works"] is None
    s = p.score_sentence("works", rep)
    assert "not scored" in s.lower()
    assert rep["coverage"]["reason"] in s


def test_score_sentence_one_per_dimension_is_str(tmp_path):
    p = plain()
    for rep in _all_reports(tmp_path).values():
        for d in DIMENSIONS:
            s = p.score_sentence(d, rep)
            assert isinstance(s, str) and s.strip()


# ---- C4 what was checked ---------------------------------------------------------------------------------------

def test_checked_lines_python_full_and_js_named():
    p = plain()
    rep = report.scan(str(FIXTURES / "risky_repo"))
    assert rep["coverage"]["other_source"] == {".js": 1}
    lines = p.checked_lines(rep)
    assert all(set(e) >= {"label", "files", "depth", "text"} for e in lines)
    py = [e for e in lines if e["label"] == "Python"]
    assert len(py) == 1 and py[0]["depth"] == "full" and py[0]["files"] == rep["coverage"]["python"]
    js = [e for e in lines if e["label"] == "JavaScript"]
    assert len(js) == 1 and js[0]["files"] == 1 and js[0]["depth"] == "secrets+manifests"
    assert js[0]["text"].startswith("JavaScript: 1 ")


def test_languages_table_and_unknown_extension():
    p = plain()
    assert len(p.LANGUAGES) >= 20
    assert p.LANGUAGES[".js"] == "JavaScript"
    rep = copy.deepcopy(report.scan(str(FIXTURES / "clean_repo")))
    rep["coverage"]["other_source"] = {".zzq": 2}
    labels = [e["label"] for e in p.checked_lines(rep)]
    assert ".zzq" in labels


def test_partial_and_invalid_put_status_reasons_first(tmp_path):
    p = plain()
    for rep in (report.scan(str(FIXTURES / "works_broken")), report.scan(str(_js_only(tmp_path)))):
        assert rep["status"] in ("PARTIAL", "INVALID")
        first = p.checked_lines(rep)[0]["text"]
        for reason in rep["status_reasons"]:
            assert reason in first, (reason, first)


# ---- C5 finding cards ------------------------------------------------------------------------------------------

def test_why_table_matches_catalogue():
    p = plain()
    assert set(p.WHY) == set(catalogue.CATALOGUE)
    assert all(isinstance(v, str) and v.strip() for v in p.WHY.values())


def test_finding_card_contract():
    p = plain()
    rep = report.scan(str(FIXTURES / "risky_repo"))
    assert rep["findings"]
    for f in rep["findings"]:
        c = p.finding_card(f, rep)
        assert set(c) == {"where", "what", "why", "how", "level", "confidence", "code", "fingerprint"}
        assert c["where"] == f["node"] and c["code"] == f["code"] and c["level"] == f["level"]
        assert c["fingerprint"] == f["fingerprint"]
        if f["code"] in catalogue.CATALOGUE:
            assert c["what"] == catalogue.CATALOGUE[f["code"]]["title"]
            assert c["why"] == p.WHY[f["code"]]
        assert c["how"] == (f.get("fix") or catalogue.CATALOGUE.get(f["code"], {}).get("fix"))
        assert f["confidence"] in str(c["confidence"])
        assert not any(word in c["why"] for word in CONFIDENCES), c["why"]


def test_finding_card_unknown_code_never_crashes():
    p = plain()
    rep = report.scan(str(FIXTURES / "clean_repo"))
    f = {"code": "zz.not_a_code", "severity": "x", "level": "WARN", "node": "a.py:3", "summary": "something odd",
         "evidence": [], "try": [], "confidence": "LIKELY", "fix": None, "fingerprint": "0" * 64}
    c = p.finding_card(f, rep)
    assert c["what"] == "zz.not_a_code" and c["why"] == "something odd"


# ---- C6 fix-first ----------------------------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["risky_repo", "supply_repo", "works_broken"])
def test_fix_first_ranks_equal_verify_plan(name):
    p = plain()
    rep = report.scan(str(FIXTURES / name))
    got = p.fix_first(rep, top=10)
    want = verify.plan(rep, top=10)["items"]
    assert [i["rank"] for i in got] == [i["rank"] for i in want]
    for item in got:
        assert set(item) >= {"rank", "title", "level", "count", "gain", "grade_after", "first_location", "how"}


# ---- C12 / never changes a number ------------------------------------------------------------------------------

def test_plain_never_mutates_the_report(tmp_path):
    p = plain()
    for name, rep in _all_reports(tmp_path).items():
        before = copy.deepcopy(rep)
        p.harm(rep)
        for d in DIMENSIONS:
            p.score_sentence(d, rep)
        p.checked_lines(rep)
        p.fix_first(rep)
        for f in rep["findings"]:
            p.finding_card(f, rep)
        assert rep == before, name


def test_adr_0007_exists_and_names_the_labels():
    adrs = sorted((ROOT / "docs" / "adr").glob("0007-*.md"))
    assert adrs, "docs/adr/0007-*.md missing"
    text = adrs[0].read_text(encoding="utf-8")
    for label in LABELS:
        assert label in text, label


def test_stdlib_only_and_selftest():
    assert re.search(r"^dependencies = \[\]$", (ROOT / "pyproject.toml").read_text(encoding="utf-8"), re.M)
    plain()
    r = subprocess.run([sys.executable, "-m", "code_guardian.plain", "--selftest"], cwd=str(ROOT),
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stdout + r.stderr
    m = re.search(r"(\d+) checks, (\d+) passed", r.stdout)
    assert m, r.stdout
    assert int(m.group(1)) == int(m.group(2)) >= 12
