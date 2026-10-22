"""Unit tests for the plain-language layer, beyond tests/test_p76_s1_acceptance.py.

The acceptance file pins the layer to real scans of the fixtures. These build reports by hand, with score.py doing
the arithmetic, so every band of contract C3 and every branch of C2 is covered at its boundary -- the bands in
particular, because no fixture lands in most of them.
"""
import copy
import re

import pytest
from conftest import ROOT

from code_guardian import catalogue, plain, report, score, verify
from code_guardian.finding import CONFIDENCES

FULL_COVERAGE = {"analysed": "python", "python": 3, "other_source": {}, "other_source_files": 0,
                 "works_scored": True, "safe_partial": False, "partial": False, "reason": None}
NO_PYTHON_REASON = "no Python source: Works not scored, Safe partial"
NO_PYTHON_COVERAGE = {"analysed": "python", "python": 0, "other_source": {".js": 1}, "other_source_files": 1,
                      "works_scored": False, "safe_partial": True, "partial": True, "reason": NO_PYTHON_REASON}


def f(code, level, node="a.py:1", summary="s", fix=None):
    return {"code": code, "severity": "partial", "level": level, "node": node, "summary": summary, "evidence": [],
            "try": [], "confidence": "LIKELY", "fix": fix, "fingerprint": "%064x" % (hash((code, node)) & ((1 << 256) - 1))}


def rep(findings, status="COMPLETE", reasons=(), coverage=None, files=None):
    """The shape report.scan() returns, with score.py computing every number."""
    cov = coverage or FULL_COVERAGE
    dims = {name: score.dimension(findings, name) for name in score.DIMENSIONS}
    if not cov["works_scored"]:
        dims["works"] = score.unscored()
    dims["safe"]["partial"] = bool(cov["safe_partial"])
    return {"path": "demo", "status": status, "status_reasons": list(reasons), "coverage": cov,
            "files": files or {"python": cov["python"], "manifests": 0, "other": 0, "skipped": 0, "ignored": 0,
                               "excluded": 0, "unparsed": 0},
            "findings": findings, "hygiene": {"findings": []}, "dimensions": dims,
            "scores": score.scores(findings, dims, status)}


# ---- C3 bands, at their boundaries -----------------------------------------------------------------------------

# (band, findings, the Safe score they produce) -- both edges of every band of C3 that score.py can land on
FLOOR_FINDINGS = [f("secret.key", "FAIL", "a.py:1"), f("obfuscation", "FAIL", "a.py:2"),
                  f("exec.dynamic", "FAIL", "b.py:1"), f("exec.shell", "FAIL", "b.py:2")]
BAND_CASES = [
    ("100", [], 100),
    ("90-99", [f("net.egress", "WARN", "a.py:1")], 98),
    ("90-99", [f("tls.off", "WARN", "a.py:1")], 90),
    ("70-89", [f("tls.off", "WARN", "a.py:1"), f("fs.outside", "WARN", "a.py:2")], 87),
    ("70-89", [f("exec.dynamic", "FAIL", "a.py:1")], 70),
    ("40-69", [f("exec.dynamic", "FAIL", "a.py:1"), f("fs.outside", "WARN", "a.py:2")], 67),
    ("40-69", [f("secret.key", "FAIL", "a.py:%d" % i) for i in range(1, 4)], 40),
    ("0-39", [f("secret.key", "FAIL", "a.py:1"), f("obfuscation", "FAIL", "a.py:2")], 20),
    ("0-39", FLOOR_FINDINGS, 0),
]


@pytest.mark.parametrize("band,findings,expected", BAND_CASES)
def test_band_sentence_carries_the_reports_own_number(band, findings, expected):
    r = rep(findings)
    assert r["scores"]["safe"] == expected, (band, r["scores"])
    s = plain.score_sentence("safe", r)
    assert s.startswith("Safe scores %d out of 100:" % expected), s
    assert s.endswith("."), s
    counted = sum(row["count"] for row in r["dimensions"]["safe"]["checks"])
    assert ("no finding took points off" if not counted else "%d finding" % counted) in s, s


def test_each_band_reads_differently_and_both_edges_read_the_same():
    """C3 has five bands: one wording each, and the two edges of a band share it."""
    wording = {}
    for band, findings, _ in BAND_CASES:
        text = plain.score_sentence("safe", rep(findings)).split(": ", 1)[1]
        wording.setdefault(band, set()).add(text.split(" (", 1)[0])
    assert sorted(wording) == ["0-39", "100", "40-69", "70-89", "90-99"]
    assert all(len(v) == 1 for v in wording.values()), wording
    assert len({next(iter(v)) for v in wording.values()}) == 5, wording


def test_band_boundaries_are_where_c3_puts_them():
    """100 / 90 / 70 / 40 / 0 are the floors; one point below each falls into the next band down."""
    seen = [plain._band(v) for v in (100, 99, 90, 89, 70, 69, 40, 39, 0)]
    assert seen[0] != seen[1]
    assert seen[1] == seen[2] != seen[3]
    assert seen[3] == seen[4] != seen[5]
    assert seen[5] == seen[6] != seen[7]
    assert seen[7] == seen[8]


def test_null_dimension_names_the_coverage_reason():
    s = plain.score_sentence("works", rep([], status="PARTIAL", reasons=[NO_PYTHON_REASON],
                                          coverage=NO_PYTHON_COVERAGE))
    assert s == "Works is not scored for this project, because %s." % NO_PYTHON_REASON


def test_overall_names_the_cap_letter_from_the_reports_own_reason():
    r = rep([f("secret.key", "FAIL", "a.py:1")])
    s = plain.score_sentence("overall", r)
    assert s.startswith("Overall D (80/100)"), s
    assert r["scores"]["cap_reason"] in s
    assert ", capped at D: " in s


def test_overall_takes_the_worst_cap_when_two_apply():
    r = rep([f("secret.key", "FAIL", "a.py:1")], status="PARTIAL", reasons=["1 Python file(s) did not parse: x.py"])
    assert r["scores"]["cap_reason"].count("at most") == 2
    s = plain.score_sentence("overall", r)
    assert ", capped at D: " in s, s  # D (Safe FAIL) is worse than B (PARTIAL)


def test_overall_on_an_invalid_scan_is_not_graded():
    r = rep([], status="INVALID", reasons=["no Python files and no manifests to judge"])
    assert r["scores"]["grade"] is None
    s = plain.score_sentence("overall", r)
    assert s == "Overall is not graded: no Python files and no manifests to judge."


def test_score_sentence_refuses_an_unknown_dimension():
    with pytest.raises(ValueError):
        plain.score_sentence("sideways", rep([]))


def test_an_incomplete_scan_says_so_in_the_score_sentence():
    partial = plain.score_sentence("safe", rep([], status="PARTIAL", reasons=["x"]))
    assert "did not cover the whole project" in partial
    assert "did not cover the whole project" not in plain.score_sentence("safe", rep([]))


# ---- C2, every branch ------------------------------------------------------------------------------------------

def test_harm_invalid_branch():
    h = plain.harm(rep([f("secret.key", "FAIL")], status="INVALID", reasons=["PATH is unreadable (OSError)"]))
    assert h["level"] == "Could not check"  # INVALID wins over a Safe FAIL
    assert "PATH is unreadable (OSError)" in h["why"]


def test_harm_fail_branch():
    h = plain.harm(rep([f("secret.key", "FAIL"), f("exec.shell", "WARN", "a.py:2")]))
    assert h["level"] == "High" and h["counts"] == {"FAIL": 1, "WARN": 1, "INFO": 0}
    assert catalogue.CATALOGUE["secret.key"]["title"] in h["why"]


def test_harm_warn_branch():
    h = plain.harm(rep([f("exec.shell", "WARN"), f("net.egress", "INFO", "a.py:2")]))
    assert h["level"] == "Medium" and h["counts"] == {"FAIL": 0, "WARN": 1, "INFO": 1}
    assert catalogue.CATALOGUE["exec.shell"]["title"] in h["why"]


def test_harm_info_branch():
    h = plain.harm(rep([f("net.egress", "INFO")]))
    assert h["level"] == "Low" and h["counts"]["INFO"] == 1
    assert catalogue.CATALOGUE["net.egress"]["title"] in h["why"]


def test_harm_nothing_branch_on_a_report_with_zero_findings():
    r = rep([])
    h = plain.harm(r)
    assert h["level"] == "No known risks found"
    assert h["counts"] == {"FAIL": 0, "WARN": 0, "INFO": 0}
    assert h["partial"] is False
    assert "No Safe check reported anything" in h["why"]
    assert plain.checked_lines(r) == [{"label": "Python", "files": 3, "depth": "full",
                                       "text": "Python: 3 files -- %s." % plain.PYTHON_TEXT}]
    assert plain.fix_first(r) == [] and plain.fix_first_notes(r) == []


def test_non_safe_findings_never_move_the_harm_level():
    h = plain.harm(rep([f("works.entry_missing", "FAIL"), f("complete.readme_missing", "WARN", ".")]))
    assert h["level"] == "No known risks found"
    assert h["counts"] == {"FAIL": 0, "WARN": 0, "INFO": 0}


def test_harm_why_names_the_heaviest_finding_not_the_first():
    """Two Safe WARNs: the sentence names the one score.py weighs most, whatever order they arrive in."""
    light, heavy = f("net.egress", "WARN", "z.py:1"), f("install.hook", "WARN", "setup.py:1")
    assert score.weight(heavy) > score.weight(light)
    for order in ([light, heavy], [heavy, light]):
        assert catalogue.CATALOGUE["install.hook"]["title"] in plain.harm(rep(order))["why"]


@pytest.mark.parametrize("status,coverage,expected", [
    ("COMPLETE", FULL_COVERAGE, False),
    ("PARTIAL", FULL_COVERAGE, True),            # partial from the status alone
    ("COMPLETE", NO_PYTHON_COVERAGE, True),      # partial from coverage.safe_partial alone
    ("INVALID", NO_PYTHON_COVERAGE, True),
])
def test_partial_comes_from_either_source(status, coverage, expected):
    assert plain.harm(rep([], status=status, coverage=coverage))["partial"] is expected


def test_harm_level_is_never_none_and_always_a_label():
    for status in ("COMPLETE", "PARTIAL", "INVALID"):
        for findings in ([], [f("net.egress", "INFO")], [f("secret.key", "FAIL")]):
            level = plain.harm(rep(findings, status=status, reasons=["r"]))["level"]
            assert level in plain.LABELS and level is not None


# ---- C4 ---------------------------------------------------------------------------------------------------------

def test_checked_lines_counts_skipped_and_unparsed_files():
    r = rep([], files={"python": 4, "manifests": 1, "other": 0, "skipped": 2, "ignored": 0, "excluded": 0,
                       "unparsed": 1})
    by_label = {e["label"]: e for e in plain.checked_lines(r)}
    assert by_label["Skipped"]["files"] == 2 and by_label["Skipped"]["depth"] == "not read"
    assert by_label["Python that did not parse"]["files"] == 1
    assert plain.checked_lines(rep([]))  # and no such entries when both counts are zero
    assert "Skipped" not in {e["label"] for e in plain.checked_lines(rep([]))}


def test_languages_names_every_extension_a_scan_can_report():
    """coverage.other_source only ever holds report.SOURCE_EXT keys: none of them may fall back to the extension."""
    missing = sorted(set(report.SOURCE_EXT) - set(plain.LANGUAGES))
    assert not missing, missing


def test_unknown_extension_falls_back_to_the_extension_itself():
    r = rep([], coverage=dict(FULL_COVERAGE, other_source={".zzq": 2}, other_source_files=2))
    entry = [e for e in plain.checked_lines(r) if e["label"] == ".zzq"]
    assert len(entry) == 1 and entry[0]["files"] == 2 and entry[0]["text"].startswith(".zzq: 2 files -- ")


def test_checked_lines_text_pluralises():
    one = rep([], coverage=dict(FULL_COVERAGE, python=1))
    assert plain.checked_lines(one)[0]["text"].startswith("Python: 1 file -- ")
    assert plain.checked_lines(rep([]))[0]["text"].startswith("Python: 3 files -- ")


# ---- C5 ---------------------------------------------------------------------------------------------------------

def test_why_covers_the_catalogue_and_claims_nothing_a_check_cannot_see():
    assert set(plain.WHY) == set(catalogue.CATALOGUE)
    for code, text in plain.WHY.items():
        assert text.strip() and text.endswith(".") and "\n" not in text, code
        assert not plain.VERDICT_PHRASES.search(text), (code, text)
        assert not any(word in text for word in CONFIDENCES), (code, text)
        assert not re.search(r"https?://|\bwww\.", text), code  # tests/test_self_scan.py reads these as literals


def test_finding_card_prefers_the_findings_own_fix():
    own = {"action": "replace", "args": {"with": "x"}}
    assert plain.finding_card(f("tls.off", "FAIL", fix=own))["how"] == own
    assert plain.finding_card(f("tls.off", "FAIL"))["how"] == catalogue.CATALOGUE["tls.off"]["fix"]


def test_finding_card_keeps_confidence_out_of_every_sentence():
    card = plain.finding_card(f("exec.shell", "WARN"))
    assert card["confidence"] == "LIKELY"
    assert not any(word in card["why"] for word in CONFIDENCES)
    assert not any(word in str(card["what"]) for word in CONFIDENCES)


def test_finding_card_on_an_unknown_code_with_no_summary():
    card = plain.finding_card({"code": "zz.new", "level": "INFO", "node": "a.py:1", "summary": "",
                               "confidence": "LIKELY", "fix": None, "fingerprint": "0" * 64})
    assert card["what"] == "zz.new" and card["why"] == "" and card["how"] is None


# ---- C6 ---------------------------------------------------------------------------------------------------------

def test_fix_first_top_1_is_the_plans_first_row():
    r = rep([f("secret.key", "FAIL", "a.py:1"), f("exec.shell", "WARN", "b.py:2"),
             f("complete.readme_missing", "WARN", ".")])
    got = plain.fix_first(r, top=1)
    want = verify.plan(r, top=1)["items"]
    assert len(got) == 1 and got[0]["rank"] == 1
    assert got[0]["title"] == want[0]["title"] and got[0]["gain"] == want[0]["gain"]
    assert got[0]["grade_after"] == want[0]["grade_after"] and got[0]["count"] == want[0]["count"]
    assert got[0]["first_location"] == want[0]["locations"][0]
    assert got[0]["how"] == catalogue.CATALOGUE[want[0]["code"]]["fix"]


def test_fix_first_top_1_does_not_change_the_ranking():
    r = rep([f("secret.key", "FAIL", "a.py:1"), f("exec.shell", "WARN", "b.py:2")])
    assert plain.fix_first(r, top=1) == plain.fix_first(r, top=10)[:1]


def test_fix_first_notes_pass_through_untouched():
    """A Safe dimension on the floor: verify.plan adds the "a Safe FAIL caps the grade" note, unedited here."""
    r = rep(FLOOR_FINDINGS)
    assert r["scores"]["safe"] == 0 and r["dimensions"]["safe"]["deducted"] == 140
    notes = plain.fix_first_notes(r)
    assert notes == verify.plan(r, top=10)["notes"]
    assert any("caps the grade at D" in n for n in notes), notes


def test_fix_first_on_an_invalid_scan_is_empty():
    r = rep([], status="INVALID", reasons=["no Python files and no manifests to judge"])
    assert plain.fix_first(r) == []
    assert plain.fix_first_notes(r) == ["the scan is INVALID: there is nothing to plan"]


# ---- C12 ---------------------------------------------------------------------------------------------------------

def test_no_call_changes_the_report():
    r = rep([f("secret.key", "FAIL", "a.py:1"), f("net.egress", "WARN", "b.py:2")], status="PARTIAL",
            reasons=["1 Python file(s) did not parse: x.py"])
    before = copy.deepcopy(r)
    plain.harm(r)
    for d in ("safe", "works", "complete", "overall"):
        plain.score_sentence(d, r)
    plain.checked_lines(r)
    plain.fix_first(r, top=1)
    plain.fix_first_notes(r)
    for finding in r["findings"]:
        plain.finding_card(finding, r)
    assert r == before


def test_adr_0007_records_the_mapping_and_the_forbidden_words():
    adr = ROOT / "docs" / "adr" / "0007-plain-language-layer-never-scores.md"
    body = adr.read_text(encoding="utf-8")
    for label in plain.LABELS:
        assert label in body, label
    for word in ("is safe", "safe to run", "secure", "clean", "no risks", "risk-free", "harmless", "guaranteed"):
        assert word in body, word
    # Built at runtime, as conftest does: a literal address here would land in this project's own egress
    # inventory when it scans itself.
    loopback = "127.0." + "0.1"
    assert "dependencies = []" in body and loopback in body
