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


def test_an_incomplete_scan_says_so_once_on_the_overall_sentence():
    r = rep([], status="PARTIAL", reasons=["x"])
    overall = plain.score_sentence("overall", r)
    # said by the cap reason, so the clause is left out (P76 S5): once either way
    assert overall.count("PARTIAL") + overall.count("did not cover the whole project") == 1, overall
    for d in ("safe", "works", "complete"):
        assert "did not cover the whole project" not in plain.score_sentence(d, r), d
    assert "did not cover the whole project" not in plain.score_sentence("overall", rep([]))


def test_no_python_line_says_there_was_nothing_to_check():
    r = rep([], status="PARTIAL", reasons=[NO_PYTHON_REASON], coverage=NO_PYTHON_COVERAGE)
    py = [e for e in plain.checked_lines(r) if e["label"] == "Python"][0]
    assert py["files"] == 0
    assert py["text"] == "Python: 0 files — there was no Python here for the Safe and Works checks to read.", py


def test_no_sentence_uses_an_ascii_double_dash():
    for r in (rep([]), rep([f("secret.key", "FAIL", "a.py:1")], status="PARTIAL", reasons=["x"]),
              rep([], files=dict(rep([])["files"], skipped=1, unparsed=1))):
        texts = [plain.harm(r)["why"]] + [plain.score_sentence(d, r) for d in ("safe", "works", "complete", "overall")]
        texts += [e["text"] for e in plain.checked_lines(r)]
        assert not [t for t in texts if " -- " in t], texts


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
                                       "text": "Python: 3 files — every Safe and Works check ran on these."}]
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
    assert len(entry) == 1 and entry[0]["files"] == 2 and entry[0]["text"].startswith(".zzq: 2 files — ")


def test_checked_lines_text_pluralises():
    one = rep([], coverage=dict(FULL_COVERAGE, python=1))
    assert plain.checked_lines(one)[0]["text"].startswith("Python: 1 file — ")
    assert plain.checked_lines(rep([]))[0]["text"].startswith("Python: 3 files — ")


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


# ---- Overseer review of c667512: six sentences claimed more than the check knows ------------------------------

# (item, code, what the sentence must now say, what it must no longer claim, the scanner fact that forces it).
# Each row is a FAILED review line on c667512; the "must not" string is the wording that shipped there.
OVERCLAIMS = [
    ("1-exec.dynamic", "exec.dynamic", ["module"], ["assembles a piece of program text"],
     "scanners.scan_exec_dynamic also fires on __import__ of a computed name, which is not program text, and it "
     "only ever sees that the argument is not a literal -- never that anything was assembled"),
    ("2-works.test_no_assert", "works.test_no_assert", ["no assertion", "another file", "may "],
     ["so they only notice a problem"],
     "works.test_no_assert builds its helper set from the one file it is parsing, so a helper that asserts in "
     "another file is invisible to it (the catalogue lists exactly that as a false positive)"),
    ("3-works.todo_stub", "works.todo_stub", ["not implemented"], ["does nothing when it is called"],
     "leftovers.is_stub also matches a body of only `raise NotImplementedError`, which stops with an error rather "
     "than doing nothing"),
    ("4-privacy.pii_prompt", "privacy.pii_prompt", ["looks like", "if it is one"],
     ["is placed into a prompt for a language model"],
     "scanners.scan_pii_prompt matches a messages=/prompt= argument or a .chat( / .complete( / .generate( call; "
     "the catalogue lists a .complete( that is not a model call as a false positive"),
]


@pytest.mark.parametrize("item,code,must_say,must_not_claim,because", OVERCLAIMS,
                         ids=[row[0] for row in OVERCLAIMS])
def test_why_claims_no_more_than_the_check_can_see(item, code, must_say, must_not_claim, because):
    text = plain.WHY[code]
    for phrase in must_not_claim:
        assert phrase not in text, (because, text)
    for phrase in must_say:
        assert phrase in text, (because, text)
    assert any(h in text for h in (" can ", " may ", " if ", "looks like")), text


def test_item_5_python_entry_leaves_out_the_files_that_did_not_parse():
    """works_broken: 4 Python files, 1 of which ast.parse rejected. The "full" line may claim only the other 3."""
    rep_ = report.scan(str(ROOT / "tests" / "fixtures" / "works_broken"))
    assert rep_["coverage"]["python"] == 4 and rep_["files"]["unparsed"] == 1
    lines = {e["label"]: e for e in plain.checked_lines(rep_)}
    assert lines["Python"]["files"] == 3
    assert lines["Python"]["text"].startswith("Python: 3 files — ")
    assert lines["Python that did not parse"]["files"] == 1
    assert lines["Python that did not parse"]["depth"] == "secrets only"  # it was read, just not parsed


def test_item_5_python_entry_never_claims_every_check_on_an_incomplete_scan():
    crashed = f("check.crashed", "WARN", "a.py:1", "a check crashed")
    for r in (rep([crashed]), rep([], status="PARTIAL", reasons=["1 Python file(s) did not parse: x.py"])):
        text = [e for e in plain.checked_lines(r) if e["label"] == "Python"][0]["text"]
        assert "every" not in text, text
        assert "checks ran on these, except" in text, text
    full = [e for e in plain.checked_lines(rep([])) if e["label"] == "Python"][0]["text"]
    assert "every Safe and Works check ran" in full, full


def test_item_5_python_entry_makes_no_per_file_claim_about_complete():
    """Complete reads the project as a whole (a licence, a README, CI), never each Python file."""
    for r in (rep([]), rep([], status="PARTIAL", reasons=["x"]), rep([f("check.crashed", "WARN")])):
        text = [e for e in plain.checked_lines(r) if e["label"] == "Python"][0]["text"]
        assert "Complete" not in text, text


def test_item_6_adr_scopes_the_token_to_api_requests():
    body = (ROOT / "docs" / "adr" / "0007-plain-language-layer-never-scores.md").read_text(encoding="utf-8")
    assert "every request must carry the session token" not in body
    assert "/api/*" in body and "Host" in body and "Origin" in body


# ---- P76 S5: before / after, and two copy items from the S3b review -----------------------------------------------

def test_diff_sentence_reads_the_counts_and_both_grades():
    before = rep([f("secret.key", "FAIL", "app.py:2"), f("exec.shell", "WARN", "app.py:9")])
    after = rep([f("exec.shell", "WARN", "app.py:9"), f("net.egress", "WARN", "app.py:4")])
    d = verify.diff(before, after)
    s = plain.diff_sentence(d)
    assert s == "1 fixed, 1 new, grade %s → %s" % (before["scores"]["grade"], after["scores"]["grade"])
    invalid = rep([], status="INVALID", reasons=["nothing to judge"])
    assert plain.diff_sentence(verify.diff(invalid, before)).endswith("grade none → %s" % before["scores"]["grade"])
    assert not plain.VERDICT_PHRASES.search(s) and " -- " not in s


def test_overall_on_a_partial_scan_says_partial_once(tmp_path):
    (tmp_path / "index.js").write_text("console.log('hi')\n", encoding="utf-8")
    (tmp_path / "package.json").write_text('{"name": "x", "version": "1.0.0"}', encoding="utf-8")
    r = report.scan(str(tmp_path))
    assert r["status"] == "PARTIAL" and "PARTIAL" in r["scores"]["cap_reason"]
    s = plain.score_sentence("overall", r)
    assert s.count("PARTIAL") == 1 and "did not cover the whole project" not in s, s
    # a report without a cap reason (hand-made, or from an older version) still gets the clause, once
    bare = copy.deepcopy(r)
    bare["scores"]["cap_reason"] = None
    assert plain.score_sentence("overall", bare).count("did not cover the whole project") == 1


def test_fix_first_lead_comes_with_the_floor_note_and_only_then():
    r = report.scan(str(ROOT / "tests" / "fixtures" / "risky_repo"))
    kept = copy.deepcopy(r)
    lead = plain.fix_first_lead(r)
    assert any("0/100" in n for n in plain.fix_first_notes(r))
    assert lead == ("Safety problems do not raise the grade until most of them are fixed, so they can show +0 here. "
                    "Fix them first anyway.")
    assert not plain.VERDICT_PHRASES.search(lead) and " -- " not in lead
    assert r == kept
    for name in ("clean_repo", "works_broken", "supply_repo"):
        other = report.scan(str(ROOT / "tests" / "fixtures" / name))
        assert (plain.fix_first_lead(other) is None) == (not any("0/100" in n for n in plain.fix_first_notes(other)))
    assert plain.fix_first_lead(rep([], status="INVALID", reasons=["nothing to judge"])) is None
