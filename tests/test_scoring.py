"""The v0.2 scoring model: Safe / Works / Complete (higher is better), per-check deductions with a count cap,
Overall = 0.5*Safe + 0.3*Works + 0.2*Complete, grade bands and the Safe-FAIL cap. Values are worked out by hand."""
import pytest

import make_risky
from conftest import FIXTURES

from code_guardian import report, score
from code_guardian.finding import make_finding


def f(code, level, node="a.py:1"):
    return make_finding(code, "partial", level, node, "s")


@pytest.mark.parametrize("weight, count, expected", [
    (40, 1, 40), (40, 2, 50), (40, 3, 60), (40, 5, 80), (40, 50, 80),   # +25% per extra, at most 2x
    (10, 2, 13), (10, 4, 18), (10, 5, 20), (10, 9, 20),
    (3, 2, 4), (3, 4, 6), (3, 100, 6),
    (2, 1, 2), (2, 2, 3), (2, 3, 3), (2, 50, 4),
    (0, 7, 0),
])
def test_per_check_deduction_and_count_cap(weight, count, expected):
    assert score.deduction(weight, count) == expected


def test_fifty_copies_of_a_minor_issue_cannot_zero_a_score():
    many = [f("net.egress", "WARN", "a.py:%d" % i) for i in range(1, 51)]
    assert score.scores(many)["safe"] == 100 - 2 * 2


@pytest.mark.parametrize("overall, grade", [
    (100, "A"), (90, "A"), (89, "B"), (75, "B"), (74, "C"), (60, "C"), (59, "D"), (40, "D"), (39, "F"), (0, "F")])
def test_grade_band_edges(overall, grade):
    assert score.grade(overall) == grade


def test_empty_repo_is_perfect():
    s = score.scores([])
    assert (s["safe"], s["works"], s["complete"], s["overall"], s["grade"], s["capped"]) == (100, 100, 100, 100, "A", False)


def test_overall_weights_and_rounding():
    assert score.overall(100, 100, 100) == 100
    assert score.overall(0, 100, 100) == 50
    assert score.overall(80, 70, 65) == 74       # 40 + 21 + 13 = 74
    assert score.overall(81, 70, 66) == 75       # 40.5 + 21 + 13.2 = 74.7 -> 75 (half up)


def test_a_single_safe_fail_caps_the_grade_at_d():
    one_key = [f("secret.key", "FAIL")]
    s = score.scores(one_key)
    assert s["safe"] == 60 and s["works"] == 100 and s["complete"] == 100
    assert s["overall"] == 80                    # (300 + 300 + 200) / 10 -> B before the cap
    assert s["grade_uncapped"] == "B" and s["grade"] == "D" and s["capped"] is True
    assert "secret.key" in s["cap_reason"]


def test_warn_does_not_cap():
    s = score.scores([f("exec.shell", "WARN")])
    assert (s["safe"], s["overall"], s["grade"], s["capped"]) == (90, 95, "A", False)


def test_every_dimension_has_a_table_and_unknown_codes_weigh_nothing():
    assert set(score.TABLES) == {"safe", "works", "complete"}
    assert score.TABLES["safe"][("secret.key", "FAIL")] == 40  # the v0.1 threat weights, unchanged
    assert score.scores([f("parse.whatever", "FAIL")])["safe"] == 100


def test_risky_repo_hand_computed(tmp_path):
    rep = report.scan(str(make_risky.build(tmp_path / "risky")))
    rows = {(r["code"], r["level"]): (r["count"], r["deduction"]) for r in rep["dimensions"]["safe"]["checks"]}
    assert rows == {
        ("secret.key", "FAIL"): (3, 60), ("exec.shell", "FAIL"): (1, 30), ("exec.shell", "WARN"): (1, 10),
        ("exec.dynamic", "WARN"): (2, 13), ("deser.unsafe", "WARN"): (2, 13), ("net.egress", "WARN"): (1, 2),
        ("net.bind_all", "WARN"): (1, 5), ("tls.off", "FAIL"): (1, 25), ("install.hook", "WARN"): (3, 23),
        ("obfuscation", "FAIL"): (1, 40), ("obfuscation", "WARN"): (2, 13), ("fs.outside", "WARN"): (1, 3),
    }
    assert rep["dimensions"]["safe"]["deducted"] == 237
    s = rep["scores"]
    # Works: works.tests_missing 15 -> 85 (a library: no dead code once its public API counts as entry points)
    # Complete: licence 20 + README 20 + CI 10 + metadata 10 + licence undeclared 5 = 65 -> 35
    assert (s["safe"], s["works"], s["complete"], s["overall"], s["grade"]) == (0, 85, 35, 33, "F")
    assert s["capped"] is True and s["grade_uncapped"] == "F"  # the cap never raises a grade
    assert [(t["dimension"], t["code"], t["level"], t["deduction"], t["first"]) for t in rep["top"]] == [
        ("safe", "secret.key", "FAIL", 60, "deploy/id_rsa:1"),
        ("safe", "obfuscation", "FAIL", 40, "risky/loader.py:7"),
        ("safe", "exec.shell", "FAIL", 30, "risky/runner.py:7"),
        ("safe", "tls.off", "FAIL", 25, "risky/network.py:11"),
        ("safe", "install.hook", "WARN", 23, "package.json:5"),
    ]


def test_clean_repo_is_a():
    s = report.scan(str(FIXTURES / "clean_repo"))["scores"]
    assert (s["safe"], s["works"], s["complete"], s["overall"], s["grade"]) == (100, 100, 100, 100, "A")


def test_report_carries_the_weight_table_it_used():
    rep = report.scan(str(FIXTURES / "clean_repo"))
    assert rep["weights"]["safe"]["secret.key FAIL"] == 40
    assert set(rep["weights"]) == {"safe", "works", "complete"}
    assert "2x" in rep["weights_rule"]
    text = report.render(rep)
    assert "weights used" in text and "secret.key FAIL 40" in text


def test_output_is_byte_identical_across_runs(tmp_path):
    import json
    path = str(make_risky.build(tmp_path / "risky"))
    a, b = report.scan(path), report.scan(path)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    assert report.render(a) == report.render(b)
