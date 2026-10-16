"""Three health scores (higher is better): Safe, Works and Complete, each 0-100, plus Overall and an A-F grade.

No model, no randomness, no clock: the same findings always give the same scores.

    deduction(weight, n) = weight + min(weight, ceil(weight * (n - 1) / 4))
        A check (one row of a table: code + level) deducts its weight once, plus a quarter of the weight for each
        extra occurrence, capped at twice the weight. Fifty copies of one minor issue cannot zero a score.
    dimension score      = max(0, 100 - sum of its deductions)      (Safe = 100 - the v0.1 threat score)
    Overall              = 0.5*Safe + 0.3*Works + 0.2*Complete, rounded half up
    grade                = A >= 90, B >= 75, C >= 60, D >= 40, F below 40
    FAIL cap             = any Safe finding at FAIL caps the grade at D, whatever the average
    PARTIAL cap          = a PARTIAL scan caps the grade at B; an INVALID scan has no grade (None)

Public contract:
    TABLES = {"safe": {...}, "works": {...}, "complete": {...}}   # {(code, level): weight}; unlisted weighs 0
    DIMENSIONS, WEIGHTS_RULE
    dimension_of(code) -> "safe" | "works" | "complete"
    weight(finding) -> int          deduction(weight, n) -> int
    dimension(findings, name) -> {"score", "deducted",
                                  "checks": [{"code","level","count","weight","deduction","first","locations","more"}]}
    overall(safe, works, complete) -> int        grade(overall) -> "A".."F"
    scores(findings, dimensions=None, status=None)
        -> {"safe","works","complete","overall","grade","grade_uncapped","capped","cap_reason"}
    top(dimensions, n=5) -> the biggest deductions across dimensions
    weight_table() -> {dimension: {"code LEVEL": weight}}
    node_key(node), sort_findings(findings)
"""

import sys

from .finding import make_finding, summarize

# Each table is documented in the README's check catalogue: change both together.
SAFE_WEIGHTS = {  # the v0.1 threat weights, unchanged
    ("secret.key", "FAIL"): 40,
    ("secret.key", "INFO"): 0,
    ("secret.history", "FAIL"): 30,  # opt-in (scan --history)
    ("exec.dynamic", "FAIL"): 30,
    ("exec.dynamic", "WARN"): 10,
    ("exec.shell", "WARN"): 10,
    ("exec.shell", "FAIL"): 30,
    ("deser.unsafe", "WARN"): 10,
    ("net.egress", "INFO"): 0,
    ("net.egress", "WARN"): 2,
    ("net.bind_all", "WARN"): 5,
    ("tls.off", "FAIL"): 25,
    ("tls.off", "WARN"): 10,
    ("install.hook", "WARN"): 15,
    ("obfuscation", "WARN"): 10,
    ("obfuscation", "FAIL"): 40,
    ("fs.outside", "WARN"): 3,
    ("deps.unpinned", "INFO"): 0,
    ("supply.unknown_package", "FAIL"): 40,
    ("supply.unknown_package", "WARN"): 10,
    ("supply.unknown_package", "INFO"): 0,
    ("supply.lookalike", "WARN"): 15,
    ("privacy.pii_log", "WARN"): 5,
    ("privacy.pii_prompt", "WARN"): 5,
}
WORKS_WEIGHTS = {
    ("works.syntax", "FAIL"): 30,
    ("works.syntax", "INFO"): 0,
    ("works.import_unresolved", "WARN"): 10,
    ("works.relative_missing", "FAIL"): 25,
    ("works.tests_missing", "WARN"): 15,
    ("works.test_no_assert", "WARN"): 5,
    ("works.entry_missing", "FAIL"): 30,
    ("orphan.dead", "WARN"): 3,  # from the hygiene section; only when entry points exist (contract or inferred)
    ("works.todo_stub", "WARN"): 3,  # AI leftovers (leftovers.py)
    ("works.commented_code", "INFO"): 0,
    ("works.dead_flag", "INFO"): 0,
}
COMPLETE_WEIGHTS = {
    ("complete.license_missing", "WARN"): 20,
    ("complete.license_undeclared", "WARN"): 5,
    ("complete.readme_missing", "WARN"): 20,
    ("complete.readme_short", "WARN"): 10,
    ("complete.readme_sections", "WARN"): 5,
    ("complete.ci_missing", "WARN"): 10,
    ("complete.metadata", "WARN"): 10,
    ("complete.lockfile", "WARN"): 10,
    ("complete.env_example", "WARN"): 10,
    ("deps.declared_unused", "INFO"): 0,
}
TABLES = {"safe": SAFE_WEIGHTS, "works": WORKS_WEIGHTS, "complete": COMPLETE_WEIGHTS}
DIMENSIONS = ("safe", "works", "complete")
PREFIXES = {"works": ("works.", "orphan."), "complete": ("complete.",)}
OVERALL_TENTHS = {"safe": 5, "works": 3, "complete": 2}
GRADE_BANDS = ((90, "A"), (75, "B"), (60, "C"), (40, "D"), (0, "F"))
FAIL_CAP = "D"
PARTIAL_CAP = "B"  # a scan that skipped or crashed somewhere cannot vouch for an A
GRADE_ORDER = "ABCDF"
LOCATIONS_MAX = 20  # a check row cites every distinct file:line, sorted, up to this many, plus "more": the rest
WEIGHTS_RULE = ("each check (code + level) deducts its weight once, plus a quarter of the weight per extra "
                "occurrence (rounded up), at most 2x the weight; INFO is never scored")


def dimension_of(code):
    for name in DIMENSIONS:
        if any(c == code for c, _ in TABLES[name]):
            return name
    for name, prefixes in PREFIXES.items():
        if str(code).startswith(prefixes):
            return name
    return "safe"


def weight(f):
    return TABLES[dimension_of(f.get("code"))].get((f.get("code"), f.get("level")), 0)


def deduction(weight_, count):
    if weight_ <= 0 or count <= 0:
        return 0
    extra = -(-weight_ * (count - 1) // 4)  # ceil without floats
    return weight_ + min(weight_, extra)


def node_key(node):
    """("pkg/a.py", 12) for "pkg/a.py:12", so line 9 sorts before line 10."""
    path, _, line = str(node).rpartition(":")
    return (path, int(line)) if line.isdigit() else (str(node), 0)


def sort_findings(findings):
    return sorted(findings, key=lambda f: (node_key(f["node"]), f["code"], f["summary"]))


def dimension(findings, name):
    groups = {}
    for f in findings:
        if dimension_of(f["code"]) == name and weight(f) > 0:
            groups.setdefault((f["code"], f["level"]), []).append(f["node"])
    checks = []
    for (code, level), nodes in groups.items():
        w = TABLES[name][(code, level)]
        where = sorted(set(nodes), key=node_key)
        checks.append({"code": code, "level": level, "count": len(nodes), "weight": w,
                       "deduction": deduction(w, len(nodes)), "first": where[0],
                       "locations": where[:LOCATIONS_MAX], "more": max(0, len(where) - LOCATIONS_MAX)})
    checks.sort(key=lambda r: (-r["deduction"], r["code"], r["level"]))
    deducted = sum(r["deduction"] for r in checks)
    return {"score": max(0, 100 - deducted), "deducted": deducted, "checks": checks}


def overall(safe, works, complete):
    tenths = (OVERALL_TENTHS["safe"] * safe + OVERALL_TENTHS["works"] * works
              + OVERALL_TENTHS["complete"] * complete)
    return (tenths + 5) // 10


def grade(value):
    for floor, letter in GRADE_BANDS:
        if value >= floor:
            return letter
    return "F"


def scores(findings, dimensions=None, status=None):
    """status (COMPLETE / PARTIAL / INVALID, see report.py): PARTIAL caps the grade at B; INVALID gives no grade."""
    dims = dimensions or {name: dimension(findings, name) for name in DIMENSIONS}
    s, w, c = (dims[n]["score"] for n in DIMENSIONS)
    total = overall(s, w, c)
    if status == "INVALID":
        return {"safe": s, "works": w, "complete": c, "overall": total, "grade": None, "grade_uncapped": None,
                "capped": False, "cap_reason": None}
    uncapped = grade(total)
    fails = sorted({f["code"] for f in findings if f["level"] == "FAIL" and dimension_of(f["code"]) == "safe"})
    caps = [(FAIL_CAP, "a Safe check is FAIL (%s): the grade is at most %s" % (", ".join(fails), FAIL_CAP))] if fails else []
    if status == "PARTIAL":
        caps.append((PARTIAL_CAP, "the scan is PARTIAL: the grade is at most %s" % PARTIAL_CAP))
    final = uncapped
    for letter, _ in caps:
        final = max(final, letter, key=GRADE_ORDER.index)
    return {"safe": s, "works": w, "complete": c, "overall": total,
            "grade": final, "grade_uncapped": uncapped, "capped": bool(caps),
            "cap_reason": "; ".join(reason for _, reason in caps) or None}


def top(dimensions, n=5):
    rows = [dict(r, dimension=name) for name in DIMENSIONS for r in dimensions[name]["checks"]]
    rows.sort(key=lambda r: (-r["deduction"], DIMENSIONS.index(r["dimension"]), r["code"], r["level"]))
    return rows[:n]


def weight_table():
    return {name: {"%s %s" % key: w for key, w in sorted(TABLES[name].items())} for name in DIMENSIONS}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if "--selftest" in argv:
        return selftest()
    sys.stderr.write("usage: python -m code_guardian.score --selftest\n")
    return 2


def selftest():
    def f(code, level, node="a.py:1"):
        return make_finding(code, "partial", level, node, "s")

    key = scores([f("secret.key", "FAIL")])
    many = [f("net.egress", "WARN", "a.py:%d" % i) for i in range(1, 51)]
    mixed = dimension([f("fs.outside", "WARN", "b.py:10"), f("fs.outside", "WARN", "b.py:9"), f("tls.off", "FAIL", "c.py:2"),
                       f("net.egress", "INFO", "a.py:1")], "safe")
    checks = [
        ("band_edges", [grade(v) for v in (100, 90, 89, 75, 74, 60, 59, 40, 39, 0)] ==
         ["A", "A", "B", "B", "C", "C", "D", "D", "F", "F"]),
        ("count_factor", [deduction(10, n) for n in (1, 2, 3, 4, 5, 6, 100)] == [10, 13, 15, 18, 20, 20, 20]),
        ("count_ceiling", deduction(40, 1000) == 80 and deduction(3, 1000) == 6 and deduction(0, 5) == 0),
        ("fifty_minor", scores(many)["safe"] == 96),
        ("empty_repo", scores([]) == {"safe": 100, "works": 100, "complete": 100, "overall": 100, "grade": "A",
                                       "grade_uncapped": "A", "capped": False, "cap_reason": None}),
        ("overall_round", overall(0, 100, 100) == 50 and overall(81, 70, 66) == 75 and overall(80, 70, 65) == 74),
        ("fail_cap", key["overall"] == 80 and key["grade_uncapped"] == "B" and key["grade"] == "D"),
        ("cap_never_raises", scores([f("secret.key", "FAIL")] * 9 + [f("tls.off", "FAIL")])["grade"] in ("D", "F")),
        ("dimension_rows", mixed["deducted"] == 29 and [r["code"] for r in mixed["checks"]] == ["tls.off", "fs.outside"]
         and mixed["checks"][1]["first"] == "b.py:9" and mixed["checks"][1]["locations"] == ["b.py:9", "b.py:10"]),
        ("locations_cap", dimension(many, "safe")["checks"][0]["locations"][-1] == "a.py:20"
         and dimension(many, "safe")["checks"][0]["more"] == 30),
        ("routing", dimension_of("works.syntax") == "works" and dimension_of("complete.readme") == "complete"
         and dimension_of("secret.key") == "safe" and dimension_of("orphan.dead") == "works"),
        ("node_key", node_key("x/y.py:10") == ("x/y.py", 10) and node_key("odd") == ("odd", 0)),
        ("partial_cap", scores([], status="PARTIAL")["grade"] == "B" and scores([], status="PARTIAL")["grade_uncapped"] == "A"
         and scores([f("secret.key", "FAIL")], status="PARTIAL")["grade"] == "D"
         and scores([f("secret.key", "FAIL")], status="PARTIAL")["cap_reason"].count(": the grade is at most") == 2),
        ("invalid_no_grade", scores([], status="INVALID")["grade"] is None and scores([], status="COMPLETE")["grade"] == "A"),
        ("tainted_exec_fail", scores([f("exec.dynamic", "FAIL")])["safe"] == 70
         and scores([f("secret.key", "INFO")])["safe"] == 100),
    ]
    return summarize("score", checks)


if __name__ == "__main__":
    sys.exit(main())
