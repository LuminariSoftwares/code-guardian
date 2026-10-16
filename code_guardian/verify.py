"""The verify loop: what did a change fix, what did it break, and what should be fixed next.

diff compares two scan reports (from `scan --json`, v0.3 or newer) by finding fingerprint. plan re-scores one report
without each check row in turn: the exact Overall points that row is worth. Neither reads or touches the code; both
are pure functions of the reports, so the same input always gives the same output.

    diff:    fixed = in BEFORE, not in AFTER; new = in AFTER, not in BEFORE; unchanged = in both (fingerprints are a
             multiset). Verdict: regressed when a WARN/FAIL finding is new or the status got worse (COMPLETE <
             PARTIAL < INVALID), improved when a WARN/FAIL finding is fixed or the status got better, mixed when both,
             unchanged otherwise. INFO findings are inventory: listed, never a verdict.
    plan:    for each check row (code + level) with a deduction, Overall with every finding of that row gone, minus
             Overall now. Ranked by that gain, ties by fewest locations, then by the larger deduction.

Public contract:
    LABEL
    load_report(value) -> report dict       # a dict, a JSON string, or a path to a JSON file
    diff(before, after) -> dict             diff_exit(d) -> 0, or 1 when anything regressed (verdict regressed/mixed)
    render_diff(d) -> text
    plan(report, top=10) -> dict            plan_markdown(p) -> str
"""

import collections
import json
import os
import sys

from . import catalogue, report, score
from .finding import make_finding, summarize

LABEL = "estimated gain if fixed"
STATUS_RANK = {"COMPLETE": 0, "PARTIAL": 1, "INVALID": 2}
VERDICT_LEVELS = ("WARN", "FAIL")
LABELS = {"safe": "Safe", "works": "Works", "complete": "Complete", "overall": "Overall"}


def load_report(value):
    """A report from a dict, a JSON string or a file path. ValueError when it is not a scan report; OSError when the
    file cannot be read."""
    if isinstance(value, dict):
        data = value
    elif isinstance(value, str) and value.lstrip().startswith("{"):
        data = json.loads(value)
    else:
        with open(value, encoding="utf-8") as fh:
            data = json.load(fh)
    if not (isinstance(data, dict) and isinstance(data.get("findings"), list) and isinstance(data.get("scores"), dict)):
        raise ValueError("not a code-guardian scan report (from scan --json)")
    return data


def _all(rep, which):
    out = list(rep["findings"]) + list((rep.get("hygiene") or {}).get("findings") or [])
    missing = [f for f in out if not f.get("fingerprint")]
    if missing:
        raise ValueError("the %s report has findings without a fingerprint: rescan it with code-guardian 0.3 or newer "
                         "(scan --json)" % which)
    return out


def _brief(f):
    return {"code": f["code"], "level": f["level"], "node": f["node"], "summary": f["summary"],
            "fingerprint": f["fingerprint"]}


def _minus(items, other):
    """items not matched by other, as a multiset; the rest. Order follows items."""
    left = collections.Counter(f["fingerprint"] for f in other)
    gone, kept = [], []
    for f in items:
        if left[f["fingerprint"]] > 0:
            left[f["fingerprint"]] -= 1
            kept.append(f)
        else:
            gone.append(f)
    return gone, kept


def diff(before, after):
    before, after = load_report(before), load_report(after)
    b, a = _all(before, "BEFORE"), _all(after, "AFTER")
    fixed, _ = _minus(b, a)
    new, unchanged = _minus(a, b)
    sb, sa = before.get("status", "COMPLETE"), after.get("status", "COMPLETE")
    worse = any(f["level"] in VERDICT_LEVELS for f in new) or STATUS_RANK.get(sa, 0) > STATUS_RANK.get(sb, 0)
    better = any(f["level"] in VERDICT_LEVELS for f in fixed) or STATUS_RANK.get(sa, 0) < STATUS_RANK.get(sb, 0)
    verdict = "mixed" if worse and better else "regressed" if worse else "improved" if better else "unchanged"
    scores = {k: {"before": before["scores"].get(k), "after": after["scores"].get(k),
                  "delta": after["scores"].get(k, 0) - before["scores"].get(k, 0)}
              for k in ("safe", "works", "complete", "overall")}
    return {"tool": "code-guardian", "verdict": verdict,
            "counts": {"fixed": len(fixed), "new": len(new), "unchanged": len(unchanged)},
            "scores": scores, "grade": {"before": before["scores"].get("grade"), "after": after["scores"].get("grade")},
            "status": {"before": sb, "after": sa},
            "fixed": [_brief(f) for f in score.sort_findings(fixed)],
            "new": [_brief(f) for f in score.sort_findings(new)],
            "unchanged": [_brief(f) for f in score.sort_findings(unchanged)]}


def diff_exit(d):
    return 1 if d["verdict"] in ("regressed", "mixed") else 0


def render_diff(d):
    c = d["counts"]
    lines = ["verdict: %s (%d fixed, %d new, %d unchanged)" % (d["verdict"], c["fixed"], c["new"], c["unchanged"]),
             "", "  %-9s %6s %6s %6s" % ("", "before", "after", "delta")]
    for k in ("safe", "works", "complete", "overall"):
        s = d["scores"][k]
        lines.append("  %-9s %6s %6s %+6d" % (LABELS[k], s["before"], s["after"], s["delta"]))
    lines += ["  %-9s %6s %6s" % ("grade", d["grade"]["before"] or "-", d["grade"]["after"] or "-"),
              "  %-9s %s -> %s" % ("status", d["status"]["before"], d["status"]["after"])]
    for name in ("fixed", "new"):
        lines += ["", "%s (%d):" % (name, len(d[name]))]
        lines.extend("  %-4s  %-13s %s  %s" % (f["level"], f["code"], f["node"], f["summary"]) for f in d[name])
        if not d[name]:
            lines.append("  none")
    lines += ["", "matched by fingerprint (code, level, file and the evidence line; line numbers ignored); INFO "
                  "findings never decide the verdict"]
    return "\n".join(lines) + "\n"


def plan(rep, top=10):
    rep = load_report(rep)
    status = rep.get("status", "COMPLETE")
    base = rep["scores"]["overall"]
    notes = []
    if status == "INVALID":
        return {"tool": "code-guardian", "label": LABEL, "path": rep.get("path"), "status": status, "overall": base,
                "grade": None, "items": [], "notes": ["the scan is INVALID: there is nothing to plan"]}
    if status == "PARTIAL":
        notes.append("the scan is PARTIAL (%s): the gains assume it stays so"
                     % "; ".join(rep.get("status_reasons") or []))
    every = report.scored_findings(rep)
    items = []
    for name in score.DIMENSIONS:
        dim = rep["dimensions"][name]
        if dim["deducted"] > 100:
            notes.append("%s is at 0/100 with %d points deducted, so no single %s fix moves Overall yet (each shows "
                         "+0): %d points of %s deductions must go first. Fix them anyway: a Safe FAIL caps the grade "
                         "at %s." % (LABELS[name], dim["deducted"], LABELS[name], dim["deducted"] - 100,
                                     LABELS[name], score.FAIL_CAP))
        for row in dim["checks"]:
            key = (row["code"], row["level"])
            rest = [f for f in every if (f["code"], f["level"]) != key]
            dims = {n: score.dimension(rest, n) for n in score.DIMENSIONS}
            after = score.scores([f for f in rep["findings"] if (f["code"], f["level"]) != key], dims, status)
            entry = catalogue.CATALOGUE.get(row["code"], {})
            items.append({"code": row["code"], "level": row["level"], "dimension": name,
                          "title": entry.get("title", row["code"]), "gain": after["overall"] - base,
                          "overall_after": after["overall"], "grade_after": after["grade"],
                          "deduction": row["deduction"], "count": row["count"],
                          "locations": row.get("locations") or [row["first"]], "more": row.get("more", 0),
                          "fix": entry.get("fix", ""), "false_positives": entry.get("false_positives", "")})
    items.sort(key=lambda i: (-i["gain"], i["count"], -i["deduction"], score.DIMENSIONS.index(i["dimension"]),
                              i["code"], i["level"]))
    items = items[:max(0, int(top))]
    for rank, item in enumerate(items, 1):
        item["rank"] = rank
    return {"tool": "code-guardian", "label": LABEL, "path": rep.get("path"), "status": status, "overall": base,
            "grade": rep["scores"].get("grade"), "items": items, "notes": notes}


def plan_markdown(p):
    name = os.path.basename(os.path.abspath(str(p.get("path") or "."))) or p.get("path")
    out = ["# code-guardian repair plan: %s" % name, "",
           "Overall **%s/100**, grade **%s**, scan %s." % (p["overall"], p["grade"] or "none", p["status"]), "",
           "Each row's points are the **%s**: what Overall would gain if every finding of that check were gone, "
           "re-scored with the same weights. The plan never touches the code; scan again after fixing and "
           "`code-guardian diff` the two reports." % LABEL, ""]
    out += ["> %s" % n for n in p["notes"]] + ([""] if p["notes"] else [])
    for i in p["items"]:
        where = ", ".join("`%s`" % loc for loc in i["locations"]) + (" and %d more" % i["more"] if i["more"] else "")
        out += ["### %d. `%s` %s (%s): %+d → %s/100 (grade %s)" % (i["rank"], i["code"], i["level"],
                                                                LABELS[i["dimension"]], i["gain"], i["overall_after"],
                                                                i["grade_after"]),
                "", "**%s.** %s" % (i["title"], i["fix"]), "",
                "Deduction %d over %d finding(s): %s." % (i["deduction"], i["count"], where), ""]
    if not p["items"]:
        out += ["Nothing to fix: no check deducts points.", ""]
    return "\n".join(out)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if "--selftest" in argv:
        return selftest()
    sys.stderr.write("usage: python -m code_guardian.verify --selftest\n")
    return 2


def selftest():
    def f(code, level, node, fp):
        out = make_finding(code, "partial", level, node, "s")
        out["fingerprint"] = fp
        return out

    def rep(findings, status="COMPLETE"):
        dims = {n: score.dimension(findings, n) for n in score.DIMENSIONS}
        return {"findings": findings, "hygiene": {"findings": []}, "status": status, "dimensions": dims,
                "scores": score.scores(findings, dims, status), "path": "demo"}

    a, b, c = (("%064x" % i) for i in (1, 2, 3))
    before = rep([f("exec.shell", "WARN", "a.py:1", a), f("tls.off", "FAIL", "a.py:2", b),
                  f("complete.readme_missing", "WARN", ".", c)])
    after = rep([f("exec.shell", "WARN", "a.py:5", a)])
    d = diff(before, after)
    p = plan(before)
    try:
        diff(rep([make_finding("x", "partial", "WARN", "a.py:1", "s")]), after)
        refuses = False
    except ValueError:
        refuses = True
    checks = [
        ("diff_sets", [x["fingerprint"] for x in d["fixed"]] == [c, b] and [x["fingerprint"] for x in d["unchanged"]] == [a]
         and d["new"] == []),
        ("verdict", d["verdict"] == "improved" and diff_exit(d) == 0 and diff(after, before)["verdict"] == "regressed"),
        ("deltas", d["scores"]["safe"] == {"before": 65, "after": 90, "delta": 25}),
        ("refuses_unfingerprinted", refuses),
        ("plan_rank", [i["code"] for i in p["items"]] == ["tls.off", "exec.shell", "complete.readme_missing"]),
        ("plan_exact", p["items"][0]["gain"] == rep(after["findings"] + [before["findings"][2]])["scores"]["overall"]
         - before["scores"]["overall"]),
        ("plan_top", len(plan(before, top=1)["items"]) == 1 and plan(rep([], "INVALID"))["items"] == []),
        ("markdown", "### 1. `tls.off` FAIL (Safe)" in plan_markdown(p) and LABEL in plan_markdown(p)),
        ("render_diff", render_diff(d).startswith("verdict: improved (2 fixed, 0 new, 1 unchanged)")),
        ("load_string", load_report(json.dumps(before))["path"] == "demo"),
    ]
    return summarize("verify", checks)


if __name__ == "__main__":
    sys.exit(main())
