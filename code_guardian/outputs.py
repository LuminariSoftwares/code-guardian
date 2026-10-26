"""SARIF 2.1.0 and Markdown renderings of a scan report. Pure functions of the report: no clock, no absolute paths,
so the same report always gives the same bytes.

SARIF: one rule per check code (from the catalogue), one result per finding (scored findings plus the hygiene
section). GitHub code scanning rejects results without a physical location, so repo-level findings (node ".") are
attached to report["anchor"] (the root manifest or README) with no line. The run properties carry the scores, the
status and the coverage (which files were analysed).

Markdown (the Action's job summary) opens with the status and the coverage line, then the score table.

Public contract:
    to_sarif(report) -> dict          to_markdown(report) -> str
"""

import json
import sys

from . import catalogue, score
from .finding import summarize
from .orphans import LEVELS as ORPHAN_LEVELS
from .scanners import redact_report

SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
HOME = "https://github.com/LuminariSoftwares/code-guardian"
SARIF_LEVEL = {"FAIL": "error", "WARN": "warning", "INFO": "note", "OK": "none"}
RANK = ("OK", "INFO", "WARN", "FAIL")
LABELS = {"safe": "Safe", "works": "Works", "complete": "Complete"}
QUESTIONS = {"safe": "is it safe to run?", "works": "will it work?", "complete": "does it have what it needs?"}


def _default_level(code):
    levels = [lv for table in score.TABLES.values() for (c, lv) in table if c == code]
    levels += [ORPHAN_LEVELS[code]] if code in ORPHAN_LEVELS else []
    return max(levels or ["WARN"], key=RANK.index)


def _max_weight(code):
    return max([w for table in score.TABLES.values() for (c, _), w in table.items() if c == code] or [0])


def _rule(code):
    entry = catalogue.CATALOGUE[code]
    dim = score.dimension_of(code)
    props = {"tags": [dim] + (["security"] if dim == "safe" else []), "dimension": dim}
    if dim == "safe":
        w = _max_weight(code)
        props["security-severity"] = "8.0" if w >= 30 else "5.0" if w >= 10 else "2.0"
    return {"id": code, "name": "".join(p.capitalize() for p in code.replace("_", ".").split(".")),
            "shortDescription": {"text": entry["title"]}, "fullDescription": {"text": entry["means"]},
            "help": {"text": "Fix: %s False positives: %s" % (entry["fix"], entry["false_positives"])},
            "helpUri": HOME + "#check-catalogue",
            "defaultConfiguration": {"level": SARIF_LEVEL[_default_level(code)]}, "properties": props}


def _location(node, anchor):
    path, _, line = str(node).rpartition(":")
    if not path or not line.isdigit():
        return {"physicalLocation": {"artifactLocation": {"uri": anchor}}}
    loc = {"artifactLocation": {"uri": path}}
    if int(line) >= 1:
        loc["region"] = {"startLine": int(line)}
    return {"physicalLocation": loc}


def to_sarif(report):
    report = redact_report(report)
    codes = sorted(catalogue.CATALOGUE)
    index = {c: i for i, c in enumerate(codes)}
    results = []
    for f in report["findings"] + report["hygiene"]["findings"]:
        code = f["code"] if f["code"] in index else "check.crashed"
        res = {"ruleId": code, "ruleIndex": index[code], "level": SARIF_LEVEL.get(f["level"], "warning"),
               "message": {"text": f["summary"]}, "locations": [_location(f["node"], report["anchor"])],
               "properties": {"dimension": score.dimension_of(code), "confidence": f.get("confidence", "LIKELY")}}
        if f.get("fingerprint"):
            res["partialFingerprints"] = {"codeGuardian/v1": f["fingerprint"]}
        if "new" in f:
            res["properties"]["new"] = f["new"]
        results.append(res)
    return {"$schema": SCHEMA, "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "code-guardian", "version": report["version"], "informationUri": HOME,
                                          "rules": [_rule(c) for c in codes]}},
                      "results": results,
                      "properties": dict({"scores": report["scores"], "weights_rule": report["weights_rule"],
                                          "status": report.get("status", "COMPLETE"),
                                          "status_reasons": report.get("status_reasons", [])},
                                         **({"coverage": report["coverage"]} if report.get("coverage") else {}))}]}


def _cell(text):
    return str(text).replace("|", "\\|").replace("\n", " ")


def _row(f):
    return "| %s | `%s` | `%s` | %s%s |" % (f["level"], f["code"], _cell(f["node"]), _cell(f["summary"]),
                                          " **(new)**" if f.get("new") else "")


def _score_cell(report, d):
    dim = (report.get("dimensions") or {}).get(d, {})
    if not dim.get("scored", True):
        return "n/a (no Python or JavaScript)"
    return "%d/100%s" % (report["scores"][d], " (partial)" if dim.get("partial") else "")


def to_markdown(report):
    import os
    from .report import coverage_line, overall_notes
    report = redact_report(report)
    s = report["scores"]
    name = os.path.basename(os.path.abspath(report["path"])) or report["path"]
    status = report.get("status", "COMPLETE")
    reasons = report.get("status_reasons") or []
    out = ["# code-guardian: %s" % name, ""]
    if status == "INVALID":
        out += ["**Status: INVALID**: no scores and no grade (%s)." % _cell("; ".join(reasons)), ""]
    else:
        out += ["**Status: %s**%s" % (status, " (%s)" % _cell("; ".join(reasons)) if reasons else ""), ""]
        if report.get("coverage"):
            out += ["**Coverage:** %s" % _cell(coverage_line(report["coverage"]).split(": ", 1)[1]), ""]
        unscored = [n for n in overall_notes(report) if "not scored" in n]
        out += ["| | score | |", "|---|---:|---|"]
        out += ["| **%s** | %s | %s |" % (LABELS[d], _score_cell(report, d), QUESTIONS[d]) for d in score.DIMENSIONS]
        out += ["| **Overall** | %d/100 | grade **%s**%s |" % (s["overall"], s["grade"],
                                                            " (%s)" % _cell("; ".join(unscored)) if unscored else ""), ""]
    if s["capped"]:
        out += ["> %s" % _cell(s["cap_reason"]), ""]
    if report["top"]:
        out += ["## Biggest deductions", "", "| deduction | dimension | check | count | first at |", "|---:|---|---|---:|---|"]
        out += ["| -%d | %s | `%s` %s | %d | `%s` |" % (t["deduction"], LABELS[t["dimension"]], t["code"], t["level"],
                                                       t["count"], _cell(t["first"])) for t in report["top"]]
        out.append("")
    out += ["## Findings", ""]
    if report.get("baseline"):
        b = report["baseline"]
        out += ["Baseline: %d new, %d known (the gate counts new findings only; the scores count all)." % (b["new"], b["known"]), ""]
    for dim in score.DIMENSIONS:
        group = [f for f in report["findings"] if score.dimension_of(f["code"]) == dim]
        out += ["### %s (%d)" % (LABELS[dim], len(group)), ""]
        if group:
            out += ["| level | check | where | what |", "|---|---|---|---|"] + [_row(f) for f in group]
        else:
            out.append("Nothing found.")
        out.append("")
    h = report["hygiene"]
    c = h["counts"]
    out += ["## Hygiene", "", "%s entry points (%d): %d dead, %d test-only, %d uncertain."
            % (h["source"], len(h["entry_points"]), c["orphan.dead"], c["orphan.test_only"], c["orphan.uncertain"]), ""]
    if h["findings"]:
        out += ["| level | check | where | what |", "|---|---|---|---|"] + [_row(f) for f in h["findings"]] + [""]
    out += ["## Weights used", "", _cell(report["weights_rule"]).capitalize() + ".", "",
            "| dimension | check | weight |", "|---|---|---:|"]
    for dim in score.DIMENSIONS:
        out += ["| %s | `%s` | %d |" % (LABELS[dim], key, w) for key, w in report["weights"][dim].items()]
    notes = report["notes"] + h["notes"]
    if notes:
        out += ["", "## Notes", ""] + ["- %s" % n for n in notes]
    out += ["", "Static analysis by [code-guardian](%s) %s: every finding is LIKELY; scores come from fixed weights, never "
            "from a model." % (HOME, report["version"])]
    return "\n".join(out) + "\n"


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if "--selftest" in argv:
        return selftest()
    sys.stderr.write("usage: python -m code_guardian.outputs --selftest\n")
    return 2


def selftest():
    f = {"code": "tls.off", "level": "FAIL", "node": "a.py:3", "summary": "x | y", "confidence": "LIKELY"}
    repo = {"code": "works.tests_missing", "level": "WARN", "node": ".", "summary": "no tests", "confidence": "LIKELY"}
    rep = {"version": "0", "path": "demo", "anchor": "pyproject.toml", "findings": [f, repo],
           "hygiene": {"findings": [], "source": "inferred", "entry_points": [], "notes": [],
                       "counts": {"orphan.dead": 0, "orphan.test_only": 0, "orphan.uncertain": 0}},
           "scores": score.scores([f, repo]), "top": [], "weights": score.weight_table(), "weights_rule": "w",
           "notes": []}
    sarif = to_sarif(rep)
    res = sarif["runs"][0]["results"]
    md = to_markdown(rep)
    checks = [
        ("rules", [r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]] == sorted(catalogue.CATALOGUE)),
        ("levels", [r["level"] for r in res] == ["error", "warning"]),
        ("anchor", res[1]["locations"][0]["physicalLocation"] == {"artifactLocation": {"uri": "pyproject.toml"}}),
        ("region", res[0]["locations"][0]["physicalLocation"]["region"] == {"startLine": 3}),
        ("markdown", "| FAIL | `tls.off` | `a.py:3` | x \\| y |" in md and md.startswith("# code-guardian: demo")),
        ("redacted", all(leak not in json.dumps(to_sarif(dict(rep, findings=[dict(f, summary="to " + leak)])))
                         and leak not in to_markdown(dict(rep, findings=[dict(f, summary="to " + leak)]))
                         for leak in ("sk-" + "B" * 20, "bob" + "@" + "mail.org"))),
        ("status", sarif["runs"][0]["properties"]["status"] == "COMPLETE" and "**Status: COMPLETE**" in md
         and "**Status: INVALID**" in to_markdown(dict(rep, status="INVALID", status_reasons=["r"]))),
    ]
    return summarize("outputs", checks)


if __name__ == "__main__":
    sys.exit(main())
