"""Run a scan end to end and render it. Reads files; never executes, imports or installs them; no network unless
explain=True, and then only the URL in CODE_GUARDIAN_LLM_URL.

Public contract:
    scan(path, goal_file=None, explain=False, env=None) -> report dict   # raises UsageError / goal.GoalError
    orphans(path, goal_file=None, infer=False) -> hygiene dict (+ "files")
    render(report) -> text            render_orphans(hygiene) -> text
    exit_code(findings, fail_on) -> 0 or 1
"""

import ast
import os
import shutil
import sys
import tempfile
import time
import warnings

from . import __version__, explain as explain_mod, goal, manifests, orphans as orphans_mod, scanners, score, walk
from .finding import LEVELS, make_finding, summarize

SOURCE_EXT = frozenset({".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".go", ".rs", ".java", ".kt", ".rb", ".php",
                        ".sh", ".bash", ".ps1", ".bat", ".c", ".h", ".cc", ".cpp", ".hpp", ".cs", ".swift", ".lua",
                        ".pl", ".r", ".scala", ".dart"})
PARSE_ERRORS = (SyntaxError, ValueError, RecursionError, MemoryError)


class UsageError(ValueError):
    """PATH is not a directory."""


def _root(path):
    root = os.path.abspath(os.path.expanduser(path))
    if not os.path.isdir(root):
        raise UsageError("not a directory: %s" % path)
    return root


def _contract(root, goal_file):
    gpath = goal.find(root, goal_file)
    contract = goal.load(gpath) if gpath else None
    notes = []
    if contract and contract["unknown_keys"]:
        notes.append("goal file: unknown keys ignored: %s" % ", ".join(contract["unknown_keys"]))
    return contract, notes


def _parse(rel, raw):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return ast.parse(raw, filename=rel)


def _unparsed(rel, exc):
    return make_finding("parse.skipped", "partial", "INFO", "%s:%d" % (rel, getattr(exc, "lineno", None) or 1),
                        "Python file does not parse; it got the secret scan only",
                        ["error: %s" % type(exc).__name__], ["check it is Python 3 source"])


def _languages(files):
    counts = {}
    for rel in files:
        ext = os.path.splitext(rel)[1].lower()
        if ext in SOURCE_EXT:
            counts[ext] = counts.get(ext, 0) + 1
    return dict(sorted(counts.items()))


def scan(path, goal_file=None, explain=False, env=None):
    started = time.perf_counter()
    root = _root(path)
    contract, notes = _contract(root, goal_file)
    inv = walk.walk(root, exclude=contract["exclude"] if contract else ())
    findings, trees, entries = [], {}, []
    for rel in inv["python"]:
        raw, text = walk.read(root, rel)
        findings.extend(scanners.scan_secret_text(rel, text, python=True))
        try:
            pf = scanners.PyFile(rel, raw, text)
        except PARSE_ERRORS as exc:
            findings.append(_unparsed(rel, exc))
            continue
        trees[rel] = pf.tree
        findings.extend(scanners.scan_python(pf))
        if rel.rsplit("/", 1)[-1] == "setup.py":
            findings.extend(manifests.scan_manifest(rel, text, pf))
    for rel in inv["manifests"]:
        if rel.endswith(".py"):
            continue
        _, text = walk.read(root, rel)
        findings.extend(scanners.scan_secret_text(rel, text, python=False))
        findings.extend(manifests.scan_manifest(rel, text))
        entries.extend(manifests.entry_points(rel, text))
    for rel in inv["other"]:
        _, text = walk.read(root, rel)
        findings.extend(scanners.scan_secret_text(rel, text, python=False))
    findings = score.sort_findings(scanners.dedupe(findings))
    langs = _languages(inv["other"])
    if langs:
        notes.append("v1 analyses Python only: %d file(s) in other languages (%s) got the secret scan only"
                     % (sum(langs.values()), ", ".join("%s %d" % kv for kv in langs.items())))
    for rel, why in inv["skipped"]:
        notes.append("skipped %s (%s)" % (rel, why))
    if inv["excluded"]:
        notes.append("%d path(s) excluded by the goal file" % inv["excluded"])
    hygiene = orphans_mod.analyse(trees, contract, entries)
    report = {
        "tool": "code-guardian", "version": __version__, "path": path,
        "goal_file": os.path.relpath(contract["path"], root).replace(os.sep, "/") if contract else None,
        "files": {"python": len(inv["python"]), "manifests": len(inv["manifests"]), "other": len(inv["other"]),
                  "skipped": len(inv["skipped"]), "ignored": inv["ignored"], "excluded": inv["excluded"],
                  "unparsed": len(inv["python"]) - len(trees)},
        "other_languages": langs,
        "threat": score.threat(findings),
        "findings": findings,
        "egress": [{"node": f["node"], "level": f["level"], "kind": f["evidence"][0][6:], "target": f["evidence"][1][8:]}
                   for f in findings if f["code"] == "net.egress"],
        "hygiene": hygiene,
        "notes": notes,
    }
    if explain:
        text, note = explain_mod.explain(report, env)
        if text:
            report["explanation"] = {"label": explain_mod.LABEL, "text": text}
        report["notes"].append(note)
    report["elapsed_ms"] = int((time.perf_counter() - started) * 1000)
    return report


def orphans(path, goal_file=None, infer=False):
    """Hygiene only. infer=True ignores the contract's entry points and keep list (it still honours exclude)."""
    root = _root(path)
    contract, notes = _contract(root, goal_file)
    inv = walk.walk(root, exclude=contract["exclude"] if contract else ())
    trees, entries = {}, []
    for rel in inv["python"]:
        try:
            trees[rel] = _parse(rel, walk.read(root, rel)[0])
        except PARSE_ERRORS:
            notes.append("%s does not parse; left out of the call graph" % rel)
    for rel in inv["manifests"]:
        if not rel.endswith(".py"):
            entries.extend(manifests.entry_points(rel, walk.read(root, rel)[1]))
    hygiene = orphans_mod.analyse(trees, None if infer else contract, entries)
    hygiene["notes"] = notes + hygiene["notes"]
    hygiene["files"] = {"python": len(inv["python"]), "parsed": len(trees)}
    return hygiene


def exit_code(findings, fail_on="FAIL"):
    rank = LEVELS.index(fail_on.upper())
    return 1 if any(LEVELS.index(f["level"]) >= rank for f in findings if f.get("level") in LEVELS) else 0


def _counts(findings):
    counts = {lv: 0 for lv in ("FAIL", "WARN", "INFO")}
    for f in findings:
        if f["level"] in counts:
            counts[f["level"]] += 1
    return ", ".join("%d %s" % (n, lv) for lv, n in counts.items())


def _hygiene_lines(h):
    c = h["counts"]
    lines = ["hygiene (%s entry points: %d): %d dead, %d test-only, %d uncertain"
             % (h["source"], len(h["entry_points"]), c["orphan.dead"], c["orphan.test_only"], c["orphan.uncertain"])]
    if h.get("goal"):
        lines.append("  goal: %s" % h["goal"])
    for f in h["findings"]:
        lines.append("  %-4s  %-16s  %s  %s" % (f["level"], f["code"], f["node"], f["summary"]))
    return lines


def render(report):
    t = report["threat"]
    fl = report["files"]
    name = os.path.basename(os.path.abspath(report["path"])) or report["path"]
    lines = ["code-guardian %s  scan of %s" % (report["version"], name),
             "files: %d Python, %d manifests, %d other (%d skipped, %d excluded by the goal file)"
             % (fl["python"], fl["manifests"], fl["other"], fl["skipped"], fl["excluded"]),
             "",
             "threat score %d/100 (raw %d)  grade %s" % (t["score"], t["raw"], t["grade"])]
    if t["top"]:
        lines.append("top contributors:")
        lines.extend("  %3d  %-13s %-4s  %s  %s" % (x["weight"], x["code"], x["level"], x["node"], x["summary"])
                     for x in t["top"])
    shown = [f for f in report["findings"] if f["code"] != "net.egress"]
    lines += ["", "findings (%s; egress listed below):" % _counts(report["findings"])]
    lines.extend("  %-4s  %-13s %s  %s" % (f["level"], f["code"], f["node"], f["summary"]) for f in shown)
    if not shown:
        lines.append("  none")
    lines += ["", "egress inventory (%d):" % len(report["egress"])]
    lines.extend("  %-4s  %s  %-4s  %s" % (e["level"], e["node"], e["kind"], e["target"]) for e in report["egress"])
    lines += [""] + _hygiene_lines(report["hygiene"])
    if report.get("explanation"):
        lines += ["", report["explanation"]["label"] + ":"] + ["  " + ln for ln in report["explanation"]["text"].splitlines()]
    notes = report["notes"] + report["hygiene"]["notes"]
    if notes:
        lines += ["", "notes:"] + ["  - " + n for n in notes]
    lines += ["", "static analysis: every finding is LIKELY; scanned in %.2f s" % (report["elapsed_ms"] / 1000.0)]
    return "\n".join(lines) + "\n"


def render_orphans(h):
    lines = _hygiene_lines(h)
    if h["entry_points"]:
        lines += ["entry points:"] + ["  " + e for e in h["entry_points"]]
    if h["notes"]:
        lines += ["notes:"] + ["  - " + n for n in h["notes"]]
    return "\n".join(lines) + "\n"


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if "--selftest" in argv:
        return selftest()
    sys.stderr.write("usage: python -m code_guardian.report --selftest\n")
    return 2


def selftest():
    tmp = tempfile.mkdtemp()

    def put(rel, text):
        full = os.path.join(tmp, *rel.split("/"))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as fh:
            fh.write(text)

    try:
        put("app/__init__.py", "")
        put("app/run.py", "import os\ndef main():\n    os.system('ls')\ndef unused():\n    pass\n"
                          "if __name__ == '__main__':\n    main()\n")
        put("app/broken.py", "def (:\n")
        put("web/x.js", "fetch('/');\n")
        first, second = scan(tmp), scan(tmp)
        for r in (first, second):
            r.pop("elapsed_ms")
        text = render(scan(tmp))
        checks = [
            ("deterministic", first == second),
            ("score", first["threat"]["raw"] == 10 and first["threat"]["grade"] == "B"),
            ("unparsed", first["files"]["unparsed"] == 1 and any(f["code"] == "parse.skipped" for f in first["findings"])),
            ("hygiene", [f["evidence"][0] for f in first["hygiene"]["findings"]] == ["name: app.run.unused"]),
            ("languages", first["other_languages"] == {".js": 1} and "secret scan only" in first["notes"][0]),
            ("render", "threat score 10/100 (raw 10)  grade B" in text and "hygiene (inferred" in text),
            ("exit_code", exit_code(first["findings"]) == 0 and exit_code(first["findings"], "WARN") == 1),
            ("orphans", orphans(tmp)["counts"]["orphan.dead"] == 1),
        ]
        try:
            scan(os.path.join(tmp, "missing"))
            checks.append(("usage_error", False))
        except UsageError:
            checks.append(("usage_error", True))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return summarize("report", checks)


if __name__ == "__main__":
    sys.exit(main())
