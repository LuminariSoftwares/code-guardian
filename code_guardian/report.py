"""Run a scan end to end and render it. Reads files; never executes, imports or installs them; no network unless
explain=True, and then only the URL in CODE_GUARDIAN_LLM_URL.

Public contract:
    scan(path, goal_file=None, explain=False, env=None, online=False, baseline=None, history=False,
         history_depth=500) -> report dict
                                       # raises UsageError (bad PATH or baseline) / goal.GoalError
    orphans(path, goal_file=None, infer=False) -> hygiene dict (+ "files")
    render(report) -> text            render_orphans(hygiene) -> text       status_line(report) -> text
    exit_code(findings, fail_on, status=None, baseline=None) -> 0, 1 or 3 (an incomplete scan: PARTIAL or INVALID);
                                       # with a baseline block only findings marked new count
    scored_findings(report) -> the findings the scores count (findings + hygiene orphan.dead)
    redact_report(report) -> a redacted copy (scanners.redact_report: every output path uses it)
    STATUSES, SCHEMA_VERSION, Outcomes, status_of(outcomes, inv, unparsed, unreadable, invalid) -> (status, reasons)
"""

import ast
import os
import shutil
import sys
import tempfile
import warnings

from . import (__version__, baseline as baseline_mod, complete, explain as explain_mod, history as history_mod, goal, manifests, orphans as orphans_mod, scanners, score,
               supply, walk, works)
from .finding import LEVELS, crash_finding, make_finding, summarize
from .scanners import redact_report

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


def _languages(files):
    counts = {}
    for rel in files:
        ext = os.path.splitext(rel)[1].lower()
        if ext in SOURCE_EXT:
            counts[ext] = counts.get(ext, 0) + 1
    return dict(sorted(counts.items()))


STATUSES = ("COMPLETE", "PARTIAL", "INVALID")
SCHEMA_VERSION = 2  # 1 was v0.2's shape; 2 adds keys (status, outcomes...) and never changes an existing one


class Outcomes:
    """What each scanner, check and the file walk did: ran, skipped (with a reason) or crashed (with the error)."""

    def __init__(self):
        self.rows = {}

    def ran(self, check):
        self.rows.setdefault(check, ("ran", None))

    def skipped(self, check, reason):
        if self.rows.get(check, ("ran",))[0] == "ran":
            self.rows[check] = ("skipped", reason)

    def crashed(self, check, reason):
        if self.rows.get(check, ("ran",))[0] != "crashed":
            self.rows[check] = ("crashed", reason)

    def run(self, check, fn, default, findings, node="."):
        """fn() guarded: a raise becomes a check.crashed finding and a crashed outcome, and default is returned."""
        try:
            got = fn()
        except Exception as exc:  # noqa: BLE001 - a broken check must not abort the scan
            crash = crash_finding(check, exc, node)
            findings.append(crash)
            self.crashed(check, crash["evidence"][0])
            return default
        self.ran(check)
        return got

    def as_list(self):
        return [{"check": c, "outcome": o, "reason": r} for c, (o, r) in self.rows.items()]


def _listing(rels, limit=5):
    shown = ", ".join(rels[:limit])
    return shown + (" and %d more" % (len(rels) - limit) if len(rels) > limit else "")


def status_of(outcomes, inv, unparsed, unreadable, invalid):
    """(status, reasons). INVALID: nothing could be judged. PARTIAL: a check crashed or was skipped, or a file that
    would have been analysed was not (did not parse, too large, unreadable). Binary files, symlinks and large
    non-source assets (only ever secret-scanned) do not make a scan PARTIAL; the notes still list them."""
    if invalid:
        return "INVALID", invalid
    reasons = []
    for row in outcomes:
        if row["outcome"] != "ran":
            what = row["reason"].split(":", 1)[0].split(" on ", 1)[0] if row["outcome"] == "crashed" else row["reason"]
            reasons.append("check %s %s (%s)" % (row["check"], row["outcome"], what))
    if unparsed:
        reasons.append("%d Python file(s) did not parse: %s" % (len(unparsed), _listing(unparsed)))
    large = [r for r, why in inv["skipped"] if why.startswith("larger than") and (r.endswith(".py") or walk.is_manifest(r))]
    if large:
        reasons.append("%d file(s) too large to analyse: %s" % (len(large), _listing(large)))
    unreadable = sorted(set(unreadable) | {r for r, why in inv["skipped"] if why == "unreadable"})
    if unreadable:
        reasons.append("%d file(s) could not be read: %s" % (len(unreadable), _listing(unreadable)))
    return ("PARTIAL" if reasons else "COMPLETE"), reasons


def _empty_inventory():
    return {"python": [], "manifests": [], "other": [], "skipped": [], "excluded": 0, "ignored": 0}


def _baseline(path):
    try:
        return baseline_mod.load(path)
    except (OSError, ValueError) as exc:
        raise UsageError("cannot read baseline %s: %s" % (path, exc)) from None


def scan(path, goal_file=None, explain=False, env=None, online=False, baseline=None, history=False,
         history_depth=history_mod.DEPTH):
    """baseline: a file written by `code-guardian baseline`; each finding is then marked new or known.
    history: also run the key-shape rules over the lines the last history_depth commits added (git, read-only)."""
    root = _root(path)
    base = _baseline(baseline) if baseline else None
    contract, notes = _contract(root, goal_file)
    out = Outcomes()
    findings, trees, entries, broken, texts, unreadable, invalid, sources = [], {}, [], {}, {}, [], [], {}
    try:
        os.listdir(root)
    except OSError as exc:
        invalid.append("PATH is unreadable (%s)" % type(exc).__name__)
    inv = _empty_inventory() if invalid else out.run(
        "walk", lambda: walk.walk(root, exclude=contract["exclude"] if contract else ()), None, findings)
    if inv is None:
        inv = _empty_inventory()
        invalid.append("the file walk crashed")
    if not invalid and not inv["python"] and not inv["manifests"]:
        invalid.append("no Python files and no manifests to judge")

    def read(rel):
        try:
            got = walk.read(root, rel)
        except OSError:
            unreadable.append(rel)
            return None
        sources[rel] = got[1]
        return got

    crashed = []
    for rel in inv["python"]:
        got = read(rel)
        if got is None:
            continue
        raw, text = got
        findings.extend(out.run("secrets", lambda: scanners.scan_secret_text(rel, text, python=True), [], findings, rel))
        try:
            pf = scanners.PyFile(rel, raw, text)
        except PARSE_ERRORS as exc:
            broken[rel] = exc
            continue
        trees[rel] = pf.tree
        findings.extend(scanners.scan_python(pf, crashed=crashed))
        if rel.rsplit("/", 1)[-1] == "setup.py":
            findings.extend(out.run("manifests", lambda: manifests.scan_manifest(rel, text, pf), [], findings, rel))
    for code, fn in scanners.PY_SCANNERS:
        out.ran(code)
    for code, crash in crashed:
        out.crashed(code, "%s on %s" % (crash["evidence"][0].split(":", 1)[0], crash["node"]))
    for rel in inv["manifests"]:
        if rel.endswith(".py"):
            continue
        got = read(rel)
        if got is None:
            continue
        text = texts[rel] = got[1]
        findings.extend(out.run("secrets", lambda: scanners.scan_secret_text(rel, text, python=False), [], findings, rel))
        findings.extend(out.run("manifests", lambda: manifests.scan_manifest(rel, text), [], findings, rel))
        entries.extend(out.run("manifests", lambda: manifests.entry_points(rel, text), [], findings, rel))
    for rel in inv["other"]:
        got = read(rel)
        if got is not None:
            findings.extend(out.run("secrets", lambda: scanners.scan_secret_text(rel, got[1], python=False), [],
                                    findings, rel))
    for rel in inv["manifests"]:
        if rel.endswith(".py"):
            got = read(rel)
            if got is not None:
                texts[rel] = got[1]
    for check in ("secrets", "manifests"):
        out.ran(check)
    project = {"root": root, "python": inv["python"], "trees": trees, "broken": broken, "texts": texts,
               "files": sorted(inv["python"] + inv["manifests"] + inv["other"] + [r for r, _ in inv["skipped"]]),
               "read": lambda rel: walk.read(root, rel)[1]}
    if inv["python"] or inv["manifests"]:
        findings.extend(out.run("works", lambda: works.check(project), [], findings))
        findings.extend(out.run("complete", lambda: complete.check(project), [], findings))
        found, supply_notes = out.run("supply", lambda: supply.check(project, online=online, env=env), ([], []),
                                      findings)
        findings.extend(found)
        notes.extend(supply_notes)
    else:
        for check in ("works", "complete", "supply"):
            out.skipped(check, "no Python files and no manifests")
        notes.append("no Python source or manifest found: Works and Complete have nothing to check")
    if history and not invalid:
        found, history_notes, skipped = out.run(
            "history", lambda: history_mod.scan(root, history_depth, current=sources), ([], [], None), findings)
        findings.extend(found)
        notes.extend(history_notes)
        if skipped:
            out.skipped("history", skipped)
    findings = score.sort_findings(scanners.dedupe(_test_code_to_info(_one_secret_per_line(findings))))
    langs = _languages(inv["other"])
    if langs:
        notes.append("code-guardian analyses Python only: %d file(s) in other languages (%s) got the secret scan only"
                     % (sum(langs.values()), ", ".join("%s %d" % kv for kv in langs.items())))
    for rel, why in inv["skipped"]:
        notes.append("skipped %s (%s)" % (rel, why))
    for rel in unreadable:
        notes.append("skipped %s (unreadable)" % rel)
    if inv["excluded"]:
        notes.append("%d path(s) excluded by the goal file" % inv["excluded"])
    hygiene = out.run("orphans", lambda: orphans_mod.analyse(trees, contract, entries, library=_is_library(project)),
                      None, findings)
    if hygiene is None:
        hygiene = {"source": "none (the orphan check crashed)", "goal": "", "entry_points": [], "keep": [],
                   "findings": [], "notes": [], "counts": {"orphan.dead": 0, "orphan.test_only": 0,
                                                           "orphan.uncertain": 0}}
        findings = score.sort_findings(findings)
    outcomes = out.as_list()
    status, reasons = status_of(outcomes, inv, sorted(broken), unreadable, invalid)
    split = {rel: text.splitlines() for rel, text in sources.items()}
    every = findings + hygiene["findings"]
    baseline_mod.stamp(every, lambda rel, n: split[rel][n - 1] if rel in split and 0 < n <= len(split[rel]) else "")
    if base is not None:
        new, known = baseline_mod.mark(every, base["fingerprints"])
        if base["version"] != __version__:
            notes.append("baseline written by code-guardian %s, this is %s" % (base["version"] or "?", __version__))
    report = {
        "tool": "code-guardian", "version": __version__, "schema_version": SCHEMA_VERSION, "path": path,
        "goal_file": os.path.relpath(contract["path"], root).replace(os.sep, "/") if contract else None,
        "status": status, "status_reasons": reasons, "outcomes": outcomes,
        "files": {"python": len(inv["python"]), "manifests": len(inv["manifests"]), "other": len(inv["other"]),
                  "skipped": len(inv["skipped"]), "ignored": inv["ignored"], "excluded": inv["excluded"],
                  "unparsed": len(inv["python"]) - len(trees)},
        "other_languages": langs,
        "anchor": _anchor(inv),
        "findings": findings,
        "egress": [{"node": f["node"], "level": f["level"], "kind": f["evidence"][0][6:], "target": f["evidence"][1][8:]}
                   for f in findings if f["code"] == "net.egress"],
        "hygiene": hygiene,
        "notes": notes,
    }
    if base is not None:
        report["baseline"] = {"file": baseline, "version": base["version"], "new": new, "known": known}
    _score(report)
    report = redact_report(report)  # before explain: the model sees what every output shows, nothing more
    if explain:
        text, note = explain_mod.explain(report, env)
        if text:
            report["explanation"] = {"label": explain_mod.LABEL, "text": text}
        report["notes"].append(note)
    return report


def _is_library(project):
    """Packaging metadata at the root and no application marker (the same markers as the lockfile rule)."""
    texts = project["texts"]
    meta = "setup.py" in texts or "setup.cfg" in texts or ("pyproject.toml" in texts
                                                          and "[project]" in texts["pyproject.toml"])
    return meta and not complete.app_markers(project)


TEST_DATA_DIRS = frozenset({"fixtures", "testdata", "test_data"})
DOC_DIRS = frozenset({"docs", "doc"})
DOC_EXTS = (".md", ".markdown", ".rst", ".txt", ".adoc")


def not_product(node):
    """'test code' or 'documentation' when the finding's file is a test, test data or a documentation file."""
    rel = str(node).rpartition(":")[0] or str(node)
    parts = rel.split("/")
    if orphans_mod.is_test(rel) or any(p in TEST_DATA_DIRS for p in parts[:-1]):
        return "test code"
    if any(p in DOC_DIRS for p in parts[:-1]) or parts[-1].lower().endswith(DOC_EXTS) and parts[-1] != "requirements.txt":
        return "documentation"
    return None


def _one_secret_per_line(findings):
    """One secret.key per line: the key-shape scan and the name scan can both match `SLACK_TOKEN = "xoxb-..."`, and
    one leaked value is one finding. The highest level wins; on a tie the first (the shape, scanned first)."""
    rank = {"FAIL": 0, "WARN": 1, "INFO": 2}
    best = {}
    for i, f in enumerate(findings):
        if f["code"] == "secret.key":
            key = f["node"]
            if key not in best or rank[f["level"]] < rank[findings[best[key]]["level"]]:
                best[key] = i
    keep = set(best.values())
    return [f for i, f in enumerate(findings) if f["code"] != "secret.key" or i in keep]


def _test_code_to_info(findings):
    """Safe findings in test code or documentation are reported at INFO: users run the product, not its tests or its
    doc samples, and tests exercise unsafe APIs on purpose. Two exceptions stay as they are: API-key shapes (a
    real key is leaked wherever it sits) and exec of decoded data (a payload in conftest.py runs on every pytest)."""
    for f in findings:
        where = not_product(f["node"]) if f["level"] in ("WARN", "FAIL") else None
        if (where is None or score.dimension_of(f["code"]) != "safe"
                or (f["code"] == "obfuscation" and f["level"] == "FAIL")
                or (f["code"] == "secret.key" and scanners.KEY_SHAPE in f["evidence"])):
            continue
        f["evidence"].append("in %s: reported at INFO (was %s)" % (where, f["level"]))
        f["level"] = "INFO"
    return findings


ANCHORS = ("pyproject.toml", "setup.py", "setup.cfg", "requirements.txt", "README.md", "README.rst", "README.txt",
           "README")


def _anchor(inv):
    """The file repo-level findings are attached to in SARIF (code scanning needs a file for every result)."""
    root_files = {r for r in inv["python"] + inv["manifests"] + inv["other"] if "/" not in r}
    for name in ANCHORS:
        if name in root_files:
            return name
    every = sorted(inv["python"] + inv["manifests"] + inv["other"])
    return every[0] if every else "."


def scored_findings(report):
    """The findings the scores count: the report's findings plus the hygiene section's orphan.dead (Works)."""
    return list(report["findings"]) + [f for f in (report.get("hygiene") or {}).get("findings") or []
                                       if f["code"] == "orphan.dead"]


def _score(report):
    """scores, per-dimension deductions, the top five and the weight table, from report["findings"] plus the
    hygiene section's orphan.dead (folded into Works at a low weight)."""
    dims = {name: score.dimension(scored_findings(report), name) for name in score.DIMENSIONS}
    report["scores"] = score.scores(report["findings"], dims, report.get("status"))
    report["dimensions"] = dims
    report["top"] = score.top(dims)
    report["weights"] = score.weight_table()
    report["weights_rule"] = score.WEIGHTS_RULE


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
    texts = {rel: walk.read(root, rel)[1] for rel in inv["manifests"]}
    for rel, text in texts.items():
        if not rel.endswith(".py"):
            entries.extend(manifests.entry_points(rel, text))
    project = {"files": sorted(inv["python"] + inv["manifests"] + inv["other"]), "trees": trees, "texts": texts}
    hygiene = orphans_mod.analyse(trees, None if infer else contract, entries, library=_is_library(project))
    hygiene["notes"] = notes + hygiene["notes"]
    hygiene["files"] = {"python": len(inv["python"]), "parsed": len(trees)}
    return hygiene


def exit_code(findings, fail_on="FAIL", status=None, baseline=None):
    """1 when a finding is at or above fail_on; else 3 when the scan is PARTIAL or INVALID (incomplete); else 0.
    With a baseline (the report's "baseline" block), only new findings count."""
    rank = LEVELS.index(fail_on.upper())
    if baseline:
        findings = [f for f in findings if f.get("new", True)]
    if any(LEVELS.index(f["level"]) >= rank for f in findings if f.get("level") in LEVELS):
        return 1
    return 3 if status in ("PARTIAL", "INVALID") else 0


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


LABELS = {"safe": "Safe", "works": "Works", "complete": "Complete"}
QUESTIONS = {"safe": "is it safe to run?", "works": "will it work?", "complete": "does it have what it needs?"}


def _weight_lines(report):
    lines = ["weights used (%s):" % report["weights_rule"]]
    for name in score.DIMENSIONS:
        table = report["weights"][name]
        row = "  %-9s" % LABELS[name]
        for i, entry in enumerate("%s %d" % kv for kv in table.items()):
            piece = entry if i == 0 else " · " + entry
            if len(row) + len(piece) > 110:
                lines.append(row + " ·")
                row, piece = " " * 11, entry
            row += piece
        if table:
            lines.append(row)
        else:
            lines.append("  %-8s (no checks yet)" % LABELS[name])
    return lines


def baseline_counts(report):
    """'; baseline: N new, M known' when the scan ran against a baseline, else ''."""
    b = report.get("baseline")
    return "; baseline: %d new, %d known" % (b["new"], b["known"]) if b else ""


def status_line(report):
    """'status: COMPLETE', or 'status: PARTIAL (reason; reason)'. Can I trust this scan?"""
    reasons = report.get("status_reasons") or []
    return "status: %s%s" % (report.get("status", "COMPLETE"), " (%s)" % "; ".join(reasons) if reasons else "")


def _where(row, n=3):
    shown = row.get("locations") or [row["first"]]
    rest = len(shown) - n + row.get("more", 0)
    return "at " + ", ".join(shown[:n]) + (" (+%d more)" % rest if rest > 0 else "")


def render(report):
    report = redact_report(report)
    s = report["scores"]
    fl = report["files"]
    name = os.path.basename(os.path.abspath(report["path"])) or report["path"]
    lines = ["code-guardian %s  scan of %s" % (report["version"], name),
             "files: %d Python, %d manifests, %d other (%d skipped, %d excluded by the goal file)"
             % (fl["python"], fl["manifests"], fl["other"], fl["skipped"], fl["excluded"]),
             status_line(report), ""]
    if report.get("status") == "INVALID":
        lines.append("  no scores and no grade: the scan is INVALID")
    for dim in score.DIMENSIONS if report.get("status") != "INVALID" else ():
        d = report["dimensions"][dim]
        lines.append(("  %-8s %3d/100  %-28s %s" % (LABELS[dim], s[dim], QUESTIONS[dim],
                                                    "-%d" % d["deducted"] if d["deducted"] else "")).rstrip())
    if s["grade"] is not None:
        lines.append("  %-8s %3d/100  grade %s%s" % ("Overall", s["overall"], s["grade"],
                                                    "  (capped: %s)" % s["cap_reason"] if s["capped"] and s["grade"] != s["grade_uncapped"]
                                                    else "  (%s)" % s["cap_reason"] if s["capped"] else ""))
    if report["top"]:
        lines += ["", "biggest deductions:"]
        lines.extend("  -%-3d %-8s %-24s x%-3d %s" % (t["deduction"], LABELS[t["dimension"]],
                                                     t["code"] + " " + t["level"], t["count"], _where(t))
                     for t in report["top"])
    shown = [f for f in report["findings"] if f["code"] != "net.egress"]
    lines += ["", "findings (%s%s; egress listed below):" % (_counts(report["findings"]), baseline_counts(report))]
    for dim in score.DIMENSIONS:
        group = [f for f in shown if score.dimension_of(f["code"]) == dim]
        if group:
            lines.append("  %s:" % LABELS[dim])
            lines.extend("    %-4s  %-13s %s  %s%s" % (f["level"], f["code"], f["node"], f["summary"],
                                                     "  [new]" if f.get("new") else "") for f in group)
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
    lines += [""] + _weight_lines(report)
    lines += ["", "static analysis: every finding is LIKELY; the scores come from fixed weights, never from a model"]
    return "\n".join(lines) + "\n"


def render_orphans(h):
    h = redact_report(h)
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
        put("tests/test_run.py", "from app import run\ndef test_main():\n    assert run.main\n")
        put("web/x.js", "fetch('/');\n")
        first, second = scan(tmp), scan(tmp)
        text = render(scan(tmp))
        checks = [
            ("deterministic", first == second),
            ("score", first["scores"]["safe"] == 90 and first["scores"]["works"] == 67 and first["scores"]["grade"] == "B"),
            ("unparsed", first["files"]["unparsed"] == 1 and any(f["code"] == "works.syntax" for f in first["findings"])),
            ("hygiene", [f["evidence"][0] for f in first["hygiene"]["findings"]] == ["name: app.run.unused"]),
            ("languages", first["other_languages"] == {".js": 1} and "secret scan only" in first["notes"][0]),
            ("render", "Safe      90/100" in text and "Works     67/100" in text and "hygiene (inferred" in text),
            ("exit_code", exit_code(first["findings"]) == 1 and exit_code([f for f in first["findings"]
                                                                           if f["level"] != "FAIL"]) == 0),
            ("orphans", orphans(tmp)["counts"]["orphan.dead"] == 1),
            ("status_partial", first["status"] == "PARTIAL" and first["status_reasons"] == [
                "1 Python file(s) did not parse: app/broken.py"] and "status: PARTIAL (1 Python file(s)" in text),
            ("exit_3", exit_code([], "FAIL", "PARTIAL") == 3 and exit_code([], "FAIL", "INVALID") == 3
             and exit_code([], "FAIL", "COMPLETE") == 0),
            ("invalid", scan(os.path.join(tmp, "web"))["status"] == "INVALID"),
            ("fingerprints", all(len(f["fingerprint"]) == 64 for f in first["findings"] + first["hygiene"]["findings"])),
            ("baseline_gate", exit_code([dict(f, new=False) for f in first["findings"]], "INFO", None, {"new": 0}) == 0),
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
