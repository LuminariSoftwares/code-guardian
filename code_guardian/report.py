"""Run a scan end to end and render it. Reads files; never executes, imports or installs them; no network unless
explain=True, and then only the URL in CODE_GUARDIAN_LLM_URL.

Public contract:
    scan(path, goal_file=None, explain=False, env=None, online=False, baseline=None, history=False,
         history_depth=500, exclude=()) -> report dict
                                       # raises UsageError (bad PATH or baseline) / goal.GoalError
                                       # exclude: globs left out at the person's request, after the goal file's;
                                       # non-empty adds excluded_by_request [{"glob", "files"}] and a note
                                       # secret.key INFO findings that say "looks like a test value" add the
                                       # top-level key test_values_graded: n (only when n > 0)
    orphans(path, goal_file=None, infer=False, exclude=()) -> hygiene dict (+ "files")
    render(report) -> text            render_orphans(hygiene) -> text       status_line(report) -> text
    coverage_of(inv, langs, not_run=()) -> coverage dict          coverage_line(coverage) -> 'coverage: ...'
                                       # JavaScript / TypeScript (walk's inv["javascript"], tokens and Safe + Works checks,
                                       # inv["generated"] only the secret, obfuscation and exec.dynamic checks) are
                                       # analysed; coverage.languages says at what depth
    exit_code(findings, fail_on, status=None, baseline=None) -> 0, 1 or 3 (an incomplete scan: PARTIAL or INVALID);
                                       # with a baseline block only findings marked new count
    gate_status(report) -> the status exit_code uses: a PARTIAL that is only about coverage gates as COMPLETE
    scored_findings(report) -> the findings the scores count (findings + hygiene orphan.dead)
    redact_report(report) -> a redacted copy (scanners.redact_report: every output path uses it)
    STATUSES, SCHEMA_VERSION, Outcomes,
    status_of(outcomes, inv, unparsed, unreadable, invalid, coverage=None) -> (status, reasons)
    COVERAGE_MIN_OTHER, COVERAGE_RATIO   # the mixed-repo rule (README: Scan status)
"""

import ast
import os
import re
import shutil
import sys
import tempfile
import warnings

from . import (__version__, baseline as baseline_mod, complete, explain as explain_mod, history as history_mod,
               leftovers, goal, manifests, orphans as orphans_mod, scanners, scanners_js, score,
               supply, walk, works, works_js)
from .finding import LEVELS, crash_finding, summarize
from .scanners import redact_report

SOURCE_EXT = frozenset({".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".go", ".rs", ".java", ".kt", ".rb", ".php",
                        ".sh", ".bash", ".ps1", ".bat", ".c", ".h", ".cc", ".cpp", ".hpp", ".cs", ".swift", ".lua",
                        ".pl", ".r", ".scala", ".dart", ".vue", ".svelte", ".astro"})
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
    """{extension: files} of the source files that only get the secret scan: JavaScript / TypeScript is analysed now."""
    counts = {}
    for rel in files:
        ext = os.path.splitext(rel)[1].lower()
        if ext in SOURCE_EXT and ext not in walk.JS_EXT:
            counts[ext] = counts.get(ext, 0) + 1
    return dict(sorted(counts.items()))


# Coverage. Python is analysed in full; JavaScript / TypeScript at token level (a lexer, not a parser: the Safe checks
# of scanners_js and the Works checks of works_js, and generated or minified files only the secret, obfuscation and
# exec.dynamic checks); other source files get the secret scan only. With neither Python nor JavaScript / TypeScript
# source, Works is not scored and Safe is partial. Other-language source is material (the scan is PARTIAL) when there
# are at least COVERAGE_MIN_OTHER such files and more than COVERAGE_RATIO times as many as Python and JavaScript /
# TypeScript files together: the analysed languages are under a third of the source. Calibrated so the nine repos in
# calibration.md stay COMPLETE (the most JS-heavy has 37 .js/.mjs files to 33 Python files).
COVERAGE_MIN_OTHER = 5
COVERAGE_RATIO = 2
JS_DEPTH = "tokens"
JS_GENERATED_CHECKS = ["secret.key", "obfuscation", "exec.dynamic"]
JS_WORKS_CODES = ("works.syntax", "works.import_unresolved", "works.relative_missing", "works.entry_missing",
                  "works.tests_missing")


def _js_checked(not_run=()):
    """The check codes that ran on the JavaScript / TypeScript files, in a fixed order."""
    codes = ["secret.key"] + [code for code, _fn in scanners_js.JS_SCANNERS] + list(JS_WORKS_CODES)
    return [code for code in codes if code not in not_run]


def _js_not_checked():
    """What the Python side checks and the JavaScript side does not (the C2 and C3 lists)."""
    ported = set(_js_checked())
    return [code for code, _fn in scanners.PY_SCANNERS if code not in ported] + list(works_js.NOT_CHECKED)


def coverage_of(inv, langs, not_run=()):
    """not_run: check codes that crashed on the JavaScript / TypeScript side; they are left out of languages.checks."""
    python, other = len(inv["python"]), sum(langs.values())
    js, generated = len(inv.get("javascript", ())), len(inv.get("generated", ()))
    material = other >= COVERAGE_MIN_OTHER and other > COVERAGE_RATIO * (python + js)
    if not (python or js):
        reason = "no Python or JavaScript source: Works not scored, Safe partial"
    elif material:
        reason = ("%s under a third of the source: %d file(s) in other languages got the secret scan only"
                  % ("Python is" if not js else "Python and JavaScript/TypeScript are", other))
    else:
        reason = None
    languages = {}
    if python:
        languages["python"] = {"files": python, "depth": "full"}
    if js or generated:
        languages["javascript"] = {"files": js, "generated": generated, "depth": JS_DEPTH,
                                   "checks": _js_checked(not_run), "generated_checks": list(JS_GENERATED_CHECKS),
                                   "not_checked": _js_not_checked()}
    return {"analysed": "python+javascript" if python and js else "javascript" if js else "python",
            "python": python, "other_source": langs, "other_source_files": other,
            "works_scored": bool(python or js), "safe_partial": not (python or js), "partial": reason is not None,
            "reason": reason, "languages": languages}


def coverage_line(cov):
    """'coverage: 40 Python analysed; 112 JavaScript/TypeScript analysed (token level); 9 .go secret-scan only'
    (each part only when there is something to say; the other languages most files first)."""
    parts = []
    if cov["python"]:
        parts.append("%d Python analysed" % cov["python"])
    js = ((cov.get("languages") or {}).get("javascript") or {}).get("files", 0)
    if js:
        parts.append("%d JavaScript/TypeScript analysed (token level)" % js)
    other = sorted(cov["other_source"].items(), key=lambda kv: (-kv[1], kv[0]))
    if other:
        parts.append("%s secret-scan only" % ", ".join("%d %s" % (n, ext) for ext, n in other))
    return "coverage: " + ("; ".join(parts) if parts else "0 Python analysed")


STATUSES = ("COMPLETE", "PARTIAL", "INVALID")
SCHEMA_VERSION = 3  # 1 was v0.2's shape; 2 adds keys (status, outcomes...); 3 adds files.javascript / .generated and
#                     coverage.languages (JavaScript / TypeScript analysis); a version never changes an existing key's meaning


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


def status_of(outcomes, inv, unparsed, unreadable, invalid, coverage=None):
    """(status, reasons). INVALID: nothing could be judged. PARTIAL: there is no Python or JavaScript / TypeScript source,
    or most source is in languages code-guardian does not analyse (coverage), a check crashed or was skipped, or a file that would have
    been analysed was not (did not parse, too large, unreadable). Binary files, symlinks and large non-source assets
    (only ever secret-scanned) do not make a scan PARTIAL; the notes still list them."""
    if invalid:
        return "INVALID", invalid
    reasons = [coverage["reason"]] if coverage and coverage["reason"] else []
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
    return {"python": [], "manifests": [], "other": [], "javascript": [], "generated": [], "skipped": [], "excluded": 0,
            "ignored": 0}


def _baseline(path):
    try:
        return baseline_mod.load(path)
    except (OSError, ValueError) as exc:
        raise UsageError("cannot read baseline %s: %s" % (path, exc)) from None


def _asked(root, goal_globs, exclude):
    """[(glob, n)]: what the walk left out for each requested glob, counted as the walk counts (a pruned folder once,
    a path matched by the goal file or an earlier glob not again). Walks the names only; no file is opened."""
    patterns, counts = walk.load_ignore(root), [0] * len(exclude)

    def left_out(rel, is_dir):
        if walk.ignored(rel, is_dir, patterns) or walk._excluded(rel, goal_globs):
            return True
        for i, glob in enumerate(exclude):
            if walk._excluded(rel, (glob,)):
                counts[i] += 1
                return True
        return False

    for dirpath, dirnames, filenames in os.walk(root):
        reldir = os.path.relpath(dirpath, root).replace(os.sep, "/")
        reldir = "" if reldir == "." else reldir + "/"
        dirnames[:] = [d for d in sorted(dirnames) if d not in walk.SKIP_DIRS
                       and not os.path.islink(os.path.join(dirpath, d)) and not left_out(reldir + d, True)]
        for name in filenames:
            if not os.path.islink(os.path.join(dirpath, name)):
                left_out(reldir + name, False)
    return list(zip(exclude, counts))


def _asked_note(asked):
    return "%d path(s) left out at your request: %s" % (sum(n for _, n in asked), ", ".join(g for g, _ in asked))


def scan(path, goal_file=None, explain=False, env=None, online=False, baseline=None, history=False,
         history_depth=history_mod.DEPTH, exclude=()):
    """baseline: a file written by `code-guardian baseline`; each finding is then marked new or known.
    history: also run the key-shape rules over the lines the last history_depth commits added (git, read-only).
    exclude: globs to leave out at the person's request, applied after the goal file's own."""
    root = _root(path)
    base = _baseline(baseline) if baseline else None
    contract, notes = _contract(root, goal_file)
    exclude = [exclude] if isinstance(exclude, str) else list(exclude)  # one glob given bare is one glob
    goal_globs = tuple(contract["exclude"]) if contract else ()
    out = Outcomes()
    findings, trees, entries, broken, texts, unreadable, invalid, sources = [], {}, [], {}, {}, [], [], {}
    try:
        os.listdir(root)
    except OSError as exc:
        invalid.append("PATH is unreadable (%s)" % type(exc).__name__)
    inv = _empty_inventory() if invalid else out.run(
        "walk", lambda: walk.walk(root, exclude=goal_globs + tuple(exclude)), None, findings)
    if inv is None:
        inv = _empty_inventory()
        invalid.append("the file walk crashed")
    asked = _asked(root, goal_globs, exclude) if exclude and inv["excluded"] else [(g, 0) for g in exclude]
    if not invalid and not (inv["python"] or inv["javascript"] or inv["generated"] or inv["manifests"]):
        invalid.append("no Python files, no JavaScript/TypeScript files and no manifests to judge")

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
        notes.append("no Python source or manifest found: %s have nothing to check"
                     % ("Complete and Supply" if inv["javascript"] or inv["generated"] else "Works and Complete"))
    js_crashed, js_works_ran = [], False
    if inv["javascript"] or inv["generated"]:
        out.ran("javascript")
        generated = set(inv["generated"])
        for rel in sorted(inv["javascript"] + inv["generated"]):
            text = sources.get(rel)  # the secret scan above read it; an unreadable file is not analysed
            if text is not None:
                findings.extend(out.run("javascript", lambda: scanners_js.scan_js(
                    scanners_js.JsFile(rel, text, _flavour(rel), generated=rel in generated), crashed=js_crashed),
                    [], findings, rel))
        for code, crash in js_crashed:
            out.crashed("javascript", "%s on %s" % (crash["evidence"][0].split(":", 1)[0], crash["node"]))
        found, has_tests = out.run("js_works", lambda: _js_works(project, inv["javascript"], notes), ([], False), findings)
        findings.extend(found)
        if has_tests:  # one works.tests_missing for the repo: the JavaScript side has tests, so works.py's is wrong
            findings = [f for f in findings if f["code"] != "works.tests_missing"]
        js_works_ran = out.rows.get("js_works", ("ran",))[0] == "ran"
    if history and not invalid:
        found, history_notes, skipped = out.run(
            "history", lambda: history_mod.scan(root, history_depth, current=sources), ([], [], None), findings)
        findings.extend(found)
        notes.extend(history_notes)
        if skipped:
            out.skipped("history", skipped)
    reached = set()
    hygiene = out.run("orphans", lambda: orphans_mod.analyse(trees, contract, entries, library=_is_library(project),
                                                             reached_out=reached), None, findings)
    if inv["python"] or inv["manifests"]:
        findings.extend(out.run("leftovers", lambda: leftovers.check(project, reached), [], findings))
    else:
        out.skipped("leftovers", "no Python files and no manifests")
    findings = score.sort_findings(scanners.dedupe(_test_code_to_info(
        _test_key_context(_one_secret_per_line(findings), trees, sources))))
    langs = _languages(inv["other"])
    coverage = coverage_of(inv, langs, [code for code, _crash in js_crashed]
                           + ([] if js_works_ran or not (inv["javascript"] or inv["generated"]) else list(JS_WORKS_CODES)))
    for rel, why in inv["skipped"]:
        notes.append("skipped %s (%s)" % (rel, why))
    for rel in unreadable:
        notes.append("skipped %s (unreadable)" % rel)
    by_goal = inv["excluded"] - sum(n for _, n in asked)
    if by_goal:
        notes.append("%d path(s) excluded by the goal file" % by_goal)
    if exclude:
        notes.append(_asked_note(asked))
    if hygiene is None:
        hygiene = {"source": "none (the orphan check crashed)", "goal": "", "entry_points": [], "keep": [],
                   "findings": [], "notes": [], "counts": {"orphan.dead": 0, "orphan.test_only": 0,
                                                           "orphan.uncertain": 0}}
        findings = score.sort_findings(findings)
    outcomes = out.as_list()
    status, reasons = status_of(outcomes, inv, sorted(broken), unreadable, invalid, coverage)
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
        "files": {"python": len(inv["python"]), "manifests": len(inv["manifests"]),
                  "other": len(inv["other"]) - len(inv["javascript"]) - len(inv["generated"]),
                  "skipped": len(inv["skipped"]), "ignored": inv["ignored"], "excluded": inv["excluded"],
                  "unparsed": len(inv["python"]) - len(trees), "javascript": len(inv["javascript"]),
                  "generated": len(inv["generated"])},
        "other_languages": langs,
        "coverage": coverage,
        "anchor": _anchor(inv),
        "findings": findings,
        "egress": [{"node": f["node"], "level": f["level"], "kind": f["evidence"][0][6:], "target": f["evidence"][1][8:]}
                   for f in findings if f["code"] == "net.egress"],
        "hygiene": hygiene,
        "notes": notes,
    }
    if base is not None:
        report["baseline"] = {"file": baseline, "version": base["version"], "new": new, "known": known}
    if exclude:
        report["excluded_by_request"] = [{"glob": g, "files": n} for g, n in asked]
    graded = sum(1 for f in findings if f["code"] == "secret.key" and f["level"] == "INFO"
                 and any(e.startswith(scanners.TEST_VALUE + ": ") for e in f["evidence"]))
    if graded:
        report["test_values_graded"] = graded
    _score(report)
    report = redact_report(report)  # before explain: the model sees what every output shows, nothing more
    if explain:
        text, note = explain_mod.explain(report, env)
        if text:
            report["explanation"] = {"label": explain_mod.LABEL, "text": text}
        report["notes"].append(note)
    return report


def _flavour(rel):
    return works_js.FLAVOURS[os.path.splitext(rel)[1].lower()]


def _js_works(project, javascript, notes):
    """([works_js findings], whether the JavaScript side has a test signal). The generated files are left out."""
    js_project = dict(project, **works_js.load(project["root"], project["files"], javascript=javascript))
    notes.extend(js_project["notes"])
    return works_js.check(js_project), works_js.has_test_signal(js_project)


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

TEST_VALUE_FIX = "keep test values out of the source too, or make them obviously fake"
TEST_VALUE_HINT = ("if this is a test value, make it say so (FAKE or TEST in the value, or one character repeated, "
                   "like 000000) and it is reported as information")
_NAME_WORDS = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+")
FAKE_NAME_WORDS = scanners.PLACEHOLDER_WORDS | {"selftest", "stub", "fixture"}


def _fake_named(name):
    """A name with a placeholder word in it: test_key, FAKE_TOKEN, TestClient, _selftest, sample_value."""
    for word in _NAME_WORDS.findall(name):
        word = word.lower()
        if word in FAKE_NAME_WORDS or word.endswith("s") and word[:-1] in FAKE_NAME_WORDS:
            return True
    return False


def _key_index(tree):
    """What _test_key_context asks of one file, found in one walk: the str constants that are the value of an
    assignment or a keyword argument (with the names they are given), the str constants inside any assert or compared
    in any comparison, and every function or class with its line span."""
    named, compared, scopes = [], [], []
    for node in ast.walk(tree):
        value, names = None, []
        if isinstance(node, ast.Assign):
            value, targets = node.value, node.targets
        elif isinstance(node, ast.AnnAssign):
            value, targets = node.value, [node.target]
        elif isinstance(node, ast.keyword) and node.arg:
            value, targets, names = node.value, (), [node.arg]
        else:
            targets = ()
        for t in targets:
            if isinstance(t, ast.Name):
                names.append(t.id)
            elif isinstance(t, ast.Attribute):
                names.append(t.attr)
        if isinstance(value, ast.Constant) and isinstance(value.value, str) and names:
            named.append((value, names))
        if isinstance(node, ast.Assert):
            compared.extend(n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str))
        elif isinstance(node, ast.Compare):
            compared.extend(n.value for n in [node.left] + node.comparators
                            if isinstance(n, ast.Constant) and isinstance(n.value, str))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            scopes.append((node.lineno, getattr(node, "end_lineno", None) or node.lineno, node.name))
    return named, compared, scopes


def _key_signals(index, value, lineno, rel):
    """The signals that hold for the key-shaped `value` on `lineno`, in the order U2, L1, L2, U1, as (word, text)
    pairs. U2: assigned to a fake-named variable or keyword. L1: in a test file. L2: the innermost function or class
    around the line has a placeholder word in its name. U1: the value sits inside a string compared in an assert or
    any comparison."""
    named, compared, scopes = index
    out = []
    for const, names in named:
        if value in const.value and const.lineno <= lineno <= (getattr(const, "end_lineno", None) or const.lineno):
            name = next((n for n in names if _fake_named(n)), None)
            if name:
                out.append(("U2", "assigned to %s" % name))
                break
    if not_product(rel) == "test code":
        out.append(("L1", "in a test file"))
    around = [s for s in scopes if s[0] <= lineno <= s[1]]
    if around:
        name = max(around, key=lambda s: (s[0], -s[1]))[2]
        if _fake_named(name):
            out.append(("L2", "inside %s()" % name))
    if any(value in text for text in compared):
        out.append(("U1", "compared in an assert"))
    return out


def _test_key_context(findings, trees, texts):
    """Read a key-shaped FAIL in a parsed Python file by how it is used (P88 C4). INFO only when the value is assigned
    to a fake-named variable (U2) and at least one more signal holds: in a test file (L1), inside a test or fake
    function (L2), compared in an assert (U1). Location and comparison alone never do: a real key pasted into a test
    still gets the FAIL, with the signals named and a hint on how to say it is a test value. `texts` maps every read
    file to its text (the scan passes its sources); a file that did not parse, or a value not found on its line, is
    left alone."""
    indexes = {}
    for f in findings:
        if f["code"] != "secret.key" or f["level"] != "FAIL" or scanners.KEY_SHAPE not in f["evidence"]:
            continue
        rel, _, line = f["node"].rpartition(":")
        if rel not in trees or rel not in texts or not line.isdigit():
            continue
        lineno = int(line)
        lines = texts[rel].splitlines()
        if not 0 < lineno <= len(lines):
            continue
        size = next((e[len("length: "):].split(" ", 1)[0] for e in f["evidence"] if e.startswith("length: ")), "")
        value = next((v for v in scanners.key_values(lines[lineno - 1]) if str(len(v)) == size), None)
        if value is None:
            continue
        if rel not in indexes:
            indexes[rel] = _key_index(trees[rel])
        signals = _key_signals(indexes[rel], value, lineno, rel)
        said = [text for _word, text in signals]
        if "U2" in [word for word, _text in signals] and len(signals) > 1:
            f["level"] = "INFO"
            f["summary"] = f["summary"].replace("in the source; value redacted",
                                                "in the source (%s; value redacted)" % scanners.TEST_VALUE)
            f["evidence"].append("%s: %s" % (scanners.TEST_VALUE, " and ".join(said)))
            f["try"] = [TEST_VALUE_FIX]
        elif signals:
            f["evidence"].append("test signals seen: " + ", ".join(said))
            f["try"].append(TEST_VALUE_HINT)
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
    cov = report.get("coverage")
    if cov and not cov["works_scored"]:
        dims["works"] = score.unscored()
    dims["safe"]["partial"] = bool(cov and cov["safe_partial"])
    report["scores"] = score.scores(report["findings"], dims, report.get("status"))
    report["dimensions"] = dims
    report["top"] = score.top(dims)
    report["weights"] = score.weight_table()
    report["weights_rule"] = score.WEIGHTS_RULE


def orphans(path, goal_file=None, infer=False, exclude=()):
    """Hygiene only. infer=True ignores the contract's entry points and keep list (it still honours exclude).
    exclude: globs to leave out at the person's request, as for scan."""
    root = _root(path)
    contract, notes = _contract(root, goal_file)
    exclude = [exclude] if isinstance(exclude, str) else list(exclude)  # one glob given bare is one glob
    goal_globs = tuple(contract["exclude"]) if contract else ()
    inv = walk.walk(root, exclude=goal_globs + tuple(exclude))
    if exclude:
        notes.append(_asked_note(_asked(root, goal_globs, exclude)))
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


def gate_status(report):
    """The status exit_code gates on. Coverage alone (no Python source, or mostly other languages) never fails the
    gate: a PARTIAL whose only reason is coverage gates as COMPLETE. The report's own status stays PARTIAL."""
    reason = (report.get("coverage") or {}).get("reason")
    if report.get("status") == "PARTIAL" and reason and report.get("status_reasons") == [reason]:
        return "COMPLETE"
    return report.get("status")


def exit_code(findings, fail_on="FAIL", status=None, baseline=None):
    """1 when a finding is at or above fail_on; else 3 when the scan is PARTIAL or INVALID (incomplete); else 0.
    With a baseline (the report's "baseline" block), only new findings count. Pass gate_status(report) as status."""
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
NOT_SCORED = "n/a (no Python or JavaScript)"
PARTIAL_LABEL = "partial: language-neutral checks only"


def overall_notes(report):
    """What the Overall line must say beside the grade: the dimensions left out, then the cap."""
    s, dims = report["scores"], report.get("dimensions") or {}
    out = ["%s not scored: no Python or JavaScript source" % LABELS[d] for d in score.DIMENSIONS
           if not dims.get(d, {}).get("scored", True)]
    if s["capped"]:
        out.append(("capped: %s" if s["grade"] != s["grade_uncapped"] else "%s") % s["cap_reason"])
    return out


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
    asked = sum(g["files"] for g in report["excluded_by_request"]) if "excluded_by_request" in report else None
    lines = ["code-guardian %s  scan of %s" % (report["version"], name),
             "files: %d Python, %d manifests, %d other (%d skipped, %d excluded by the goal file%s)"
             % (fl["python"], fl["manifests"], fl["other"], fl["skipped"], fl["excluded"] - (asked or 0),
                "" if asked is None else ", %d left out at your request" % asked),
             status_line(report)]
    if report.get("coverage"):
        lines.append(coverage_line(report["coverage"]))
    lines.append("")
    if report.get("status") == "INVALID":
        lines.append("  no scores and no grade: the scan is INVALID")
    for dim in score.DIMENSIONS if report.get("status") != "INVALID" else ():
        d = report["dimensions"][dim]
        if not d.get("scored", True):
            lines.append("  %-8s %s  %s" % (LABELS[dim], NOT_SCORED, QUESTIONS[dim]))
            continue
        lines.append(("  %-8s %3d/100  %-28s %s%s" % (LABELS[dim], s[dim], QUESTIONS[dim],
                                                      "-%d" % d["deducted"] if d["deducted"] else "",
                                                      "  " + PARTIAL_LABEL if d.get("partial") else "")).rstrip())
    if s["grade"] is not None:
        why = overall_notes(report)
        lines.append("  %-8s %3d/100  grade %s%s" % ("Overall", s["overall"], s["grade"],
                                                    "  (%s)" % "; ".join(why) if why else ""))
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
    if report.get("test_values_graded"):
        lines.append("  %d key-shaped value(s) look like test values and are reported as information, not as "
                     "failures; each finding says why" % report["test_values_graded"])
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
    tmp, js_tmp = tempfile.mkdtemp(), tempfile.mkdtemp()

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
        put("web/x.go", "package main\n")
        with open(os.path.join(js_tmp, "x.js"), "w", encoding="utf-8") as fh:
            fh.write("fetch('/');\n")
        put("web2/package.json", '{"name": "w"}\n')
        first, second = scan(tmp), scan(tmp)
        text = render(scan(tmp))
        checks = [
            ("deterministic", first == second),
            ("score", first["scores"]["safe"] == 90 and first["scores"]["works"] == 67 and first["scores"]["grade"] == "B"),
            ("unparsed", first["files"]["unparsed"] == 1 and any(f["code"] == "works.syntax" for f in first["findings"])),
            ("hygiene", [f["evidence"][0] for f in first["hygiene"]["findings"]] == ["name: app.run.unused"]),
            ("languages", first["other_languages"] == {".go": 1} and first["coverage"]["python"] == 4
             and not first["coverage"]["partial"] and "coverage: 4 Python analysed; 1 .go secret-scan only" in text
             and first["coverage"]["languages"] == {"python": {"files": 4, "depth": "full"}}),
            ("coverage_line", coverage_line({"python": 40, "other_source": {".go": 9, ".rs": 112},
                                             "languages": {"javascript": {"files": 112}}})
             == "coverage: 40 Python analysed; 112 JavaScript/TypeScript analysed (token level); 112 .rs, 9 .go secret-scan only"
             and coverage_line({"python": 0, "other_source": {}}) == "coverage: 0 Python analysed"),
            ("javascript", scan(js_tmp)["coverage"]["analysed"] == "javascript" and scan(js_tmp)["status"] != "INVALID"
             and [o["check"] for o in scan(js_tmp)["outcomes"] if o["check"] in ("javascript", "js_works")]
             == ["javascript", "js_works"]),
            ("no_python", scan(os.path.join(tmp, "web2"))["scores"]["works"] is None),
            ("gate_status", gate_status({"status": "PARTIAL", "status_reasons": ["r"], "coverage": {"reason": "r"}})
             == "COMPLETE" and gate_status({"status": "PARTIAL", "status_reasons": ["r", "x"],
                                            "coverage": {"reason": "r"}}) == "PARTIAL"),
            ("render", "Safe      90/100" in text and "Works     67/100" in text and "hygiene (inferred" in text),
            ("exit_code", exit_code(first["findings"]) == 1 and exit_code([f for f in first["findings"]
                                                                           if f["level"] != "FAIL"]) == 0),
            ("orphans", orphans(tmp)["counts"]["orphan.dead"] == 1),
            ("status_partial", first["status"] == "PARTIAL" and first["status_reasons"] == [
                "1 Python file(s) did not parse: app/broken.py"] and "status: PARTIAL (1 Python file(s)" in text),
            ("exit_3", exit_code([], "FAIL", "PARTIAL") == 3 and exit_code([], "FAIL", "INVALID") == 3
             and exit_code([], "FAIL", "COMPLETE") == 0),
            ("invalid", scan(os.path.join(tmp, "web"))["status"] == "INVALID"
             and scan(os.path.join(tmp, "web"))["status_reasons"]
             == ["no Python files, no JavaScript/TypeScript files and no manifests to judge"]),
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
        shutil.rmtree(js_tmp, ignore_errors=True)
    return summarize("report", checks)


if __name__ == "__main__":
    sys.exit(main())
