"""Plain language over a scan report: the same numbers, in sentences a person who does not write code can read.

Every function here is a pure read of the report dict `report.scan()` (and `scan --json`) produces. Nothing in this
module scans, scores, re-ranks or edits anything: it never writes to the report and never computes a number of its
own. When a sentence carries a number, that number was already in the report.

What it will not say. A static scan sees patterns in files it could read. It cannot run the code, so it cannot
promise anything about what the code does. Every sentence below is therefore written as what the check *saw*, and
VERDICT_PHRASES lists the words that would turn that into a promise; no sentence this module produces contains one
of them, and the acceptance test greps for them over every fixture.

Public contract:
    LABELS, COULD_NOT_CHECK, VERDICT_PHRASES, LANGUAGES, WHY
    harm(report) -> {"level", "partial", "why", "counts": {"FAIL", "WARN", "INFO"}}
    score_sentence(dimension, report) -> str        # dimension: "safe" | "works" | "complete" | "overall"
    checked_lines(report) -> [{"label", "files", "depth", "text"}]
    finding_card(finding, report=None) -> {"where", "what", "why", "how", "level", "confidence", "code",
                                           "fingerprint"}
    fix_first(report, top=10) -> [{"rank", "title", "level", "count", "gain", "grade_after", "first_location",
                                   "how"}]
    fix_first_notes(report, top=10) -> [str]        # verify.plan(...)["notes"], unchanged
    fix_first_lead(report) -> str | None            # one plain sentence shown above those notes
    diff_sentence(d) -> str                         # d: verify.diff(...); "1 fixed, 0 new, grade D \u2192 B"
    file_rows(report, inventory) -> [{"rel", "kind", "why_not_read", "why_partly", "findings", "risk"}]
    file_counts(rows) -> {"all", "with_findings", "no_known_risks", "partly_checked", "not_read"}
    backup_offer_line(offered, total) -> str        # P88 C5: the banner sentence; offered = backup_offer["offered"]
    held_line(held) -> [str]                        # one muted line per backup folder that was not offered
    named_line(group) -> str | None                 # the caution under an offered folder that files name in a string
    left_out_line(groups) -> str                    # groups = report["excluded_by_request"]
    test_values_line(n) -> str                      # the summary line for report["test_values_graded"]

CLI:
    python -m code_guardian.plain --selftest        # counted checks; rc 0 only if all pass
"""

import re
import sys

from . import catalogue, score, verify
from .finding import summarize

# ---------------------------------------------------------------------------------------------------------------
# Vocabulary

HIGH = "High"
MEDIUM = "Medium"
LOW = "Low"
NONE_FOUND = "No known risks found"
COULD_NOT_CHECK = "Could not check"
LABELS = (HIGH, MEDIUM, LOW, NONE_FOUND, COULD_NOT_CHECK)
PARTLY_CHECKED = "Partly checked"  # file labels (file_rows); the first four of LABELS are also file labels
NOT_READ = "Not read"
FILE_RISKS = (HIGH, MEDIUM, LOW, NONE_FOUND, PARTLY_CHECKED, NOT_READ)

# Words that would promise more than a static scan can know. Single words match as whole words, phrases as written;
# "Safe" as the name of the score dimension is not one of them.
VERDICT_PHRASES = re.compile(
    r"is safe|safe to run|\bsecure\b|\bclean\b|no risks|risk-free|\bharmless\b|\bguaranteed\b", re.IGNORECASE)

LEVEL_ORDER = ("FAIL", "WARN", "INFO")
LEVEL_LABEL = {"FAIL": HIGH, "WARN": MEDIUM, "INFO": LOW}
DIMENSION_LABEL = {"safe": "Safe", "works": "Works", "complete": "Complete", "overall": "Overall"}

# Extension -> the name a reader would use. Mirrors report.SOURCE_EXT (the extensions a scan can report under
# coverage.other_source); an extension missing here is shown as the extension itself. tests/test_plain.py pins the
# two tables together so a new extension over there cannot pass unnamed.
LANGUAGES = {
    ".js": "JavaScript",
    ".mjs": "JavaScript (ES module)",
    ".cjs": "JavaScript (CommonJS)",
    ".jsx": "JavaScript (JSX)",
    ".ts": "TypeScript",
    ".tsx": "TypeScript (TSX)",
    ".go": "Go",
    ".rs": "Rust",
    ".java": "Java",
    ".kt": "Kotlin",
    ".rb": "Ruby",
    ".php": "PHP",
    ".sh": "Shell",
    ".bash": "Shell (bash)",
    ".ps1": "PowerShell",
    ".bat": "Windows batch",
    ".c": "C",
    ".h": "C/C++ header",
    ".cc": "C++",
    ".cpp": "C++",
    ".hpp": "C++ header",
    ".cs": "C#",
    ".swift": "Swift",
    ".lua": "Lua",
    ".pl": "Perl",
    ".r": "R",
    ".scala": "Scala",
    ".dart": "Dart",
    ".vue": "Vue",
    ".svelte": "Svelte",
    ".astro": "Astro",
}

# One sentence per catalogue code, for a reader who does not write code: what the check saw, and why that can
# matter to them. Each says only what the check saw. Where the check can only see a shape or a name, the sentence
# says so ("shaped like", "whose name says") and what follows is written with can / may / if, because the scan
# cannot run the code and cannot know. tests/test_plain.py pins this table to the catalogue.
WHY = {
    # Safe
    "secret.key":
        "A string shaped like an API key, a password or a private key is written into a file here; if it is a real "
        "one, anyone who can read this project can use it, and taking it out later may not be enough, because "
        "older copies can still hold it.",
    "secret.history":
        "An earlier change added a string shaped like a key to this file and a later change took it out again; "
        "anyone holding a copy of the project's history can still read it, and it may still work.",
    "exec.dynamic":
        "The code runs a piece of text, or loads a module, that is chosen while the program runs rather than written "
        "out in the file, so reading the file does not show everything it can end up doing.",
    "exec.shell":
        "The code hands a command to the system's command line; if any part of that command can come from outside, "
        "whoever controls that input may be able to run commands of their own.",
    "deser.unsafe":
        "The code loads a saved file in a format that can carry instructions as well as data, so opening such a "
        "file from someone else can run their instructions on this machine.",
    "net.egress":
        "This line names a place on the network the program can talk to; every one is listed so you can see where "
        "data could go, and a public destination or an unencrypted one is called out.",
    "net.bind_all":
        "The program accepts network connections on every network this machine is attached to rather than only "
        "from this machine, so other machines may be able to reach it.",
    "tls.off":
        "The code switches off the check that the server it connects to is really that server, so the connection "
        "can be read or altered on the way.",
    "install.hook":
        "This project runs code of its own while it is being installed, before you ever start it, so installing it "
        "is already running part of it.",
    "dom.html_sink":
        "This code puts text into the page as HTML. If that text comes from a visitor or a web address, it can run "
        "as a script in another visitor's browser.",
    "obfuscation":
        "Something here is stored encoded instead of written out, and at the strongest level the code decodes it "
        "and runs it; either way you cannot tell by reading the file what the encoded part holds.",
    "fs.outside":
        "A write, a delete or a move points at a path outside this project, such as your home folder, so running "
        "this can change files that have nothing to do with it.",
    "deps.unpinned":
        "This dependency is named without a fixed version, so installing it on another day can bring in a "
        "different version of somebody else's code than the one this was built against.",
    "supply.unknown_package":
        "This project asks to install a package the check does not recognise; it may be a real but little-known "
        "one, or a name that never existed, which is how an invented dependency gets claimed by someone else.",
    "supply.lookalike":
        "This package name is one or two characters away from a well-known one, which is the shape of a "
        "typo-squat, though it can also just be a different real project.",
    "privacy.pii_log":
        "A value whose name says it holds personal data is written into the log; logs get copied, shared and kept "
        "far longer than the data itself.",
    "privacy.pii_prompt":
        "A value whose name says it holds personal data is passed to something that looks like a call to a language "
        "model; if it is one, that data can be sent to whoever runs the model and kept by them.",
    "check.crashed":
        "One of code-guardian's own checks stopped with an error on this file, so that one check did not finish; "
        "the rest of the scan did, and this says nothing about your project.",
    # Works
    "works.syntax":
        "Python cannot read this file at all, so nothing can import it or run it; it is either broken or written "
        "for a different version of Python than the one that scanned it.",
    "works.import_unresolved":
        "This file asks for a module that is not part of Python, not in this project and not in the list of things "
        "the project says it needs, so it can fail the moment it is loaded on another machine.",
    "works.relative_missing":
        "This file loads another file of this same project by name, and no such file is here, so that line can "
        "fail as soon as it runs.",
    "works.tests_missing":
        "There are no test files anywhere in this project, so nothing here checks that the code still does what it "
        "is meant to do.",
    "works.test_no_assert":
        "The check found no assertion in these tests, and it cannot see a helper that asserts in another file, so "
        "they may only notice a problem if the code stops with an error.",
    "works.entry_missing":
        "A command this project installs points at a function that is not in the project, so typing that command "
        "can fail straight away.",
    "works.todo_stub":
        "This is a placeholder somebody meant to fill in later, and the program can reach it, so if it is called it "
        "either does nothing or stops with a \"not implemented\" error.",
    "works.commented_code":
        "Several lines of real code here are commented out instead of deleted; the project's history already keeps "
        "the old version, so this is leftover text that makes the file harder to read.",
    "works.dead_flag":
        "An on/off setting is defined here and no file in the project ever names it, so changing it may have no "
        "effect at all.",
    "orphan.dead":
        "Starting from the places this project says it begins, nothing reaches this code, so as far as the check "
        "can follow it is carried around and never run.",
    "orphan.test_only":
        "Only the tests reach this; the program itself never does, so it is being kept alive by its own tests.",
    "orphan.uncertain":
        "This could be reached by a name the program works out while it runs, which the check cannot follow, so it "
        "cannot tell whether anything uses it.",
    # Complete
    "complete.license_missing":
        "There is no licence file, so nobody reading this project can tell what they are allowed to do with it.",
    "complete.license_undeclared":
        "The packaging details do not name a licence, so tools that read those details cannot tell what the terms "
        "are.",
    "complete.readme_missing":
        "There is no README, so somebody opening this project has nothing telling them what it is or how to run "
        "it.",
    "complete.readme_short":
        "The README is only a few lines long, which is rarely enough to say what this is, how to install it and "
        "how to use it.",
    "complete.readme_sections":
        "The README has no heading about installing and no heading about using it, so the two things a newcomer "
        "looks for first may be missing.",
    "complete.ci_missing":
        "Nothing here runs the tests automatically when the code changes, so they run only when somebody "
        "remembers to run them.",
    "complete.metadata":
        "The packaging file is missing a basic detail such as the name, the version or which Python it needs, "
        "which can stop it installing.",
    "complete.lockfile":
        "This looks like an application rather than a library, and it records no exact set of dependency "
        "versions, so two installs on different days can end up different.",
    "complete.env_example":
        "The code reads settings from its environment but no example file lists them, so whoever sets this up has "
        "to guess what to provide.",
    "deps.declared_unused":
        "This project says it needs this package and nothing here loads it; it may be used by a tool rather than "
        "by the code, or it may simply not be needed any more.",
}

# ---------------------------------------------------------------------------------------------------------------
# Small helpers


def _plural(n, word):
    return "%d %s%s" % (n, word, "" if n == 1 else "s")


def _findings(rep):
    return list(rep.get("findings") or [])


def _safe_findings(rep):
    return [f for f in _findings(rep) if score.dimension_of(f.get("code")) == "safe"]


def _reasons(rep):
    return [str(r) for r in (rep.get("status_reasons") or [])]


def _coverage(rep):
    return rep.get("coverage") or {}


def _title(code):
    entry = catalogue.CATALOGUE.get(code)
    return entry["title"] if entry else str(code)


# ---------------------------------------------------------------------------------------------------------------
# C2: harm level


def harm(rep):
    """The one-word answer to "how bad is this?", from the Safe findings only, plus why it says that.

    level is one of LABELS and is never None; partial says the scan did not cover the whole project, and a page
    renders it beside the label as "partial check"."""
    safe = _safe_findings(rep)
    counts = {level: sum(1 for f in safe if f.get("level") == level) for level in LEVEL_ORDER}
    partial = rep.get("status") == "PARTIAL" or bool(_coverage(rep).get("safe_partial"))
    if rep.get("status") == "INVALID":
        return {"level": COULD_NOT_CHECK, "partial": partial, "why": _invalid_why(rep), "counts": counts}
    for level in LEVEL_ORDER:
        if counts[level]:
            return {"level": LEVEL_LABEL[level], "partial": partial,
                    "why": _worst_why(safe, level, counts[level], partial), "counts": counts}
    return {"level": NONE_FOUND, "partial": partial, "why": _nothing_why(partial), "counts": counts}


def _invalid_why(rep):
    reasons = _reasons(rep)
    tail = "; ".join(reasons) if reasons else "the scan could not judge this project"
    return "There is no grade for this project: %s." % tail


def _worst(findings, level):
    """The finding of that level the scoring weighs heaviest; ties by code, then by where it is."""
    rows = [f for f in findings if f.get("level") == level]
    return max(rows, key=lambda f: (score.weight(f), str(f.get("code")), str(f.get("node"))))


def _worst_why(safe, level, count, partial):
    worst = _worst(safe, level)
    same = sum(1 for f in safe if f.get("code") == worst.get("code") and f.get("level") == level)
    rest = count - same
    lead = {"FAIL": "the level the checks use when a pattern they treat as serious matched",
            "WARN": "a level that means the pattern matched but may be fine where it is",
            "INFO": "a level that is inventory to read, not a problem on its own"}[level]
    return ("The strongest Safe signal is \"%s\", in %s, at %s (%s)%s%s."
            % (_title(worst.get("code")), _plural(same, "place"), level, lead,
               ", with %s also at that level" % _plural(rest, "other finding") if rest else "",
               _PARTIAL_CLAUSE if partial else ""))


_PARTIAL_CLAUSE = ", from a scan that did not cover the whole project"


def _nothing_why(partial):
    return ("No Safe check reported anything in the files that were read%s; a static scan only sees the patterns it "
            "knows, in files it could open." % (_PARTIAL_CLAUSE if partial else ""))


# ---------------------------------------------------------------------------------------------------------------
# C3: one sentence per score

# (floor, what that band reads like). The score itself and the counts come from the report.
BANDS = (
    (100, "nothing in this group took points off"),
    (90, "a few small things took points off"),
    (70, "there is a handful here worth reading"),
    (40, "several checks matched, or one heavy check did"),
    (0, "a lot matched, or something the scoring treats as serious did"),
)
_CAP_LETTER = re.compile(r"at most ([A-F])\b")


def _band(value):
    for floor, text in BANDS:
        if value >= floor:
            return text
    return BANDS[-1][1]


def _rows(rep, dimension):
    return list(((rep.get("dimensions") or {}).get(dimension) or {}).get("checks") or [])


def _behind(rows):
    total = sum(int(r.get("count") or 0) for r in rows)
    if not total:
        return "no finding took points off"
    return "%s across %s took the points off" % (_plural(total, "finding"), _plural(len(rows), "check"))


def _incomplete_clause(rep):
    """Said once, on the Overall sentence: the page's banner already leads with it, so repeating it on Safe, Works
    and Complete as well only adds noise."""
    return _PARTIAL_CLAUSE if rep.get("status") in ("PARTIAL", "INVALID") else ""


def score_sentence(dimension, rep):
    """One sentence for Safe, Works, Complete or Overall: the report's own number, the band it falls in, and how
    many findings are behind the deduction. Never a verdict."""
    if dimension not in DIMENSION_LABEL:
        raise ValueError("unknown dimension: %r" % (dimension,))
    scores = rep.get("scores") or {}
    value = scores.get(dimension)
    if dimension == "overall":
        return _overall_sentence(rep, scores)
    if value is None:
        reason = _coverage(rep).get("reason") or "the check could not run on this project"
        return "%s is not scored for this project, because %s." % (DIMENSION_LABEL[dimension], reason)
    rows = _rows(rep, dimension)
    return "%s scores %d out of 100: %s (%s)." % (DIMENSION_LABEL[dimension], value, _band(value), _behind(rows))


def _overall_sentence(rep, scores):
    reasons = _reasons(rep)
    if scores.get("grade") is None:
        tail = "; ".join(reasons) if reasons else "the scan could not judge this project"
        return "Overall is not graded: %s." % tail
    rows = [r for name in score.DIMENSIONS for r in _rows(rep, name)]
    value = scores.get("overall")
    cap = _cap_clause(scores)
    # When the cap reason already says the scan is PARTIAL, the clause would say it a second time.
    incomplete = "" if "PARTIAL" in cap else _incomplete_clause(rep)
    return "Overall %s (%s/100): %s (%s)%s%s." % (scores.get("grade"), value, _band(value), _behind(rows), cap,
                                                  incomplete)


def _cap_clause(scores):
    """", capped at D: <cap_reason>": the reason verbatim from the report, the letter read back out of it."""
    reason = scores.get("cap_reason")
    if not scores.get("capped") or not reason:
        return ""
    letters = _CAP_LETTER.findall(reason)
    letter = max(letters, key=score.GRADE_ORDER.index) if letters else scores.get("grade")
    return ", capped at %s: %s" % (letter, reason)


# ---------------------------------------------------------------------------------------------------------------
# C4: what was actually checked

# Complete looks at the project as a whole, not at each file, so it is not part of a per-file claim. "every"
# is only true when nothing was skipped or crashed; otherwise the line points at the reasons instead.
PYTHON_TEXT = "every Safe and Works check ran on these"
PYTHON_TEXT_PARTIAL = "the Safe and Works checks ran on these, except where the first line says otherwise"
PYTHON_TEXT_CRASHED = "the Safe and Works checks ran on these, except where a check did not finish"
# With no Python file there is nothing for those checks to run on, so the line says that and claims nothing ran.
PYTHON_TEXT_NONE = "there was no Python here for the Safe and Works checks to read"
OTHER_TEXT = ("read for key shapes, and where the file is a manifest for install hooks and pins; the code itself "
              "was not analysed")
# Measured, not quoted: a skipped file is never opened. walk.py puts a file in files.skipped when it is binary, a
# symlink, over the size limit or unreadable, and report.scan() secret-scans only inv["other"], never inv["skipped"].
# JavaScript / TypeScript (P81 C6): read at token level, so the line says what that reaches and what it does not.
# "tokens" is the depth the page shows as "token level". The generated line says what ran on minified or generated
# files (report.JS_GENERATED_CHECKS: key shapes, obfuscation, exec.dynamic) and nothing more.
JS_LABEL = "JavaScript / TypeScript"
JS_TEXT = ("analysed at token level: what the code calls, what it imports and loads, where it sends data, how it "
           "starts, and the text itself; not checked: how values move between functions, types, unused code")
JS_GENERATED_LABEL = "JavaScript (minified or generated)"
JS_GENERATED_TEXT = ("read for key shapes and for code that runs text or decodes hidden text; nothing else was "
                     "checked")
SKIPPED_TEXT = "not read at all, because they are binary, a symlink, too large or unreadable; the notes name each"
# An unparsed file is read and secret-scanned (report.scan() scans the text before building the parse tree) and
# only then fails to parse, so it is "secrets only", not "not read".
UNPARSED_TEXT = ("read and scanned for key shapes, but Python could not parse them, so every check that needs the "
                 "parse tree was skipped on them")


def checked_lines(rep):
    """What the scan actually looked at, one entry per group, in the order a page should show them. A scan that is
    PARTIAL or INVALID leads with why, so the first screen says it before it says anything else."""
    out = []
    reasons = _reasons(rep)
    leads = rep.get("status") in ("PARTIAL", "INVALID") and bool(reasons)
    if leads:
        out.append({"label": "Not fully checked", "files": 0, "depth": "not read",
                    "text": "Not fully checked: %s" % "; ".join(reasons)})
    cov = _coverage(rep)
    files = rep.get("files") or {}
    unparsed = int(files.get("unparsed") or 0)
    js = (cov.get("languages") or {}).get("javascript") or {}
    js_files, js_generated = int(js.get("files") or 0), int(js.get("generated") or 0)
    # The files that did not parse get their own entry below; they are not files every check ran on.
    python = max(0, int(cov.get("python") or 0) - unparsed)
    # No Python file but JavaScript / TypeScript analysed: the Safe and Works checks ran on that, so "there was no
    # Python here for the Safe and Works checks to read" would be false. With neither, the Python line stays.
    if int(cov.get("python") or 0) or not js_files:
        out.append({"label": "Python", "files": python, "depth": "full",
                    "text": "Python: %s \u2014 %s." % (_plural(python, "file"), _python_text(rep, leads, python))})
    if js_files:
        out.append({"label": JS_LABEL, "files": js_files, "depth": "tokens",
                    "text": "%s: %s \u2014 %s." % (JS_LABEL, _plural(js_files, "file"), JS_TEXT)})
    if js_generated:
        out.append({"label": JS_GENERATED_LABEL, "files": js_generated, "depth": "tokens",
                    "text": "%s: %s \u2014 %s." % (JS_GENERATED_LABEL, _plural(js_generated, "file"),
                                                   JS_GENERATED_TEXT)})
    for ext, count in sorted((cov.get("other_source") or {}).items()):
        label = LANGUAGES.get(ext, ext)
        out.append({"label": label, "files": int(count), "depth": "secrets+manifests",
                    "text": "%s: %s \u2014 %s." % (label, _plural(int(count), "file"), OTHER_TEXT)})
    skipped = int(files.get("skipped") or 0)
    if skipped:
        out.append({"label": "Skipped", "files": skipped, "depth": "not read",
                    "text": "Skipped: %s \u2014 %s." % (_plural(skipped, "file"), SKIPPED_TEXT)})
    if unparsed:
        out.append({"label": "Python that did not parse", "files": unparsed, "depth": "secrets only",
                    "text": "Python that did not parse: %s \u2014 %s." % (_plural(unparsed, "file"), UNPARSED_TEXT)})
    return out


def _python_text(rep, leads, python):
    """"every check ran" only when the report says nothing was skipped, crashed or left unread."""
    if not python:
        return PYTHON_TEXT_NONE
    crashed = any(f.get("code") == "check.crashed" for f in _findings(rep))
    if leads:
        return PYTHON_TEXT_PARTIAL
    if crashed or rep.get("status") in ("PARTIAL", "INVALID"):
        return PYTHON_TEXT_CRASHED
    return PYTHON_TEXT


# ---------------------------------------------------------------------------------------------------------------
# C5: one finding, as a card


def finding_card(finding, rep=None):
    """where / what / why / how for one finding. An unknown code falls back to the code and the finding's own
    summary rather than raising: a report from a newer version must still render.

    rep is accepted so a caller can hand the card its report (the page passes both); nothing here needs it, because
    a card must say the same thing wherever it is shown."""
    code = finding.get("code")
    entry = catalogue.CATALOGUE.get(code)
    return {
        "where": finding.get("node"),
        "what": entry["title"] if entry else code,
        "why": WHY.get(code) or finding.get("summary") or "",
        "how": finding.get("fix") or (entry or {}).get("fix"),
        "level": finding.get("level"),
        "confidence": finding.get("confidence"),  # a labelled field, never a word inside a sentence
        "code": code,
        "fingerprint": finding.get("fingerprint"),
    }


# ---------------------------------------------------------------------------------------------------------------
# C6: what to fix first


def fix_first(rep, top=10):
    """verify.plan's ranked rows, reduced to what a card needs. The ranks, gains and grades are the plan's."""
    return [{"rank": item["rank"], "title": item["title"], "level": item["level"], "count": item["count"],
             "gain": item["gain"], "grade_after": item["grade_after"],
             "first_location": (item.get("locations") or [None])[0], "how": item.get("fix") or ""}
            for item in verify.plan(rep, top=top)["items"]]


def fix_first_notes(rep, top=10):
    """The plan's notes, unchanged: they carry the "a Safe FAIL caps the grade" sentence among others."""
    return verify.plan(rep, top=top)["notes"]


FLOOR_NAME = {"safe": "Safety", "works": "Works", "complete": "Completeness"}


def fix_first_lead(rep):
    """One plain sentence for above the plan's notes, or None. The scanner's floor note ("Safe is at 0/100 with 174
    points deducted ...") is exact but hard to read; this says the same thing in plain words, for the dimensions
    where that note applies (the same test verify.plan uses, read from the report's own deductions)."""
    if rep.get("status") == "INVALID":
        return None
    floored = []
    for name in score.DIMENSIONS:
        dim = (rep.get("dimensions") or {}).get(name) or {}
        excess = int(dim.get("deducted") or 0) - 100
        rows = dim.get("checks") or []
        if excess > 0 and rows and max(int(r.get("deduction") or 0) for r in rows) <= excess:
            floored.append(FLOOR_NAME[name])
    if not floored:
        return None
    return ("%s problems do not raise the grade until most of them are fixed, so they can show +0 here. Fix them "
            "first anyway." % " and ".join(floored))


# ---------------------------------------------------------------------------------------------------------------
# C7 / C9: before and after


def diff_sentence(d):
    """One sentence for a verify.diff result: how many findings went away, how many are new, and what the grade did.
    The counts and the grades are the diff's own."""
    counts = d.get("counts") or {}
    grade = d.get("grade") or {}
    return "%d fixed, %d new, grade %s \u2192 %s" % (int(counts.get("fixed") or 0), int(counts.get("new") or 0),
                                                     grade.get("before") or "none", grade.get("after") or "none")


# ---------------------------------------------------------------------------------------------------------------
# S3 (P78 C4): every file, one honest label each

QUALITY = "Quality"
FILE_LEVELS = (HIGH, MEDIUM, LOW, QUALITY)
WHY_PARTLY_UNPARSED = "this file did not parse, so only the checks that need no parse tree ran"
WHY_PARTLY_LANGUAGE = "%s code is not analysed yet; only key shapes were checked"
WHY_PARTLY_NO_LANGUAGE = "this is not Python, so only key shapes were checked"
WHY_PARTLY_JS_BROKEN = ("this file stopped tokenising at a break, so the code after the break was not analysed "
                        "(the first line says where)")
WHY_PARTLY_JS_GENERATED = ("this is minified or generated JavaScript, so it was read only for key shapes and for "
                           "code that runs text or decodes hidden text")
_AND_MORE = re.compile(r" and \d+ more$")


def _unparsed_names(rep):
    """The files the report says did not parse: a works.syntax finding's file, or a name in a "did not parse" reason
    (report.status_of lists up to five names, then "and N more")."""
    names = {f["node"].rpartition(":")[0] or f["node"] for f in _findings(rep)
             if f.get("code") == "works.syntax" and isinstance(f.get("node"), str)}
    for reason in _reasons(rep):
        head, _, listing = reason.partition(": ")
        if "did not parse" in head:
            names.update(n.strip() for n in _AND_MORE.sub("", listing).split(", ") if n.strip())
    return names


def _file_of(node, known):
    """The file a finding's node ("file:line" or a bare file) points at, or None for a project-level node."""
    if not isinstance(node, str):
        return None
    if node in known:
        return node
    head, _, tail = node.rpartition(":")
    return head if tail.isdigit() and head in known else None


def file_rows(rep, inventory):
    """One row per distinct file the scan saw, sorted by rel; the report is read, never changed. inventory is
    walk.walk()'s result for the same scan. A file is labelled, in this order:
      Not read        walk put it in skipped (binary, symlink, unreadable, too large), whatever the findings say
      High/Medium/Low its worst Safe finding (FAIL, WARN, INFO); findings of any other check count as Quality
      Partly checked  a source file in a language this tool does not analyse, a Python file that did not parse,
                      a JavaScript / TypeScript file that stopped tokenising, or a minified or generated one
      No known risks found  a Python file that fully parsed, a JavaScript / TypeScript file that was analysed, or a
                      manifest
    A file the tool did not really read is never labelled "No known risks found"."""
    skipped = dict(inventory.get("skipped") or [])
    python, manifests = set(inventory.get("python") or []), set(inventory.get("manifests") or [])
    other = set(inventory.get("other") or [])
    known = python | manifests | other | set(skipped)
    counts = {rel: dict.fromkeys(FILE_LEVELS, 0) for rel in known}
    worst = {}
    for f in _findings(rep):
        rel = _file_of(f.get("node"), known)
        if rel is None:
            continue
        if score.dimension_of(f.get("code")) == "safe" and f.get("level") in LEVEL_LABEL:
            label = LEVEL_LABEL[f["level"]]
            counts[rel][label] += 1
            worst[rel] = min(worst.get(rel, label), label, key=FILE_LEVELS.index)
        else:
            counts[rel][QUALITY] += 1
    unparsed = _unparsed_names(rep)
    javascript, generated = set(inventory.get("javascript") or []), set(inventory.get("generated") or [])
    rows = []
    for rel in sorted(known):
        kind = ("not_read" if rel in skipped else "python" if rel in python
                else "manifest" if rel in manifests else "other")
        why_not_read = skipped.get(rel)
        why_partly = None
        if kind == "not_read":
            risk = NOT_READ
        elif rel in worst:
            risk = worst[rel]
        elif kind == "other" and rel in generated:
            risk, why_partly = PARTLY_CHECKED, WHY_PARTLY_JS_GENERATED
        elif kind == "other" and rel in javascript:
            if rel in unparsed:
                risk, why_partly = PARTLY_CHECKED, WHY_PARTLY_JS_BROKEN
            else:
                risk = NONE_FOUND
        elif kind == "other":
            risk = PARTLY_CHECKED
            stem, dot, ext = rel.rsplit("/", 1)[-1].rpartition(".")
            language = LANGUAGES.get("." + ext.lower()) if dot and stem else None
            why_partly = WHY_PARTLY_LANGUAGE % language if language else WHY_PARTLY_NO_LANGUAGE
        elif kind == "python" and rel in unparsed:
            risk, why_partly = PARTLY_CHECKED, WHY_PARTLY_UNPARSED
        else:
            risk = NONE_FOUND
        rows.append({"rel": rel, "kind": kind, "why_not_read": why_not_read, "why_partly": why_partly,
                     "findings": counts[rel], "risk": risk})
    return rows


def file_counts(rows):
    """The five numbers the file filter shows, derived from the rows and nothing else."""
    return {"all": len(rows),
            "with_findings": sum(1 for r in rows if any(r["findings"].values())),
            "no_known_risks": sum(1 for r in rows if r["risk"] == NONE_FOUND),
            "partly_checked": sum(1 for r in rows if r["risk"] == PARTLY_CHECKED),
            "not_read": sum(1 for r in rows if r["risk"] == NOT_READ)}


# ---------------------------------------------------------------------------------------------------------------
# P88 C5: the backup banner, the left-out line and the test-value line. The page builds these same sentences in
# app.js from the same fields (the server sends no sentence for them); tests/test_p88_s2_acceptance.py and
# tests/test_ui_backups.py hold the two to the same strings.


def _count(n, one, many):
    return "%d %s" % (n, one if n == 1 else many)


def backup_offer_line(offered, total):
    """The banner sentence: how many of the findings sit in the groups offered, and the globs. offered is the list in
    backup_offer["offered"] (each {"glob", "findings", ...}); total is every finding of the result the banner sits on.
    A glob ending in "/*" is a folder; any other is a set of files."""
    findings = sum(g["findings"] for g in offered)
    folders = sum(1 for g in offered if g["glob"].endswith("/*"))
    kinds = []
    if folders:
        kinds.append(_count(folders, "folder", "folders"))
    if len(offered) - folders:
        kinds.append(_count(len(offered) - folders, "set of files", "sets of files"))
    return "%d of %d %s %s in %s that %s: %s" % (
        findings, total, "finding" if total == 1 else "findings", "is" if total == 1 else "are", " and ".join(kinds),
        "looks like a backup copy" if len(offered) == 1 else "look like backup copies",
        ", ".join(g["glob"] for g in offered))


def held_line(held):
    """One line per backup group the check did not offer, with the reason it gave."""
    return ["%s was not offered: %s" % (g["glob"], g["why"]) for g in held]


def named_line(group):
    """A caution for an offered group that kept files name in a string, or None when none does: such files may only
    write copies there, or may read from it."""
    named = group.get("named_by") or []
    if not named:
        return None
    names = ", ".join(named[:3]) + (" and %d more" % (len(named) - 3) if len(named) > 3 else "")
    return "%s is named in a string by %s (%s): leave it out only if they just write copies there" % (
        group["glob"], _count(len(named), "file", "files"), names)


def left_out_line(groups):
    """The summary-header line after a person left paths out. groups is report["excluded_by_request"]: each has a glob
    and the files it left out; the server adds the findings and their counts by code when it computed them. A result
    with no counts for some group (a command-line one) says the files only."""
    files = sum(g.get("files", 0) for g in groups)
    head = "Left out at your request: %s" % ", ".join(g["glob"] for g in groups)
    if not all(isinstance(g.get("findings"), int) and isinstance(g.get("by_code"), dict) for g in groups):
        return "%s (%s)" % (head, _count(files, "file", "files"))
    found = sum(g["findings"] for g in groups)
    keys = sum(n for g in groups for code, n in g["by_code"].items() if code.split(" ")[0] == "secret.key")
    return "%s (%s, %s left out: %d secret.key, %d other)" % (
        head, _count(files, "file", "files"), _count(found, "finding", "findings"), keys, found - keys)


def test_values_line(n):
    """The summary line for key-shaped values graded as test values: n is report["test_values_graded"]."""
    if n == 1:
        return "1 key-shaped value was graded as a test value -- check it is fake"
    return "%d key-shaped values were graded as test values -- check they are fake" % n


# ---------------------------------------------------------------------------------------------------------------
# selftest


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if "--selftest" in argv:
        return selftest()
    sys.stderr.write("usage: python -m code_guardian.plain --selftest\n")
    return 2


def _demo(findings, status="COMPLETE", reasons=(), coverage=None, files=None):
    """A report of the shape report.scan() returns, scored by score.py so the numbers are the real ones."""
    cov = coverage or {"analysed": "python", "python": 3, "other_source": {}, "other_source_files": 0,
                       "works_scored": True, "safe_partial": False, "partial": False, "reason": None}
    dims = {name: score.dimension(findings, name) for name in score.DIMENSIONS}
    if not cov["works_scored"]:
        dims["works"] = score.unscored()
    dims["safe"]["partial"] = bool(cov["safe_partial"])
    return {"path": "demo", "status": status, "status_reasons": list(reasons), "coverage": cov,
            "files": files or {"python": cov["python"], "manifests": 0, "other": 0, "skipped": 0, "ignored": 0,
                               "excluded": 0, "unparsed": 0},
            "findings": findings, "hygiene": {"findings": []}, "dimensions": dims,
            "scores": score.scores(findings, dims, status)}


def selftest():
    import copy

    def f(code, level, node="a.py:1", summary="s", fingerprint=None):
        return {"code": code, "severity": "partial", "level": level, "node": node, "summary": summary,
                "evidence": [], "try": [], "confidence": "LIKELY", "fix": None,
                "fingerprint": fingerprint or ("%064x" % (abs(hash((code, level, node))) % (1 << 256)))}

    high = _demo([f("secret.key", "FAIL", "app.py:2"), f("exec.shell", "WARN", "app.py:9")])
    medium = _demo([f("supply.lookalike", "WARN", "requirements.txt:1")])
    low = _demo([f("net.egress", "INFO", "app.py:4")])
    nothing = _demo([])
    invalid = _demo([], status="INVALID", reasons=["no Python files and no manifests to judge"])
    no_python = _demo([], status="PARTIAL", reasons=["no Python source: Works not scored, Safe partial"],
                      coverage={"analysed": "python", "python": 0, "other_source": {".js": 1},
                                "other_source_files": 1, "works_scored": False, "safe_partial": True,
                                "partial": True, "reason": "no Python source: Works not scored, Safe partial"})
    mixed = _demo([f("net.egress", "WARN", "a.py:%d" % i) for i in range(1, 12)]
                  + [f("complete.readme_missing", "WARN", ".")])
    unknown_ext = _demo([], coverage=dict(low["coverage"], other_source={".zzq": 2}, other_source_files=2))
    skipped = _demo([], files={"python": 3, "manifests": 0, "other": 0, "skipped": 2, "ignored": 0, "excluded": 0,
                               "unparsed": 1})
    crashed_rep = _demo([f("check.crashed", "WARN", "a.py:1", "a check crashed")])

    sentences = []
    for rep in (high, medium, low, nothing, invalid, no_python, mixed, unknown_ext, skipped, crashed_rep):
        h = harm(rep)
        sentences += [h["level"], h["why"]]
        sentences += [score_sentence(d, rep) for d in ("safe", "works", "complete", "overall")]
        sentences += [e["text"] for e in checked_lines(rep)]
    sentences += list(WHY.values())

    before = copy.deepcopy(high)
    harm(high), checked_lines(high), fix_first(high), fix_first_notes(high)
    [score_sentence(d, high) for d in ("safe", "works", "complete", "overall")]
    [finding_card(x, high) for x in high["findings"]]

    card = finding_card(high["findings"][0], high)
    stranger = finding_card(f("zz.not_a_code", "WARN", "a.py:3", "something odd"), high)
    try:
        score_sentence("nope", high)
        refuses = False
    except ValueError:
        refuses = True
    bands = [score_sentence("safe", _demo([f("net.egress", "WARN", "a.py:%d" % i) for i in range(1, n + 1)]))
             for n in (0, 1, 7, 20, 60)]
    plan_items = fix_first(mixed, top=1)

    inventory = {"python": ["a.py", "b.py", "c.py", "setup.py"], "manifests": ["requirements.txt", "setup.py"],
                 "other": ["index.js", "notes.txt", "Makefile"], "skipped": [("blob.bin", "binary")],
                 "excluded": 0, "ignored": 0}
    rows_rep = _demo([f("exec.shell", "FAIL", "b.py:3"), f("net.egress", "INFO", "b.py:5"),
                      f("works.syntax", "FAIL", "c.py:1"), f("complete.readme_missing", "WARN", "a.py"),
                      f("supply.lookalike", "WARN", "requirements.txt:1"), f("secret.key", "FAIL", "index.js:1"),
                      f("secret.key", "FAIL", "blob.bin:1"), f("complete.readme_missing", "WARN", ".")])
    rows_before = copy.deepcopy(rows_rep)
    rows = {r["rel"]: r for r in file_rows(rows_rep, inventory)}
    reason_only = {r["rel"]: r for r in file_rows(
        _demo([], status="PARTIAL", reasons=["2 Python file(s) did not parse: c.py, d.py"]), inventory)}
    more = {r["rel"]: r for r in file_rows(
        _demo([], status="PARTIAL", reasons=["7 Python file(s) did not parse: a.py, b.py and 5 more"]), inventory)}

    checks = [
        ("labels_are_the_five", set(LABELS) == {HIGH, MEDIUM, LOW, NONE_FOUND, COULD_NOT_CHECK}),
        ("harm_high", harm(high)["level"] == HIGH and harm(high)["counts"] == {"FAIL": 1, "WARN": 1, "INFO": 0}),
        ("harm_medium", harm(medium)["level"] == MEDIUM),
        ("harm_low", harm(low)["level"] == LOW),
        ("harm_none", harm(nothing)["level"] == NONE_FOUND and harm(nothing)["counts"]["FAIL"] == 0),
        ("harm_invalid_says_why", harm(invalid)["level"] == COULD_NOT_CHECK
         and invalid["status_reasons"][0] in harm(invalid)["why"]),
        ("harm_partial", harm(no_python)["partial"] is True and harm(nothing)["partial"] is False),
        ("harm_why_names_the_worst", _title("secret.key") in harm(high)["why"]),
        ("no_verdict_phrase", not [s for s in sentences if VERDICT_PHRASES.search(s or "")]),
        ("why_covers_catalogue", set(WHY) == set(catalogue.CATALOGUE)
         and all(isinstance(v, str) and v.strip() for v in WHY.values())),
        ("score_bands_differ", len({b.split(": ", 1)[1] for b in bands}) == 5),
        ("score_names_the_count", "1 finding across 1 check" in bands[1]),
        ("overall_carries_grade_and_cap", "Overall %s (%s/100)" % (high["scores"]["grade"],
                                                                   high["scores"]["overall"])
         in score_sentence("overall", high) and high["scores"]["cap_reason"] in score_sentence("overall", high)),
        ("null_dimension", "not scored" in score_sentence("works", no_python).lower()
         and no_python["coverage"]["reason"] in score_sentence("works", no_python)),
        ("unknown_dimension_refused", refuses),
        ("languages_table", len(LANGUAGES) >= 20 and LANGUAGES[".js"] == "JavaScript"),
        ("checked_lines_python_first", [e["label"] for e in checked_lines(low)][0] == "Python"
         and checked_lines(low)[0]["depth"] == "full"),
        ("checked_lines_language_named", [e for e in checked_lines(no_python) if e["label"] == "JavaScript"]
         and checked_lines(no_python)[-1]["text"].startswith("JavaScript: 1 file \u2014")),
        ("checked_lines_unknown_extension", ".zzq" in [e["label"] for e in checked_lines(unknown_ext)]),
        ("checked_lines_skipped_and_unparsed",
         {"Skipped", "Python that did not parse"} <= {e["label"] for e in checked_lines(skipped)}
         and [e["files"] for e in checked_lines(skipped) if e["label"] == "Python"] == [2]),  # 3 read - 1 unparsed
        ("checked_lines_hedge_when_a_check_did_not_finish",
         "every" in checked_lines(low)[0]["text"]
         and "every" not in [e for e in checked_lines(crashed_rep) if e["label"] == "Python"][0]["text"]
         and "every" not in [e for e in checked_lines(no_python) if e["label"] == "Python"][0]["text"]),
        ("checked_lines_no_python_claims_nothing_ran",
         [e["text"] for e in checked_lines(no_python) if e["label"] == "Python"][0] == "Python: 0 files \u2014 %s."
         % PYTHON_TEXT_NONE),
        ("no_ascii_double_dash", not [s for s in sentences if " -- " in (s or "")]),
        ("partial_clause_once", sum(_PARTIAL_CLAUSE in score_sentence(d, no_python)
                                    for d in ("safe", "works", "complete", "overall")) <= 1
         and _PARTIAL_CLAUSE not in score_sentence("safe", no_python)),
        ("status_reasons_first", checked_lines(invalid)[0]["text"].endswith(invalid["status_reasons"][0])),
        ("finding_card_known", card["what"] == _title("secret.key") and card["why"] == WHY["secret.key"]
         and card["how"] == catalogue.CATALOGUE["secret.key"]["fix"] and card["confidence"] == "LIKELY"
         and set(card) == {"where", "what", "why", "how", "level", "confidence", "code", "fingerprint"}),
        ("finding_card_unknown_code", stranger["what"] == "zz.not_a_code" and stranger["why"] == "something odd"
         and stranger["how"] is None),
        ("fix_first_matches_plan", [i["rank"] for i in plan_items] == [1]
         and plan_items[0]["title"] == verify.plan(mixed, top=1)["items"][0]["title"]
         and plan_items[0]["first_location"] == verify.plan(mixed, top=1)["items"][0]["locations"][0]),
        ("fix_first_notes_pass_through", fix_first_notes(mixed) == verify.plan(mixed, top=10)["notes"]),
        ("never_mutates", high == before),
        ("diff_sentence", diff_sentence(verify.diff(high, medium)).startswith("2 fixed, 1 new, grade %s \u2192 %s"
                                                                         % (high["scores"]["grade"],
                                                                            medium["scores"]["grade"]))),
        ("fix_first_lead_only_when_floored", fix_first_lead(high) is None and fix_first_lead(invalid) is None),
        ("partial_said_once_in_overall", score_sentence("overall", no_python).count("PARTIAL")
         + score_sentence("overall", no_python).count(_PARTIAL_CLAUSE) == 1),
        ("file_rows_one_row_per_file_sorted", list(rows) == sorted(rows) and len(rows) == 9
         and [r["rel"] for r in file_rows(rows_rep, inventory)] == sorted(rows)),
        ("file_rows_worst_safe_finding_wins", rows["b.py"]["risk"] == HIGH
         and rows["b.py"]["findings"] == {HIGH: 1, MEDIUM: 0, LOW: 1, QUALITY: 0}
         and rows["requirements.txt"]["risk"] == MEDIUM),
        ("file_rows_other_dimensions_are_quality", rows["a.py"]["risk"] == NONE_FOUND
         and rows["a.py"]["findings"][QUALITY] == 1 and not any(rows["a.py"]["findings"][k] for k in LEVEL_LABEL.values())),
        ("file_rows_unparsed_python_is_partly_checked", rows["c.py"]["risk"] == PARTLY_CHECKED
         and rows["c.py"]["why_partly"] == WHY_PARTLY_UNPARSED
         and reason_only["c.py"]["risk"] == PARTLY_CHECKED and reason_only["a.py"]["risk"] == NONE_FOUND
         and more["a.py"]["risk"] == PARTLY_CHECKED and more["c.py"]["risk"] == NONE_FOUND),
        ("file_rows_other_files_name_their_language", rows["notes.txt"]["risk"] == PARTLY_CHECKED
         and rows["Makefile"]["why_partly"] == WHY_PARTLY_NO_LANGUAGE
         and reason_only["index.js"]["risk"] == PARTLY_CHECKED
         and reason_only["index.js"]["why_partly"].startswith("JavaScript code is not analysed yet")),
        ("file_rows_not_read_wins_over_findings", rows["blob.bin"]["risk"] == NOT_READ
         and rows["blob.bin"]["why_not_read"] == "binary" and rows["blob.bin"]["kind"] == "not_read"),
        ("file_rows_a_secret_in_another_language_is_high", rows["index.js"]["risk"] == HIGH
         and rows["index.js"]["why_partly"] is None),
        ("file_rows_setup_py_is_one_row", [r["kind"] for r in file_rows(rows_rep, inventory)
                                           if r["rel"] == "setup.py"] == ["python"]
         and rows["requirements.txt"]["kind"] == "manifest"),
        ("file_rows_unchecked_files_are_never_no_known_risks", not [
            r for r in rows.values() if r["kind"] in ("other", "not_read") and r["risk"] == NONE_FOUND]
         and not [r for r in reason_only.values() if r["kind"] in ("other", "not_read") and r["risk"] == NONE_FOUND]),
        ("file_rows_project_level_findings_belong_to_no_file", sum(
            sum(r["findings"].values()) for r in rows.values()) == 7),
        ("file_counts_from_the_rows", file_counts(list(rows.values())) == {
            "all": 9, "with_findings": 6, "no_known_risks": 2, "partly_checked": 3, "not_read": 1}
         and file_counts([]) == dict.fromkeys(("all", "with_findings", "no_known_risks", "partly_checked",
                                               "not_read"), 0)),
        ("backup_lines_exact", backup_offer_line([{"glob": "_archive/*", "findings": 5}], 9)
         == "5 of 9 findings are in 1 folder that looks like a backup copy: _archive/*"
         and backup_offer_line([{"glob": "_archive/*", "findings": 1}], 1)
         == "1 of 1 finding is in 1 folder that looks like a backup copy: _archive/*"
         and held_line([{"glob": "old/*", "why": "app/main.py imports old/helper.py"}])
         == ["old/* was not offered: app/main.py imports old/helper.py"] and held_line([]) == []
         and named_line({"glob": "old/*", "named_by": []}) is None),
        ("left_out_and_test_value_lines_exact", left_out_line(
            [{"glob": "old/*", "files": 1, "findings": 1, "by_code": {"secret.key FAIL": 1}}])
         == "Left out at your request: old/* (1 file, 1 finding left out: 1 secret.key, 0 other)"
         and left_out_line([{"glob": "old/*", "files": 4}]) == "Left out at your request: old/* (4 files)"
         and test_values_line(3) == "3 key-shaped values were graded as test values -- check they are fake"),
        ("file_rows_never_mutates", rows_rep == rows_before),
        ("file_rows_no_verdict_phrase", not [
            v for r in rows.values() for v in (r["risk"], r["why_partly"], r["why_not_read"])
            if VERDICT_PHRASES.search(v or "")]),
    ]
    return summarize("plain", checks)


if __name__ == "__main__":
    sys.exit(main())
