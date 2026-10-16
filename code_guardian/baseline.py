"""Finding fingerprints and baselines: which findings are new since the baseline was written?

A fingerprint is sha256(code | level | relpath | normalised evidence line). The evidence line is the source line the
finding points at, stripped, whitespace collapsed and redacted. Line numbers are left out, so moving code does not make
"new" findings; editing the line does. A repo-level finding (node ".") or one without a line has an empty evidence line.

A baseline is a JSON file meant to be committed: {"tool", "version", "fingerprints": [sorted]}. Fingerprints are a
multiset: a file with the same line twice has the same fingerprint twice, and a third copy is new. Pure and
deterministic; the only file it writes is the one `code-guardian baseline` asks for.

Public contract:
    FILENAME
    normalise(line) -> str                fingerprint(code, level, relpath, line) -> 64 hex chars
    split_node(node) -> (relpath, line number or 0)
    stamp(findings, line_of)              # sets f["fingerprint"]; line_of(relpath, lineno) -> source line text
    document(findings, version) -> dict   # the baseline file's content
    load(path) -> {"version", "fingerprints"}   # raises ValueError on a malformed file, OSError when unreadable
    mark(findings, fingerprints) -> (new, known)  # sets f["new"]; findings in report order
"""

import collections
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile

from .finding import make_finding, summarize
from .scanners import redact

FILENAME = "code-guardian.baseline.json"
_SPACE = re.compile(r"\s+")


def normalise(line):
    return redact(_SPACE.sub(" ", str(line).strip()))


def fingerprint(code, level, relpath, line):
    text = "%s|%s|%s|%s" % (code, level, relpath, normalise(line))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def split_node(node):
    path, _, line = str(node).rpartition(":")
    return (path, int(line)) if path and line.isdigit() else (str(node), 0)


def stamp(findings, line_of):
    for f in findings:
        rel, lineno = split_node(f["node"])
        f["fingerprint"] = fingerprint(f["code"], f["level"], rel, line_of(rel, lineno) if lineno else "")
    return findings


def document(findings, version):
    return {"tool": "code-guardian", "version": version,
            "note": "finding fingerprints for code-guardian scan --baseline; regenerate with code-guardian baseline",
            "fingerprints": sorted(f["fingerprint"] for f in findings)}


def load(path):
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    fps = data.get("fingerprints") if isinstance(data, dict) else None
    if not isinstance(fps, list) or not all(isinstance(x, str) and re.fullmatch(r"[0-9a-f]{64}", x) for x in fps):
        raise ValueError("%s is not a code-guardian baseline (no list of fingerprints)" % path)
    return {"version": str(data.get("version", "")), "fingerprints": fps}


def mark(findings, fingerprints):
    """Each finding consumes one matching fingerprint (known) or none is left (new). Returns (new, known)."""
    left = collections.Counter(fingerprints)
    new = known = 0
    for f in findings:
        if left[f["fingerprint"]] > 0:
            left[f["fingerprint"]] -= 1
            f["new"] = False
            known += 1
        else:
            f["new"] = True
            new += 1
    return new, known


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if "--selftest" in argv:
        return selftest()
    sys.stderr.write("usage: python -m code_guardian.baseline --selftest\n")
    return 2


def selftest():
    lines = {("a.py", 3): "os.system('ls')", ("a.py", 9): "  os.system('ls')", ("a.py", 4): "eval(x)"}

    def mk(node, code="exec.shell"):
        return make_finding(code, "partial", "WARN", node, "s")

    old = stamp([mk("a.py:3"), mk("a.py:4", "exec.dynamic"), mk(".", "works.tests_missing")],
                lambda r, n: lines.get((r, n), ""))
    moved = stamp([mk("a.py:9"), mk("a.py:3")], lambda r, n: lines.get((r, n), ""))
    tmp = tempfile.mkdtemp()
    try:
        path = os.path.join(tmp, FILENAME)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(document(old, "0"), fh)
        loaded = load(path)
        bad = os.path.join(tmp, "bad.json")
        with open(bad, "w", encoding="utf-8") as fh:
            fh.write('{"fingerprints": ["nope"]}')
        try:
            load(bad)
            rejects = False
        except ValueError:
            rejects = True
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    checks = [
        ("hex", len(old[0]["fingerprint"]) == 64 and old[0]["fingerprint"] == moved[0]["fingerprint"]),
        ("no_line_numbers", fingerprint("c", "WARN", "a.py", " x  = 1 ") == fingerprint("c", "WARN", "a.py", "x = 1")),
        ("repo_level", old[2]["fingerprint"] == fingerprint("works.tests_missing", "WARN", ".", "")),
        ("sorted_doc", document(old, "0")["fingerprints"] == sorted(f["fingerprint"] for f in old)),
        ("load", loaded["fingerprints"] == sorted(f["fingerprint"] for f in old) and loaded["version"] == "0"),
        ("rejects_bad", rejects),
        ("multiset", mark(moved, [old[0]["fingerprint"]]) == (1, 1) and [f["new"] for f in moved] == [False, True]),
        ("split_node", split_node("x/y.py:12") == ("x/y.py", 12) and split_node(".") == (".", 0)),
    ]
    return summarize("baseline", checks)


if __name__ == "__main__":
    sys.exit(main())
