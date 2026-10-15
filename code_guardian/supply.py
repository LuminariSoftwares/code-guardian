"""Supply-chain name checks: does every dependency name point at a real, established package?

AI assistants sometimes suggest packages that do not exist, and anyone can register such a name on PyPI. A package
existing is not proof it is safe: attackers register exactly the names assistants invent.

    supply.unknown_package  INFO  offline: not in the bundled list of known packages (run --online to check)
    supply.unknown_package  FAIL  --online: PyPI has no such project
    supply.unknown_package  WARN  --online: first release under 90 days ago, or only one release
    supply.lookalike        WARN  one or two edits away from a known package without being it

Offline (the default) compares against code_guardian/data/known_packages.txt.gz, a hand-built list (see
tools/known_packages.txt). --online asks https://pypi.org/pypi/<name>/json (or CODE_GUARDIAN_PYPI_URL) with urllib,
caches each answer for the run, and reports timeouts as notes; it never fails the scan. Online answers depend on
PyPI and on today's date, so --online output is not reproducible; the default offline output is.

Candidates are every declared dependency plus every import works.import_unresolved could not place.

Public contract:
    known_names() -> frozenset         distance(a, b, limit=2) -> int (limit + 1 when further)
    lookalike(name, known) -> nearest known name or None
    candidates(project) -> [(name, node)]
    check(project, online=False, env=None) -> (findings, notes)
"""

import datetime
import functools
import gzip
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from .finding import make_finding, summarize
from .manifests import declared as declared_deps
from .works import IMPORT_DISTS, local_names, normalise, product, registered_modules, unresolved_imports

DATA = Path(__file__).resolve().parent / "data" / "known_packages.txt.gz"
PYPI = "https://pypi.org/pypi"
NEW_DAYS = 90
LOOKALIKE_MIN = 5          # names shorter than this are too short to judge (six, sh, rq...)
LOOKALIKE_TWO_EDITS = 8    # two edits only for names at least this long


@functools.lru_cache(maxsize=1)
def known_names(path=DATA):
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        return frozenset(line.strip() for line in fh if line.strip() and not line.startswith("#"))


def distance(a, b, limit=2):
    """Optimal-string-alignment distance (insert, delete, substitute, swap neighbours), capped at limit + 1."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2, prev = None, list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if prev2 is not None and i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > limit:
            return limit + 1
        prev2, prev = prev, cur
    return min(prev[-1], limit + 1)


def lookalike(name, known):
    name = normalise(name)
    if name in known or len(name) < LOOKALIKE_MIN:
        return None
    limit = 2 if len(name) >= LOOKALIKE_TWO_EDITS else 1
    best = None
    for k in known:
        d = distance(name, k, limit)
        if 0 < d <= limit and (best is None or (d, k) < best):
            best = (d, k)
    return best[1] if best else None


def candidates(project):
    """(normalised distribution name, first file:line) for declared dependencies, then unresolved imports."""
    texts, trees = project["texts"], project["trees"]
    own = set()
    out, seen = [], set()
    for rel, text in sorted(texts.items()):
        if rel == "pyproject.toml":
            own.update(normalise(n) for n in _project_names(text))
        for name, line, _ in declared_deps(rel, text, trees.get(rel)):
            key = normalise(name)
            if key not in seen and key not in own:
                seen.add(key)
                out.append((key, "%s:%d" % (rel, line)))
    declared = {k for k, _ in out} | own
    local = local_names(project["files"]) | registered_modules(trees)
    for rel in sorted(t for t in trees if product(t)):
        for line, module in unresolved_imports(rel, trees[rel], local, declared):
            key = normalise((IMPORT_DISTS.get(module) or (module,))[0])
            if key not in seen:
                seen.add(key)
                out.append((key, "%s:%d" % (rel, line)))
    return out


def _project_names(text):
    import tomllib
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    names = [(data.get("project") or {}).get("name"), ((data.get("tool") or {}).get("poetry") or {}).get("name")]
    return [n for n in names if isinstance(n, str)]


def _finding(code, level, node, summary, evidence, try_):
    return make_finding(code, "partial", level, node, summary, evidence=evidence, try_=try_)


def fetch(name, base, timeout):
    """("missing" | "ok" | "error", detail). detail for ok: (release count, first upload date or None)."""
    url = "%s/%s/json" % (base.rstrip("/"), urllib.parse.quote(name))
    host = urllib.parse.urlsplit(url).hostname or ""
    handlers = [urllib.request.ProxyHandler({})] if host in ("127.0.0.1", "localhost", "::1") else []
    try:
        with urllib.request.build_opener(*handlers).open(url, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return ("missing", None) if exc.code == 404 else ("error", "HTTP %d" % exc.code)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return "error", type(getattr(exc, "reason", exc)).__name__
    dates, count = [], 0
    for files in (body.get("releases") or {}).values():
        if files:
            count += 1
            dates.extend(str(f.get("upload_time_iso_8601") or f.get("upload_time") or "")[:10] for f in files)
    dates = [d for d in dates if len(d) == 10]
    return "ok", (count, min(dates) if dates else None)


def check(project, online=False, env=None):
    env = os.environ if env is None else env
    known = known_names()
    base = (env.get("CODE_GUARDIAN_PYPI_URL") or PYPI).strip()
    timeout = float(env.get("CODE_GUARDIAN_PYPI_TIMEOUT") or 10)
    today = datetime.date.today() if online else None
    findings, notes, cache = [], [], {}
    for name, node in candidates(project):
        if name in known:
            continue
        near = lookalike(name, known)
        if near:
            findings.append(_finding("supply.lookalike", "WARN", node,
                                     "%s is one or two letters away from the popular package %s" % (name, near),
                                     ["name: %s" % name, "looks like: %s" % near],
                                     ["check you meant %s; a lookalike name is how typosquatting works" % near]))
        answer = None
        if online:
            if name not in cache:
                cache[name] = fetch(name, base, timeout)
            answer = cache[name]
            if answer[0] == "error":
                notes.append("online check: could not check %s on PyPI (%s)" % (name, answer[1]))
        if answer and answer[0] == "missing":
            findings.append(_finding("supply.unknown_package", "FAIL", node,
                                     "%s does not exist on PyPI (likely invented by an AI assistant; anyone could "
                                     "register this name)" % name,
                                     ["name: %s" % name, "PyPI answered 404"],
                                     ["remove it, or find the real package that provides what you need"]))
        elif answer and answer[0] == "ok":
            count, first = answer[1]
            young = first is not None and (today - datetime.date.fromisoformat(first)).days < NEW_DAYS
            if count <= 1 or young:
                findings.append(_finding("supply.unknown_package", "WARN", node,
                                         "%s is a new or single-release package; check it is the one you meant" % name,
                                         ["name: %s" % name, "releases: %d" % count, "first release: %s" % first],
                                         ["confirm the project, its author and its source repository before installing"]))
        elif not near:
            findings.append(_finding("supply.unknown_package", "INFO", node,
                                     "%s is not in the offline list of known packages; run with --online to check it "
                                     "exists" % name, ["name: %s" % name, "offline list: %d names" % len(known)],
                                     ["run code-guardian scan --online"]))
    return findings, notes


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if "--selftest" in argv:
        return selftest()
    sys.stderr.write("usage: python -m code_guardian.supply --selftest\n")
    return 2


def selftest():
    import ast
    known = known_names()
    project = {"texts": {"requirements.txt": "requests==2.32.3\nreqeusts==1.0\nzzz-made-up-pkg==0.1\n"},
               "trees": {"a.py": ast.parse("import numpy\nimport pandaz\n")}, "files": ["a.py", "requirements.txt"]}
    found = sorted((f["code"], f["level"], f["node"]) for f in check(project)[0])
    checks = [
        ("snapshot", len(known) > 900 and "requests" in known and "python-dateutil" in known),
        ("distance", [distance("reqeusts", "requests"), distance("requets", "requests"), distance("django", "flask")]
         == [1, 1, 3]),
        ("lookalike", lookalike("reqeusts", known) == "requests" and lookalike("six", known) is None
         and lookalike("requests", known) is None),
        ("candidates", [n for n, _ in candidates(project)] == ["requests", "reqeusts", "zzz-made-up-pkg", "numpy", "pandaz"]),
        ("offline", found == [("supply.lookalike", "WARN", "a.py:2"), ("supply.lookalike", "WARN", "requirements.txt:2"),
                              ("supply.unknown_package", "INFO", "requirements.txt:3")]),
    ]
    return summarize("supply", checks)


if __name__ == "__main__":
    sys.exit(main())
