"""The golden test (P81 C5): every Python-only fixture is re-scanned and compared with the report recorded from main
before any JavaScript analysis existed, so every later P81 section can prove "every Python result unchanged".

tests/golden/<fixture>.json is canonical(<fixture>) as json.dumps(..., indent=1, sort_keys=True) + a newline.
Regenerate one only on purpose, from a commit with the scanner change you mean to record:

    python tests/test_golden.py --record

The comparison, per fixture:
  1. every key in the golden has the identical value in the new report, recursively (a list is compared whole, so
     an extra outcomes row or finding is a delta);
  2. a key in the new report that the golden lacks is allowed only when its dotted path is in ADDITIVE;
  3. tests/golden/<fixture>.delta.json, when it exists, is applied to the golden first. It is {"replace": {dotted.path:
     new value}} and is reviewed line by line against the plan's list of what may change; none exists yet (risky_repo's
     is recorded by S4);
  4. scores, status and hygiene are also compared literally against the unmodified golden, never through a delta.

EXCLUDED are the top-level keys dropped from both sides: version changes every release, schema_version is bumped by
the plan on purpose, weights is pinned by test_readme_sync and test_scoring, path is the scanned location.
The scan is of an LF-normalised temporary copy, so one golden serves Linux, macOS and Windows (a CRLF checkout changes
complete_bare's README byte count).
"""
import json
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import make_risky  # noqa: E402

from code_guardian import report  # noqa: E402
from code_guardian.scanners import redact_report  # noqa: E402

FIXTURES = HERE / "fixtures"
GOLDEN = HERE / "golden"
EXCLUDED = ("version", "schema_version", "weights", "path")
ADDITIVE = {"files.javascript", "files.generated", "coverage.languages"}
JS_FIXTURES = ("js_clean", "js_risky", "js_broken", "jsx_torture")
GOLDEN_FIXTURES = sorted(p.name for p in FIXTURES.iterdir() if p.is_dir() and p.name not in JS_FIXTURES)
LITERAL = ("scores", "status", "hygiene")


def _source(name, tmp):
    """The fixture as the scan sees it: risky_repo is built (its key shapes are written at test time)."""
    if name == "risky_repo":
        return make_risky.build(Path(tmp) / "build" / name)
    return FIXTURES / name


def canonical(path):
    """The `scan --json` report of an LF-normalised temporary copy of path, with EXCLUDED dropped."""
    path = Path(path)
    with tempfile.TemporaryDirectory() as tmp:
        copy = Path(tmp) / path.name
        shutil.copytree(path, copy)
        for p in copy.rglob("*"):
            if p.is_file() and not p.is_symlink():
                data = p.read_bytes()
                if b"\0" not in data and b"\r\n" in data:
                    p.write_bytes(data.replace(b"\r\n", b"\n"))
        rep = json.loads(json.dumps(redact_report(report.scan(str(copy)))))
    for key in EXCLUDED:
        rep.pop(key, None)
    return rep


def dumps(rep):
    return json.dumps(rep, indent=1, sort_keys=True) + "\n"


def apply_delta(golden, delta):
    out = json.loads(json.dumps(golden))
    for dotted, value in delta.get("replace", {}).items():
        *parents, last = dotted.split(".")
        node = out
        for part in parents:
            node = node[part]
        node[last] = value
    return out


def differences(golden, new, prefix=""):
    """Problems found comparing new with golden: a changed or missing golden key, a new key not in ADDITIVE."""
    out = []
    for key, want in golden.items():
        dotted = prefix + key
        if key not in new:
            out.append("missing: %s" % dotted)
        elif isinstance(want, dict) and isinstance(new[key], dict):
            out.extend(differences(want, new[key], dotted + "."))
        elif want != new[key]:
            out.append("changed: %s\n    golden: %s\n    new:    %s" % (dotted, json.dumps(want)[:300],
                                                                      json.dumps(new[key])[:300]))
    for key in new:
        if key not in golden and prefix + key not in ADDITIVE:
            out.append("new key not in ADDITIVE: %s" % (prefix + key))
    return out


@pytest.mark.parametrize("name", GOLDEN_FIXTURES)
def test_golden(name, tmp_path):
    golden = json.loads((GOLDEN / ("%s.json" % name)).read_text(encoding="utf-8"))
    delta_file = GOLDEN / ("%s.delta.json" % name)
    delta = json.loads(delta_file.read_text(encoding="utf-8")) if delta_file.is_file() else {}
    assert not {k.split(".")[0] for k in delta.get("replace", {})} & set(LITERAL), (
        "a delta may not touch scores, status or hygiene")
    new = canonical(_source(name, tmp_path))
    problems = differences(apply_delta(golden, delta), new)
    problems += ["literal %s differs from the golden" % key for key in LITERAL if golden.get(key) != new.get(key)]
    assert not problems, "%s: the report moved from the recorded golden:\n  %s" % (name, "\n  ".join(problems))


if __name__ == "__main__":
    if sys.argv[1:] != ["--record"]:
        sys.exit("usage: python tests/test_golden.py --record")
    GOLDEN.mkdir(exist_ok=True)
    for fixture in GOLDEN_FIXTURES:
        with tempfile.TemporaryDirectory() as tmp:
            (GOLDEN / ("%s.json" % fixture)).write_text(dumps(canonical(_source(fixture, tmp))), encoding="utf-8",
                                                        newline="\n")
        print("recorded", fixture)
