"""P141 S0 golden: all 13 fixture repos and works.test_no_assert, frozen before any later P141 section.

tests/test_golden.py covers only the 10 Python fixtures and allows ADDITIVE keys. This file adds
  tests/golden/p141_scan_all13.json     canonical(<fixture>) for every dir under tests/fixtures, compared for FULL
                                        equality (no ADDITIVE allowance), with the same EXCLUDED keys dropped;
  tests/golden/p141_test_no_assert.json for every .py file under each fixture's tests/ dir, the exact return value
                                        of code_guardian.works.test_no_assert(rel, tree), plus the full
                                        works.test_no_assert findings the scan emits for that fixture.
canonical() is imported from test_golden, not copied; risky_repo is built by make_risky as test_golden does.
Regenerate both on purpose, from a commit whose scanner output you mean to record:

    python tests/test_p141_golden.py --record
"""
import ast
import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
import test_golden  # noqa: E402
from test_golden import canonical, dumps  # noqa: E402

from code_guardian import works  # noqa: E402

FIXTURES = HERE / "fixtures"
GOLDEN = HERE / "golden"
SCAN_GOLDEN = GOLDEN / "p141_scan_all13.json"
ASSERT_GOLDEN = GOLDEN / "p141_test_no_assert.json"
# the 13 fixtures recorded by P141 S0, by name: later fixture dirs (agent_risky, S11) are not part of this golden
ALL13 = ["backup_repo", "clean_repo", "complete_app", "complete_bare", "js_broken", "js_clean", "js_risky",
         "jsx_torture", "orphan_repo", "risky_repo", "supply_repo", "works_broken", "works_weak_tests"]


def _scan_all(tmp):
    return {name: canonical(test_golden._source(name, tmp)) for name in ALL13}


def _no_assert_all(tmp):
    out = {}
    for name in ALL13:
        src = Path(test_golden._source(name, Path(tmp) / "na"))
        direct = {}
        for d in sorted(p for p in src.rglob("tests") if p.is_dir()):
            for f in sorted(d.rglob("*.py")):
                rel = f.relative_to(src).as_posix()
                tree = ast.parse(f.read_bytes().replace(b"\r\n", b"\n").decode("utf-8"))
                direct[rel] = list(works.test_no_assert(rel, tree))
        emitted = [f for f in canonical(src).get("findings", []) if f.get("code") == "works.test_no_assert"]
        out[name] = {"direct": direct, "findings": emitted}
    return out


def test_fixture_list_is_the_thirteen():
    assert sorted(p.name for p in FIXTURES.iterdir() if p.is_dir() and p.name != "agent_risky") == ALL13
    assert ALL13 == ["backup_repo", "clean_repo", "complete_app", "complete_bare", "js_broken", "js_clean",
                     "js_risky", "jsx_torture", "orphan_repo", "risky_repo", "supply_repo", "works_broken",
                     "works_weak_tests"]


def test_scan_of_all_13_fixtures_is_identical(tmp_path):
    golden = json.loads(SCAN_GOLDEN.read_text(encoding="utf-8"))
    now = _scan_all(tmp_path)
    assert sorted(now) == sorted(golden)
    for name in golden:
        assert now[name] == golden[name], name


def test_test_no_assert_is_identical(tmp_path):
    golden = json.loads(ASSERT_GOLDEN.read_text(encoding="utf-8"))
    now = json.loads(json.dumps(_no_assert_all(tmp_path)))
    assert sorted(now) == sorted(golden)
    for name in golden:
        assert now[name] == golden[name], name


if __name__ == "__main__":
    if sys.argv[1:] != ["--record"]:
        sys.exit("usage: python tests/test_p141_golden.py --record")
    GOLDEN.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        SCAN_GOLDEN.write_text(dumps(_scan_all(tmp)), encoding="utf-8", newline="\n")
        ASSERT_GOLDEN.write_text(dumps(json.loads(json.dumps(_no_assert_all(tmp)))), encoding="utf-8", newline="\n")
    print("recorded", SCAN_GOLDEN.name, ASSERT_GOLDEN.name)
