"""P141 S12: works.test_hollow -- tests that assert, but cannot fail (tautology, mock-only, swallowed exception).

The sample test file is built here, in a temporary repo, and not stored under tests/fixtures: a stored test file in
works_broken or works_weak_tests would change those fixtures' frozen goldens."""
import ast
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from code_guardian import catalogue, hollow as hollow_mod, report, score, works  # noqa: E402

SAMPLE = '''import unittest
from unittest import mock
from unittest.mock import MagicMock, patch


def test_tautology_true():
    assert True


def test_tautology_one():
    assert 1


def test_tautology_same():
    x = 3
    assert x == x


def test_mock_only():
    m = MagicMock()
    m.run(1)
    assert m.run.called
    assert len(m.run.mock_calls) == 1


def test_mock_with_real_assert():
    m = MagicMock()
    m.run(1)
    assert m.run.called
    assert int("4") == 4


@patch("os.getcwd")
def test_patch_decorator_only_mock(getcwd):
    getcwd.return_value = "x"
    assert getcwd() == "x"


def test_with_patch():
    with mock.patch("os.getcwd") as g:
        g()
    g.assert_called_once()


def test_swallowed_bare():
    try:
        int("x")
    except:
        pass
    assert 1 + 1 == 2


def test_swallowed_exception():
    try:
        int("x")
    except Exception:
        pass
    assert int("1") == 1


def test_narrow_except_is_fine():
    try:
        int("x")
    except ValueError:
        pass
    assert int("2") == 2


def test_real():
    assert int("4") + 1 == 5


def test_silent_and_hollow():
    try:
        int("x")
    except Exception:
        pass


class T(unittest.TestCase):
    def test_assert_true_true(self):
        self.assertTrue(True)

    def test_real_method(self):
        self.assertEqual(int("2"), 2)
'''


def hollow(text=SAMPLE):
    return hollow_mod.test_hollow("tests/test_x.py", ast.parse(text))


def scan(tmp_path, text):
    (tmp_path / "pkg").mkdir(exist_ok=True)
    (tmp_path / "pkg" / "__init__.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    (tmp_path / "tests").mkdir(exist_ok=True)
    (tmp_path / "tests" / "test_x.py").write_text(text, encoding="utf-8")
    return report.scan(str(tmp_path))["findings"]


def test_kinds_and_names():
    first, total, kinds = hollow()
    assert set(kinds) == {"tautology", "mock_only", "swallowed"}
    assert kinds["tautology"] == ["test_tautology_true", "test_tautology_one", "test_tautology_same",
                                  "T.test_assert_true_true"]
    assert kinds["mock_only"] == ["test_mock_only", "test_patch_decorator_only_mock", "test_with_patch"]
    assert kinds["swallowed"] == ["test_swallowed_bare", "test_swallowed_exception"]
    assert first == SAMPLE.splitlines().index("def test_tautology_true():") + 1
    assert total == works.test_no_assert("tests/test_x.py", ast.parse(SAMPLE))[1] == 14


def test_real_and_narrow_tests_are_clean():
    named = {n for v in hollow()[2].values() for n in v}
    for name in ("test_real", "T.test_real_method", "test_mock_with_real_assert", "test_narrow_except_is_fine"):
        assert name not in named


def test_silent_test_is_reported_once_by_test_no_assert():
    named = {n for v in hollow()[2].values() for n in v}
    assert "test_silent_and_hollow" not in named
    assert "test_silent_and_hollow" in works.test_no_assert("tests/test_x.py", ast.parse(SAMPLE))[2]


def test_one_kind_per_test_in_order():
    text = "def test_both():\n    assert True\n    try:\n        pass\n    except Exception:\n        pass\n"
    _, _, kinds = hollow(text)
    assert kinds == {"tautology": ["test_both"], "mock_only": [], "swallowed": []}


def test_no_hollow_is_zero():
    assert hollow("def test_ok():\n    assert sum([1, 2]) == 3\n") == (
        0, 1, {"tautology": [], "mock_only": [], "swallowed": []})


def test_scan_emits_one_warn_per_file_with_counts(tmp_path):
    found = [f for f in scan(tmp_path, SAMPLE) if f["code"] == "works.test_hollow"]
    assert len(found) == 1 and found[0]["level"] == "WARN"
    assert "tautology 4, mock-only 3, swallowed 2" in found[0]["summary"]
    assert any(e.startswith("tautology: ") for e in found[0]["evidence"])
    silent = [f for f in scan(tmp_path, SAMPLE) if f["code"] == "works.test_no_assert"]
    assert len(silent) == 1 and "test_silent_and_hollow" in " ".join(silent[0]["evidence"])


def test_clean_file_has_no_hollow_finding(tmp_path):
    assert not [f for f in scan(tmp_path, "def test_ok():\n    assert sum([1, 2]) == 3\n")
                if f["code"] == "works.test_hollow"]


def test_weight_and_catalogue():
    assert score.TABLES["works"][("works.test_hollow", "WARN")] == 5
    assert catalogue.CATALOGUE["works.test_hollow"]["fix"]


def test_module_selftest_prints_the_counted_line():
    import re
    import subprocess
    r = subprocess.run([sys.executable, "-m", "code_guardian.hollow", "--selftest"], capture_output=True, text=True,
                       timeout=180, cwd=str(HERE.parent))
    assert r.returncode == 0, r.stdout + r.stderr
    m = re.fullmatch(r"hollow selftest: (\d+) checks, (\d+) passed, 0 failed", r.stdout.strip().splitlines()[-1])
    assert m and m.group(1) == m.group(2) and int(m.group(1)) > 0
