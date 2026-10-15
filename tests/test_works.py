"""Works checks (will it work?): each has a fixture that triggers it and a clean fixture that must not."""
import ast

import pytest
from conftest import FIXTURES

from code_guardian import report, works

WORKS_CODES = {"works.syntax", "works.import_unresolved", "works.relative_missing", "works.tests_missing",
               "works.test_no_assert", "works.entry_missing"}


def works_findings(name):
    rep = report.scan(str(FIXTURES / name))
    return rep, [(f["code"], f["level"], f["node"]) for f in rep["findings"] if f["code"].startswith("works.")]


def test_broken_repo_triggers_each_check_once_at_its_place():
    rep, found = works_findings("works_broken")
    assert sorted(found) == sorted([
        ("works.tests_missing", "WARN", "."),
        ("works.syntax", "FAIL", "brokenpkg/legacy.py:1"),
        ("works.import_unresolved", "WARN", "brokenpkg/cli.py:3"),
        ("works.relative_missing", "FAIL", "brokenpkg/cli.py:9"),
        ("works.entry_missing", "FAIL", "pyproject.toml:9"),
        ("works.entry_missing", "FAIL", "pyproject.toml:10"),
    ])


def test_broken_repo_hand_computed_works_score():
    rep, _ = works_findings("works_broken")
    rows = {(r["code"], r["level"]): r["deduction"] for r in rep["dimensions"]["works"]["checks"]}
    # syntax 30, relative 25, entry_missing 30 + ceil(30/4)=8, import 10, tests_missing 15
    assert rows == {("works.syntax", "FAIL"): 30, ("works.relative_missing", "FAIL"): 25,
                    ("works.entry_missing", "FAIL"): 38, ("works.import_unresolved", "WARN"): 10,
                    ("works.tests_missing", "WARN"): 15}
    s = rep["scores"]
    # Complete: no licence 20, no README 20, no CI 10, licence undeclared 5 -> 45; Overall (500 + 0 + 90) / 10 = 59
    assert (s["safe"], s["works"], s["complete"], s["overall"], s["grade"]) == (100, 0, 45, 59, "D")
    assert s["capped"] is False  # Works FAILs never cap: only Safe does


def test_unresolved_import_names_the_module_and_skips_guarded_ones():
    rep, _ = works_findings("works_broken")
    summaries = [f["summary"] for f in rep["findings"] if f["code"] == "works.import_unresolved"]
    assert summaries == ["import numpy: not in the standard library, the repo, or a declared dependency"]
    # requests, yaml (PyYAML), dateutil (python-dateutil) are declared; ujson (try/except ImportError) and pandas
    # (if TYPE_CHECKING) are guarded


def test_syntax_error_reports_line_and_still_gets_the_secret_scan():
    rep, _ = works_findings("works_broken")
    (f,) = [f for f in rep["findings"] if f["code"] == "works.syntax"]
    assert f["node"] == "brokenpkg/legacy.py:1" and "SyntaxError" in f["evidence"][0]
    assert not any(f["code"] == "parse.skipped" for f in rep["findings"])


def test_entry_missing_says_which_part_is_missing():
    rep, _ = works_findings("works_broken")
    summaries = sorted(f["summary"] for f in rep["findings"] if f["code"] == "works.entry_missing")
    assert summaries == ["script 'ghost' points at brokenpkg.missing:run, but module brokenpkg.missing is not in the repo",
                         "script 'nofunc' points at brokenpkg.cli:nope, but brokenpkg.cli defines no nope"]


def test_weak_tests_reported_once_per_file_with_count():
    rep, found = works_findings("works_weak_tests")
    assert found == [("works.test_no_assert", "WARN", "tests/test_add.py:12")]
    (f,) = [f for f in rep["findings"] if f["code"] == "works.test_no_assert"]
    assert f["summary"] == "3 of 7 test functions in this file make no assertion"
    assert f["evidence"] == ["without an assertion: test_runs, test_nothing, TestAdd.test_silent"]
    assert rep["scores"]["works"] == 95


@pytest.mark.parametrize("name", ["clean_repo", "orphan_repo"])
def test_clean_fixtures_trigger_no_works_check(name):
    _, found = works_findings(name)
    assert found == []


def test_orphans_fold_into_works_at_a_low_weight():
    rep = report.scan(str(FIXTURES / "orphan_repo"))
    rows = {(r["code"], r["level"]): (r["count"], r["deduction"]) for r in rep["dimensions"]["works"]["checks"]}
    assert rows == {("orphan.dead", "WARN"): (1, 3)}
    assert rep["scores"]["works"] == 97 and rep["scores"]["safe"] == 100
    assert not any(f["code"].startswith("orphan.") for f in rep["findings"])  # still reported under hygiene only


def test_no_orphan_deduction_without_entry_points(tmp_path):
    (tmp_path / "a.py").write_text("def unused():\n    pass\n", encoding="utf-8")
    (tmp_path / "test_a.py").write_text("def test_x():\n    assert True\n", encoding="utf-8")
    rep = report.scan(str(tmp_path))
    assert rep["hygiene"]["entry_points"] == [] and rep["dimensions"]["works"]["checks"] == []


@pytest.mark.parametrize("module, declared, resolved", [
    ("yaml", {"pyyaml"}, True), ("PIL", {"Pillow"}, True), ("cv2", {"opencv-python-headless"}, True),
    ("sklearn", {"scikit-learn"}, True), ("bs4", {"beautifulsoup4"}, True), ("dateutil", {"python-dateutil"}, True),
    ("typing_extensions", {"typing-extensions"}, True), ("google", {"google-cloud-storage"}, True),
    ("ruamel", {"ruamel.yaml"}, True), ("Flask", {"flask"}, True), ("numpy", {"pandas"}, False),
    ("yaml", set(), False),
])
def test_import_to_distribution_mapping(module, declared, resolved):
    assert works.import_declared(module, {works.normalise(d) for d in declared}) is resolved


def test_stdlib_set_is_interpreter_independent():
    for name in ("distutils", "imp", "asyncore", "tomllib", "os", "winreg", "msvcrt"):
        assert name in works.STDLIB


def test_relative_import_to_a_compiled_or_stub_module_is_not_missing(tmp_path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("from ._speedups import fast\nfrom ._typed import T\nfrom . import sub\n",
                                     encoding="utf-8")
    (pkg / "_speedups.c").write_text("/* C */\n", encoding="utf-8")
    (pkg / "_typed.pyi").write_text("T = int\n", encoding="utf-8")
    (pkg / "sub").mkdir()
    (pkg / "sub" / "__init__.py").write_text("", encoding="utf-8")
    rep = report.scan(str(tmp_path))
    assert not [f for f in rep["findings"] if f["code"] == "works.relative_missing"]


def test_relative_name_bound_in_package_init_is_not_missing(tmp_path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("VERSION = '1'\ndef helper():\n    pass\n", encoding="utf-8")
    (pkg / "mod.py").write_text("from . import VERSION, helper\nfrom . import nothing_here\n", encoding="utf-8")
    rep = report.scan(str(tmp_path))
    assert [(f["code"], f["node"]) for f in rep["findings"] if f["code"] == "works.relative_missing"] == [
        ("works.relative_missing", "pkg/mod.py:2")]


def test_newer_syntax_than_the_scanner_is_not_a_fail(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\nversion = "1"\nrequires-python = ">=3.99"\n',
                                             encoding="utf-8")
    (tmp_path / "new.py").write_text("print 'not parseable here'\n", encoding="utf-8")
    rep = report.scan(str(tmp_path))
    assert [(f["code"], f["level"]) for f in rep["findings"] if f["code"].startswith("works.syntax")] == [
        ("works.syntax", "INFO")]


def test_test_tools_in_test_files_need_no_declaration():
    tree = ast.parse("import pytest\nimport hypothesis\n")
    assert works.unresolved_imports("tests/test_x.py", tree, set(), set()) == []
    assert [m for _, m in works.unresolved_imports("pkg/x.py", tree, set(), set())] == ["pytest", "hypothesis"]


def test_fallback_import_in_except_importerror_is_guarded():
    tree = ast.parse("try:\n    from . import core as sg_core\nexcept ImportError:\n    import sg_core\n"
                     "try:\n    import tomllib\nexcept ModuleNotFoundError:\n    import tomli as tomllib\n")
    assert works.unresolved_imports("pkg/cli.py", tree, set(), set()) == []


def test_names_registered_in_sys_modules_count_as_local(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "__init__.py").write_text("import sys\nfrom . import finding\n"
                                                  "sys.modules.setdefault('sg_finding', finding)\n"
                                                  "sys.modules['sg_extra'] = finding\n", encoding="utf-8")
    (tmp_path / "pkg" / "finding.py").write_text("X = 1\n", encoding="utf-8")
    (tmp_path / "plugin.py").write_text("import sg_finding\nimport sg_extra\nimport sg_unknown\n", encoding="utf-8")
    rep = report.scan(str(tmp_path))
    assert [f["summary"].split(":")[0] for f in rep["findings"] if f["code"] == "works.import_unresolved"] == [
        "import sg_unknown"]
