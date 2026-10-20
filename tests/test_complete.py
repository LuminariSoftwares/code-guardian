"""Complete checks (does it have what it needs?): file presence plus basic parsing. Each check has a fixture that
triggers it and clean fixtures (a complete library and a complete app) that must not."""
import pytest
from conftest import FIXTURES

from code_guardian import complete, report


def found(rep, prefix=("complete.", "deps.declared_unused")):
    return sorted((f["code"], f["level"], f["node"]) for f in rep["findings"] if f["code"].startswith(prefix))


def test_bare_repo_triggers_every_complete_check():
    rep = report.scan(str(FIXTURES / "complete_bare"))
    assert found(rep) == [
        ("complete.ci_missing", "WARN", "."),
        ("complete.env_example", "WARN", "app.py:3"),
        ("complete.license_missing", "WARN", "."),
        ("complete.license_undeclared", "WARN", "pyproject.toml:1"),
        ("complete.lockfile", "WARN", "."),
        ("complete.metadata", "WARN", "pyproject.toml:1"),
        ("complete.readme_short", "WARN", "README.md:1"),
        ("deps.declared_unused", "INFO", "pyproject.toml:3"),
    ]


def test_bare_repo_hand_computed_scores():
    rep = report.scan(str(FIXTURES / "complete_bare"))
    rows = {(r["code"], r["level"]): r["deduction"] for r in rep["dimensions"]["complete"]["checks"]}
    # licence file 20, licence not declared 5, README short 10, CI 10, metadata 10, lockfile 10, .env.example 10
    assert rows == {("complete.license_missing", "WARN"): 20, ("complete.license_undeclared", "WARN"): 5,
                    ("complete.readme_short", "WARN"): 10, ("complete.ci_missing", "WARN"): 10,
                    ("complete.metadata", "WARN"): 10, ("complete.lockfile", "WARN"): 10,
                    ("complete.env_example", "WARN"): 10}
    s = rep["scores"]
    # Works: tests_missing 15 -> 85; Overall (500 + 255 + 50) / 10 = 80.5 -> 81
    assert (s["safe"], s["works"], s["complete"], s["overall"], s["grade"]) == (100, 85, 25, 81, "B")


def test_bare_repo_messages():
    rep = report.scan(str(FIXTURES / "complete_bare"))
    by_code = {f["code"]: f for f in rep["findings"]}
    assert by_code["complete.metadata"]["summary"] == "pyproject.toml [project] is missing: version, requires-python"
    assert by_code["complete.lockfile"]["evidence"] == ["application marker: Dockerfile",
                                                        "looked for: uv.lock, poetry.lock, Pipfile.lock, pdm.lock, "
                                                        "pixi.lock, requirements.lock, a fully pinned requirements.txt"]
    assert by_code["complete.env_example"]["evidence"][0] == "reads: BARE_TOKEN_NAME"
    assert by_code["deps.declared_unused"]["summary"] == "dependency requests is declared but never imported"


@pytest.mark.parametrize("name", ["clean_repo", "complete_app"])
def test_complete_fixtures_trigger_nothing(name):
    rep = report.scan(str(FIXTURES / name))
    assert found(rep) == []
    assert rep["scores"]["complete"] == 100


def test_complete_app_is_100_everywhere():
    s = report.scan(str(FIXTURES / "complete_app"))["scores"]
    assert (s["safe"], s["works"], s["complete"], s["overall"], s["grade"]) == (100, 100, 100, 100, "A")


def test_a_library_needs_no_lockfile():
    rep = report.scan(str(FIXTURES / "clean_repo"))  # [project] + scripts, no Dockerfile, no web app object
    assert not [f for f in rep["findings"] if f["code"] == "complete.lockfile"]


@pytest.mark.parametrize("files, app", [
    ({"Dockerfile": "FROM x\n"}, True),
    ({"pkg/__main__.py": "print(1)\n"}, True),
    ({"pkg/__main__.py": "print(1)\n", "pyproject.toml": '[project]\nname = "p"\n[project.scripts]\np = "pkg:m"\n'}, False),
    ({"web.py": "from fastapi import FastAPI\napi = FastAPI()\n"}, True),
    ({"proj/wsgi.py": "from django.core.wsgi import get_wsgi_application\napplication = get_wsgi_application()\n"}, True),
    ({"examples/demo.py": "from flask import Flask\napp = Flask(__name__)\n"}, False),
    ({"lib.py": "def f():\n    from flask import Flask\n    return Flask(__name__)\n"}, False),
])
def test_application_markers(tmp_path, files, app):
    files = dict(files, **{"src.py": "X = 1\n"})
    for rel, text in files.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(text, encoding="utf-8")
    rep = report.scan(str(tmp_path))
    assert any(f["code"] == "complete.lockfile" for f in rep["findings"]) is app


@pytest.mark.parametrize("lock", ["uv.lock", "poetry.lock", "Pipfile.lock", "pdm.lock", "requirements.txt"])
def test_any_lockfile_satisfies_an_app(tmp_path, lock):
    (tmp_path / "Dockerfile").write_text("FROM x\n", encoding="utf-8")
    (tmp_path / lock).write_text("flask==3.0.3 --hash=sha256:00\n" if lock.endswith(".txt") else "x\n", encoding="utf-8")
    rep = report.scan(str(tmp_path))
    assert not [f for f in rep["findings"] if f["code"] == "complete.lockfile"]


def test_loose_requirements_is_not_a_lockfile(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM x\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("flask==3.0.3\nrequests>=2\n", encoding="utf-8")
    assert [f["code"] for f in report.scan(str(tmp_path))["findings"] if f["code"] == "complete.lockfile"] == [
        "complete.lockfile"]


def test_env_example_only_when_env_is_read(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM x\n", encoding="utf-8")  # an application (the rule applies to apps only)
    (tmp_path / "a.py").write_text("import os\nprint(os.getcwd())\n", encoding="utf-8")
    (tmp_path / "test_a.py").write_text("import os\ndef test_x():\n    assert os.environ.get('CI') is None or True\n",
                                        encoding="utf-8")
    assert not [f for f in report.scan(str(tmp_path))["findings"] if f["code"] == "complete.env_example"]
    (tmp_path / "b.py").write_text("from os import getenv\nKEY = getenv('B_NAME')\n", encoding="utf-8")
    assert [f["node"] for f in report.scan(str(tmp_path))["findings"] if f["code"] == "complete.env_example"] == ["b.py:2"]
    for name in (".env.example", ".env.sample", ".env.template", "example.env"):
        (tmp_path / name).write_text("B_NAME=\n", encoding="utf-8")
        assert not [f for f in report.scan(str(tmp_path))["findings"] if f["code"] == "complete.env_example"], name
        (tmp_path / name).unlink()


@pytest.mark.parametrize("text, missing", [
    ("# x\n\n## Installation\n\n## Usage\n", []),
    ("x\n=\n\nGetting started\n---------------\n", []),                 # setext / rst headings; covers both
    ("# x\n\n## Install\n\n## API\n", ["usage"]),
    ("# x\n\n## Examples\n", ["install"]),
    ("# x\n\nSome text.\n", ["install", "usage"]),
])
def test_readme_sections(text, missing):
    assert complete.readme_missing_sections(text) == missing


def test_readme_sections_finding(tmp_path):
    (tmp_path / "README.md").write_text("# x\n\n" + "words " * 40 + "\n\n## Install\n\npip install x\n", encoding="utf-8")
    (tmp_path / "x.py").write_text("X = 1\n", encoding="utf-8")
    rep = report.scan(str(tmp_path))
    (f,) = [f for f in rep["findings"] if f["code"].startswith("complete.readme")]
    assert (f["code"], f["summary"]) == ("complete.readme_sections", "README has no usage section")


def test_no_readme_and_ci_variants(tmp_path):
    (tmp_path / "x.py").write_text("X = 1\n", encoding="utf-8")
    codes = {f["code"] for f in report.scan(str(tmp_path))["findings"]}
    assert "complete.readme_missing" in codes and "complete.ci_missing" in codes
    (tmp_path / ".gitlab-ci.yml").write_text("test:\n  script: [pytest]\n", encoding="utf-8")
    assert "complete.ci_missing" not in {f["code"] for f in report.scan(str(tmp_path))["findings"]}


def test_metadata_accepts_dynamic_version(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "p"\ndynamic = ["version"]\nrequires-python = ">=3.11"\n'
                                             'license = {text = "MIT"}\n', encoding="utf-8")
    (tmp_path / "p.py").write_text("X = 1\n", encoding="utf-8")
    codes = {f["code"] for f in report.scan(str(tmp_path))["findings"]}
    assert "complete.metadata" not in codes and "complete.license_undeclared" not in codes


def test_declared_unused_ignores_tools_and_counts_tests(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "p"\nversion = "1"\nrequires-python = ">=3.11"\n'
        'dependencies = ["PyYAML>=6,<7", "gunicorn>=21,<22", "types-requests", "attrs>=23,<24", "lonely>=1,<2"]\n',
        encoding="utf-8")
    (tmp_path / "p.py").write_text("import yaml\n", encoding="utf-8")
    (tmp_path / "test_p.py").write_text("import attr\ndef test_x():\n    assert attr\n", encoding="utf-8")
    rep = report.scan(str(tmp_path))
    assert [f["summary"] for f in rep["findings"] if f["code"] == "deps.declared_unused"] == [
        "dependency lonely is declared but never imported"]


def test_empty_repo_is_perfect_and_says_why(tmp_path):
    rep = report.scan(str(tmp_path))
    s = rep["scores"]
    # v0.3: nothing to judge is an INVALID scan, which has no grade (v0.2 graded it A); 0.3.2: no Python source, so
    # Works is not scored (None) rather than 100
    assert (s["safe"], s["works"], s["complete"], s["overall"], s["grade"]) == (100, None, 100, 100, None)
    assert rep["status"] == "INVALID"
    assert rep["findings"] == []
    assert any("no Python source or manifest" in n for n in rep["notes"])
