"""Invented-package checks: offline against the bundled hand-built name list, online (opt-in) against PyPI.
The online tests use a stub PyPI on loopback; nothing here reaches the real network."""
import datetime
import gzip
import json

import pytest
from conftest import FIXTURES

from code_guardian import report, supply

TODAY = datetime.date.today()


def found(rep):
    return sorted((f["code"], f["level"], f["node"], f["evidence"][0]) for f in rep["findings"] if f["code"].startswith("supply."))


def test_offline_lookalike_and_unknown():
    rep = report.scan(str(FIXTURES / "supply_repo"))
    assert found(rep) == [
        ("supply.lookalike", "WARN", "app/__init__.py:1", "name: pandaz"),
        ("supply.lookalike", "WARN", "pyproject.toml:6", "name: reqeusts"),
        ("supply.unknown_package", "INFO", "pyproject.toml:6", "name: flask-gpt-helperz"),
    ]
    by_name = {f["evidence"][0]: f for f in rep["findings"] if f["code"].startswith("supply.")}
    assert by_name["name: reqeusts"]["summary"] == "reqeusts is one or two letters away from the popular package requests"
    assert by_name["name: flask-gpt-helperz"]["summary"] == (
        "flask-gpt-helperz is not in the offline list of known packages; run with --online to check it exists")


def test_offline_scores():
    rep = report.scan(str(FIXTURES / "supply_repo"))
    rows = {(r["code"], r["level"]): (r["count"], r["deduction"]) for r in rep["dimensions"]["safe"]["checks"]}
    assert rows == {("supply.lookalike", "WARN"): (2, 19)}  # 15 + ceil(15/4)
    assert rep["scores"]["safe"] == 81


@pytest.mark.parametrize("name", ["clean_repo", "complete_app", "orphan_repo", "works_broken"])
def test_known_dependencies_trigger_nothing(name):
    assert found(report.scan(str(FIXTURES / name))) == []


def release(days_ago, files=1):
    when = (TODAY - datetime.timedelta(days=days_ago)).isoformat() + "T00:00:00Z"
    return [{"upload_time_iso_8601": when}] * files


def test_online_answers(stub):
    pypi = stub({
        ("GET", "/pypi/flask-gpt-helperz/json"): (404, {"message": "Not Found"}, 0),
        ("GET", "/pypi/reqeusts/json"): (200, {"info": {"name": "reqeusts"}, "releases": {"1.0": release(400)}}, 0),
        ("GET", "/pypi/pandaz/json"): (200, {"info": {"name": "pandaz"},
                                             "releases": {"0.1": release(900), "0.2": release(700), "0.3": []}}, 0),
    })
    rep = report.scan(str(FIXTURES / "supply_repo"), online=True, env={"CODE_GUARDIAN_PYPI_URL": pypi.url + "/pypi"})
    assert found(rep) == [
        ("supply.lookalike", "WARN", "app/__init__.py:1", "name: pandaz"),
        ("supply.lookalike", "WARN", "pyproject.toml:6", "name: reqeusts"),
        ("supply.unknown_package", "FAIL", "pyproject.toml:6", "name: flask-gpt-helperz"),
        ("supply.unknown_package", "WARN", "pyproject.toml:6", "name: reqeusts"),
    ]
    by = {(f["code"], f["evidence"][0]): f for f in rep["findings"] if f["code"].startswith("supply.")}
    assert by[("supply.unknown_package", "name: flask-gpt-helperz")]["summary"] == (
        "flask-gpt-helperz does not exist on PyPI (likely invented by an AI assistant; anyone could register this name)")
    assert by[("supply.unknown_package", "name: reqeusts")]["summary"] == (
        "reqeusts is a new or single-release package; check it is the one you meant")
    assert sorted(pypi.paths()) == ["/pypi/flask-gpt-helperz/json", "/pypi/pandaz/json", "/pypi/reqeusts/json"]
    assert rep["scores"]["grade"] == "D"  # a Safe FAIL caps the grade


def test_online_new_package_and_cache(stub):
    pypi = stub({("GET", "/pypi/flask-gpt-helperz/json"): (200, {"releases": {"0.1": release(10), "0.2": release(5)}}, 0),
                 ("GET", "/pypi/reqeusts/json"): (200, {"releases": {"1.0": release(400), "1.1": release(300)}}, 0),
                 ("GET", "/pypi/pandaz/json"): (200, {"releases": {"1.0": release(400), "1.1": release(300)}}, 0)})
    rep = report.scan(str(FIXTURES / "supply_repo"), online=True, env={"CODE_GUARDIAN_PYPI_URL": pypi.url + "/pypi"})
    unknown = [(f["level"], f["evidence"][0]) for f in rep["findings"] if f["code"] == "supply.unknown_package"]
    assert unknown == [("WARN", "name: flask-gpt-helperz")]  # first release 10 days ago
    assert len(pypi.paths()) == 3  # one request per name, cached for the run


def test_online_timeout_is_reported_not_fatal(stub):
    pypi = stub({("GET", "/pypi/flask-gpt-helperz/json"): (200, {"releases": {}}, 3)})
    rep = report.scan(str(FIXTURES / "supply_repo"), online=True,
                      env={"CODE_GUARDIAN_PYPI_URL": pypi.url + "/pypi", "CODE_GUARDIAN_PYPI_TIMEOUT": "0.5"})
    unknown = [(f["level"], f["evidence"][0]) for f in rep["findings"] if f["code"] == "supply.unknown_package"]
    assert ("INFO", "name: flask-gpt-helperz") in unknown
    assert any(n.startswith("online check: could not check flask-gpt-helperz on PyPI") for n in rep["notes"])


def test_offline_makes_no_request(stub):
    pypi = stub({})
    report.scan(str(FIXTURES / "supply_repo"), env={"CODE_GUARDIAN_PYPI_URL": pypi.url + "/pypi"})
    assert pypi.paths() == []


@pytest.mark.parametrize("a, b, d", [
    ("requests", "requests", 0), ("reqeusts", "requests", 1), ("requets", "requests", 1), ("requestss", "requests", 1),
    ("reqursts", "requests", 1), ("rqeuests", "requests", 1), ("numpyy", "numpy", 1), ("nunpi", "numpy", 2),
    ("django", "flask", 3),
])
def test_distance(a, b, d):
    assert supply.distance(a, b, limit=2) == min(d, 3)


@pytest.mark.parametrize("name, near", [
    ("reqeusts", "requests"), ("pandaz", "pandas"), ("djnago", "django"), ("beautifulsoup5", "beautifulsoup4"),
    ("requests", None), ("six", None), ("sixx", None), ("pandas-stubs-x", None), ("flask-gpt-helperz", None),
])
def test_lookalike(name, near):
    assert supply.lookalike(name, supply.known_names()) == near


def test_snapshot_is_bundled_sorted_and_reproducible(tmp_path):
    names = supply.known_names()
    assert 900 <= len(names) <= 20000 and {"requests", "numpy", "flask", "pyyaml", "python-dateutil"} <= names
    import subprocess
    import sys
    from conftest import ROOT
    raw = (ROOT / "code_guardian" / "data" / "known_packages.txt.gz").read_bytes()
    lines = gzip.decompress(raw).decode().splitlines()
    assert lines[0].startswith("# code-guardian known PyPI projects: hand-built")
    assert lines[1:] == sorted(lines[1:]) and len(set(lines[1:])) == len(lines) - 1
    r = subprocess.run([sys.executable, str(ROOT / "tools" / "build_known_packages.py")], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert (ROOT / "code_guardian" / "data" / "known_packages.txt.gz").read_bytes() == raw  # same input, same bytes
