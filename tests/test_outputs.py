"""SARIF 2.1.0 and Markdown outputs, the composite GitHub Action and the pre-commit hook."""
import json
import os
import re
import subprocess
import sys

import pytest

import make_risky
from conftest import FIXTURES, ROOT

from code_guardian import catalogue, outputs, report, score

LEVEL = {"FAIL": "error", "WARN": "warning", "INFO": "note"}


@pytest.fixture(scope="module")
def risky(tmp_path_factory):
    return report.scan(str(make_risky.build(tmp_path_factory.mktemp("r") / "risky_repo")))


def all_codes():
    codes = {c for table in score.TABLES.values() for c, _ in table}
    return codes | {"orphan.test_only", "orphan.uncertain", "check.crashed"}


def test_every_check_code_has_a_catalogue_entry():
    assert set(catalogue.CATALOGUE) == all_codes()
    for code, entry in catalogue.CATALOGUE.items():
        assert set(entry) == {"title", "means", "fix", "false_positives"}, code
        assert all(isinstance(v, str) and v.strip() for v in entry.values()), code


def test_sarif_shape(risky):
    s = outputs.to_sarif(risky)
    assert s["version"] == "2.1.0" and s["$schema"].endswith("sarif-schema-2.1.0.json")
    (run,) = s["runs"]
    rules = run["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == sorted(all_codes())  # one rule per check code
    assert run["tool"]["driver"]["name"] == "code-guardian"
    results = run["results"]
    assert len(results) == len(risky["findings"]) + len(risky["hygiene"]["findings"])
    for res in results:
        assert rules[res["ruleIndex"]]["id"] == res["ruleId"]
        loc = res["locations"][0]["physicalLocation"]
        uri = loc["artifactLocation"]["uri"]
        assert uri and not uri.startswith(("/", "file:")) and ":" not in uri and "\\" not in uri
        if "region" in loc:
            assert loc["region"]["startLine"] >= 1
    assert run["properties"]["scores"] == risky["scores"]


def test_sarif_levels_and_locations(risky):
    results = outputs.to_sarif(risky)["runs"][0]["results"]
    by = {(r["ruleId"], r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
           r["locations"][0]["physicalLocation"].get("region", {}).get("startLine")): r for r in results}
    tls = by[("tls.off", "risky/network.py", 11)]
    assert tls["level"] == "error" and tls["message"]["text"].startswith("TLS certificate checking is switched off")
    assert by[("works.tests_missing", "pyproject.toml", None)]["level"] == "warning"  # repo-level: anchored, no region
    assert by[("deps.unpinned", "package.json", 8)]["level"] == "note"


def test_sarif_security_metadata(risky):
    rules = {r["id"]: r for r in outputs.to_sarif(risky)["runs"][0]["tool"]["driver"]["rules"]}
    assert rules["secret.key"]["properties"]["security-severity"] == "8.0"
    assert rules["secret.key"]["defaultConfiguration"]["level"] == "error"
    assert "security" in rules["secret.key"]["properties"]["tags"]
    assert "security-severity" not in rules["works.syntax"]["properties"]
    assert rules["complete.readme_missing"]["properties"]["tags"] == ["complete"]
    assert rules["secret.key"]["helpUri"].endswith("#check-catalogue")


def test_sarif_is_valid_against_the_schema(risky):
    schema_path = os.environ.get("CODE_GUARDIAN_SARIF_SCHEMA")
    jsonschema = pytest.importorskip("jsonschema")
    if not schema_path:
        pytest.skip("set CODE_GUARDIAN_SARIF_SCHEMA to the SARIF 2.1.0 schema file (the CI sarif job does)")
    with open(schema_path, encoding="utf-8") as fh:
        schema = json.load(fh)
    validator = jsonschema.Draft4Validator(schema)
    for sarif in (outputs.to_sarif(risky), outputs.to_sarif(report.scan(str(FIXTURES / "clean_repo")))):
        assert [e.message for e in validator.iter_errors(sarif)] == []


def test_markdown(risky):
    md = outputs.to_markdown(risky)
    assert md.startswith("# code-guardian: risky_repo\n")
    assert "| **Safe** | 0/100 | is it safe to run? |" in md
    assert "| **Overall** | 33/100 | grade **F** |" in md
    assert "## Biggest deductions" in md and "| -60 | Safe | `secret.key` FAIL | 3 | `deploy/id_rsa:1` |" in md
    assert "### Safe" in md and "### Works" in md and "### Complete" in md and "## Hygiene" in md
    assert "| FAIL | `tls.off` | `risky/network.py:11` |" in md
    assert "## Weights used" in md


def test_markdown_escapes_pipes():
    f = {"code": "x.y", "level": "WARN", "node": "a|b.py:1", "summary": "one | two"}
    assert outputs._row(f) == "| WARN | `x.y` | `a\\|b.py:1` | one \\| two |"


def test_outputs_are_byte_identical_across_runs(tmp_path):
    path = str(make_risky.build(tmp_path / "risky_repo"))
    a, b = report.scan(path), report.scan(path)
    assert json.dumps(outputs.to_sarif(a), sort_keys=True) == json.dumps(outputs.to_sarif(b), sort_keys=True)
    assert outputs.to_markdown(a) == outputs.to_markdown(b)


def cli(*args):
    return subprocess.run([sys.executable, "-m", "code_guardian", *map(str, args)], capture_output=True, text=True,
                          timeout=120)


def test_cli_formats_and_exit_codes(tmp_path):
    path = make_risky.build(tmp_path / "risky_repo")
    sarif = cli("scan", path, "--sarif")
    assert sarif.returncode == 1 and json.loads(sarif.stdout)["version"] == "2.1.0"
    md = cli("scan", FIXTURES / "clean_repo", "--markdown")
    assert md.returncode == 0 and md.stdout.startswith("# code-guardian: clean_repo")
    assert cli("scan", FIXTURES / "clean_repo", "--sarif", "--json").returncode == 2
    assert cli("scan", FIXTURES / "clean_repo", "--sarif", "--markdown").returncode == 2


def test_action_is_composite_and_never_interpolates_inputs_into_shell():
    text = (ROOT / "action.yml").read_text(encoding="utf-8")
    assert re.search(r"(?m)^  using: ['\"]?composite", text)
    for name in ("path", "fail-on", "online", "sarif-file", "upload-sarif"):
        assert re.search(r"(?m)^  %s:\n" % re.escape(name), text), name
    assert "github/codeql-action/upload-sarif@" in text
    assert "${{ github.action_path }}" in text  # installs the action's own checkout, not PyPI
    run_blocks = re.findall(r"(?ms)^      run: \|\n(.*?)(?=^    - |\Z)", text)
    assert run_blocks
    for block in run_blocks:
        assert "${{" not in block, block  # inputs reach the shell only through env:


def test_pre_commit_hook():
    text = (ROOT / ".pre-commit-hooks.yaml").read_text(encoding="utf-8")
    assert re.search(r"(?m)^- id: code-guardian$", text)
    assert re.search(r"(?m)^  entry: code-guardian scan \.", text)
    assert re.search(r"(?m)^  language: python$", text)
    assert re.search(r"(?m)^  pass_filenames: false$", text) and re.search(r"(?m)^  always_run: true$", text)
