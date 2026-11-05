"""P93 S1 acceptance -- code-guardian 0.4.2: an offered copy reports exactly what its glob leaves out, releases publish
by trusted publishing, version 0.4.2.

Written by the overseer BEFORE the build session. The build session must add this file to the PR byte-for-byte and
must not edit it; a PR that changes it fails the section. Pure ASCII on purpose; no key-shaped value anywhere.

Why (P88 S5 calibration on a real folder, 2026-10-24): the page offered `*.backup-*` as 48 files, but leaving it out
skipped 177, because `offer` grouped files by `looks_like_backup` (a file inside another backup-looking folder went to
that folder's group) while `--exclude` drops every path the glob matches; and a mark glob such as `*.pre-*` also drops
dot files like `.pre-commit-config.yaml` (fnmatch's `*` matches nothing), whose findings were never counted or checked
for a risk that runs code. 0.4.1 counted findings right on that folder; the file counts and the dot-file case were not.

Contract (P93 C1), backups.offer(findings, inventory, graph=None, texts=None) -> (offered, held), unchanged shape:
  - Candidate globs: looks_like_backup() of every finding's file (as in 0.4.1).
  - Order the candidates: folder globs ("<dir>/*") before mark globs ("*...*"); within each kind, the one whose glob
    drops more findings first, then the glob text.
  - Walk the candidates in that order. Every inventory path (python, manifests, other, skipped) and every finding is
    ATTRIBUTED to the first candidate whose glob drops it, with the walk's own rule (walk._excluded(rel, (glob,))).
  - A candidate's "files", "findings", "by_code" and "fail" count what is attributed to it; the held check (imports,
    install.hook at any level, obfuscation / exec.dynamic / exec.shell at FAIL) looks at its attributed findings, so a
    risky dot file that a mark glob would drop holds that glob back. A candidate with no attributed finding is neither
    offered nor held.
  - The returned "offered" list is sorted by attributed findings, most first, then by glob.
  So leaving out every offered glob drops exactly the offered findings, no more and no fewer.

Release (P93 C2): `.github/workflows/release.yml` publishes to PyPI by trusted publishing when a GitHub Release is
published (the route proven on tool-guardian): third-party actions pinned to full commit SHAs, top-level permissions
`contents: read`, `id-token: write` only on the publishing job, which runs in environment `pypi` with
pypa/gh-action-pypi-publish and `attestations: true`; the build job runs `python -m build` and
`twine check --strict`; the tag must equal "v" + pyproject's version; pull requests and manual runs (dry_run) build
and check without publishing; no stored registry token anywhere. `docs/RELEASING.md` names the PyPI trusted-publisher
fields: owner LuminariSoftwares, repository code-guardian, workflow release.yml, environment pypi.
"""
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"


def inventory(**kw):
    inv = {"python": [], "manifests": [], "other": [], "skipped": [], "excluded": 0, "ignored": 0}
    inv.update(kw)
    for k in ("python", "manifests", "other"):
        inv[k] = sorted(inv[k])
    return inv


def finding(code, level, node):
    return {"code": code, "level": level, "node": node}


def _offer(findings, inv):
    from code_guardian import backups
    return backups.offer(findings, inv)


def _folder_and_marks():
    inv = inventory(python=["app/main.py", "_archive/a.py", "_archive/b.py.backup-1", "src/x.py.backup-2",
                            "tmp_old/y.py.backup-3"],
                    other=[".pre-commit-config.yaml", "z.py.pre-fix-20261024", "notes.txt"])
    fs = [finding("secret.key", "FAIL", "_archive/a.py:1"),
          finding("secret.key", "FAIL", "_archive/b.py.backup-1:1"),
          finding("secret.key", "FAIL", "src/x.py.backup-2:1"),
          finding("secret.key", "FAIL", "z.py.pre-fix-20261024:1"),
          finding("deps.unpinned", "INFO", ".pre-commit-config.yaml:3"), finding("exec.shell", "WARN", "app/main.py:2")]
    return fs, inv


def test_each_path_and_finding_is_counted_once_under_the_glob_that_drops_it():
    fs, inv = _folder_and_marks()
    offered, held = _offer(fs, inv)
    assert held == [], held
    got = [(g["glob"], g["files"], g["findings"]) for g in offered]
    # _archive/* (a folder glob) goes first and takes both files inside it, the .backup-1 one included;
    # *.backup-* takes src/x and tmp_old/y (tmp_old/* has no finding, so it is no candidate);
    # *.pre-* takes the dated copy AND the dot file it also drops.
    assert got == [("*.pre-*", 2, 2), ("_archive/*", 2, 2), ("*.backup-*", 2, 1)], got


def test_leaving_out_the_offered_globs_drops_exactly_the_offered_findings():
    from code_guardian import walk
    fs, inv = _folder_and_marks()
    offered, _ = _offer(fs, inv)
    globs = tuple(g["glob"] for g in offered)
    dropped = [f for f in fs if walk._excluded(f["node"].rpartition(":")[0], globs)]
    assert len(dropped) == sum(g["findings"] for g in offered)
    paths = inv["python"] + inv["manifests"] + inv["other"]
    assert len([p for p in paths if walk._excluded(p, globs)]) == sum(g["files"] for g in offered)


def test_by_code_and_fail_count_the_attributed_findings():
    fs, inv = _folder_and_marks()
    offered, _ = _offer(fs, inv)
    pre = [g for g in offered if g["glob"] == "*.pre-*"][0]
    assert pre["by_code"] == {"deps.unpinned INFO": 1, "secret.key FAIL": 1}, pre["by_code"]
    assert pre["fail"] == 1


def test_a_risky_dot_file_a_mark_glob_would_drop_holds_it_back():
    inv = inventory(python=["app/main.py"], other=[".pre-commit-config.yaml", "z.py.pre-fix-20261024"])
    fs = [finding("secret.key", "FAIL", "z.py.pre-fix-20261024:1"),
          finding("install.hook", "WARN", ".pre-commit-config.yaml:1")]
    offered, held = _offer(fs, inv)
    assert offered == [] and [h["glob"] for h in held] == ["*.pre-*"], (offered, held)
    assert ".pre-commit-config.yaml" in held[0]["why"], held[0]["why"]


def test_files_in_a_folder_with_no_finding_count_under_the_mark_glob_that_drops_them():
    inv = inventory(python=["app/main.py", "src/y.py.backup-1"],
                    other=["_backups/x.py.backup-9", "_backups/w.py.backup-8"])
    fs = [finding("secret.key", "FAIL", "src/y.py.backup-1:1")]
    offered, _ = _offer(fs, inv)
    assert [(g["glob"], g["files"], g["findings"]) for g in offered] == [("*.backup-*", 3, 1)], offered


def test_a_single_folder_copy_is_unchanged_from_041():
    inv = inventory(python=["app/main.py", "_archive/a.py", "_archive/b.py"])
    fs = [finding("secret.key", "FAIL", "_archive/a.py:1"), finding("secret.key", "FAIL", "_archive/b.py:2")]
    offered, held = _offer(fs, inv)
    assert held == [] and [(g["glob"], g["files"], g["findings"]) for g in offered] == [("_archive/*", 2, 2)]


# ---- C2: trusted publishing ------------------------------------------------------------------------------------------

def _wf():
    assert WORKFLOW.is_file(), ".github/workflows/release.yml is missing"
    return WORKFLOW.read_text(encoding="utf-8")


def test_release_workflow_triggers():
    text = _wf()
    assert re.search(r"^on:\s*$", text, re.M)
    assert re.search(r"^\s+release:\s*\n\s+types:\s*\[\s*published\s*\]", text, re.M), "on: release: types: [published]"
    assert re.search(r"^\s+workflow_dispatch:", text, re.M) and "dry_run" in text
    assert re.search(r"^\s+pull_request:", text, re.M)


def test_release_workflow_pins_every_action_to_a_sha():
    uses = re.findall(r"^\s*-?\s*uses:\s*(\S+)", _wf(), re.M)
    assert uses, "no actions"
    bad = [u for u in uses if not re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", u)]
    assert not bad, "not pinned to a full commit SHA: %s" % bad
    assert any(u.startswith("pypa/gh-action-pypi-publish@") for u in uses)


def test_release_workflow_permissions_and_environment():
    text = _wf()
    top = text.split("\njobs:", 1)[0]
    assert re.search(r"^permissions:\s*\n\s+contents:\s*read\s*$", top, re.M), "top-level permissions: contents: read"
    assert text.count("id-token: write") == 1, "id-token: write belongs to the one publishing job"
    assert re.search(r"environment:\s*\n\s+name:\s*pypi", text) or re.search(r"environment:\s*pypi\b", text)
    assert re.search(r"attestations:\s*true", text)


def test_release_workflow_builds_checks_and_holds_no_token():
    text = _wf()
    assert "python -m build" in text and re.search(r"twine check --strict", text)
    assert "pyproject" in text, "the tag must be checked against pyproject.toml's version"
    for word in ("PYPI_API_TOKEN", "PYPI_TOKEN", "password:", "TWINE_PASSWORD"):
        assert word not in text, word


def test_releasing_doc_names_the_trusted_publisher_fields():
    doc = (ROOT / "docs" / "RELEASING.md").read_text(encoding="utf-8")
    for field in ("LuminariSoftwares", "code-guardian", "release.yml", "pypi"):
        assert field in doc, field


# ---- version --------------------------------------------------------------------------------------------------------

def test_version_is_042_and_changelog_names_it():
    # amended by the overseer for P81 S6: 0.5.0 follows 0.4.2
    assert re.search(r'^version\s*=\s*"0\.(?:4\.2|5\.0)"', (ROOT / "pyproject.toml").read_text(encoding="utf-8"), re.M)
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert re.search(r"^## code-guardian-mcp 0\.4\.2 \(20\d\d-\d\d-\d\d\)\s*$", text, re.M)
    unreleased = re.search(r"^## Unreleased\s*$(.*?)(?=^## |\Z)", text, re.M | re.S)
    assert unreleased is None or not unreleased.group(1).strip()
