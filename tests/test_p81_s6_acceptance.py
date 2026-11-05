"""P81 S6 acceptance -- code-guardian-mcp 0.5.0, prepared for release.

Written by the overseer on main (d91aed1) BEFORE the build session. The build session adds this file to the PR
byte-for-byte and never edits it. Pure ASCII on purpose.

The PR prepares the release; it never tags, publishes or creates a GitHub Release (the owner does, by
docs/RELEASING.md). What it must hold:
  * 0.5.0 everywhere the version lives: pyproject.toml, code_guardian.__version__, mcp_server.VERSION, both
    server.json fields; `python -m code_guardian --version` prints "code-guardian 0.5.0".
  * CHANGELOG: the 0.5.0 heading is dated (YYYY-MM-DD), no "(unreleased)" heading is left, and the 0.5.0 section
    still carries "### Upgrading to 0.5.0" and the two S5b lines.
  * README: the status line, the quick-start success line, the sample report line, the Action `uses:` line and the
    pre-commit `rev:` line say 0.5.0; "## Upgrading to 0.5.0" is there.
  * action.yml: the `status` output description no longer says PARTIAL means "no Python source" (JavaScript /
    TypeScript is analysed now).
  * calibration.md: the P81 S4 section has its Markdown back (the S4 paste stripped it; the overseer's script in the
    prompt restores it after proving the words are the same).
  * The screenshots are made again (tools/ui_screenshots.py with no --only), so the README's phone and side-window
    result shots are no longer the pre-JavaScript ones that said "partial check".
  * The plan's S6 proof row: the "Upgrading to 0.5.0" baseline path runs. On a copy of js_risky, `baseline` then
    `scan --baseline` exits 0 with every finding known; after one new `eval(req.query.x)` line, the same scan exits 1
    with exactly one new finding, marked [new].
"""
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))

V = "0.5.0"
OLD_SHOTS = {  # sha256 on main d91aed1: a JavaScript-only project from before JavaScript was analysed
    "result_390x844.png": "1c6e0e53f0fa35b1f4442e080222895d238f6a2692021c7548280e8fc3cd32f2",
    "result_520x900.png": "fccda9683ea77b8bc7a29b47f52f431337c152e2ecaa224677514a536b5711d3",
}


def _read(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def _cg(*args):
    return subprocess.run([sys.executable, "-m", "code_guardian"] + [str(a) for a in args], cwd=str(ROOT),
                          capture_output=True, text=True, timeout=300)


def test_version_is_050_everywhere():
    assert re.search(r'^version\s*=\s*"0\.5\.0"\s*$', _read("pyproject.toml"), re.M)
    import code_guardian
    from code_guardian import mcp_server
    assert code_guardian.__version__ == V and mcp_server.VERSION == V
    server = json.loads(_read("server.json"))
    assert server["version"] == V and all(p["version"] == V for p in server["packages"]), server
    r = _cg("--version")
    assert r.returncode == 0 and (r.stdout + r.stderr).strip() == "code-guardian " + V, r.stdout + r.stderr


def test_changelog_is_dated():
    text = _read("CHANGELOG.md")
    m = re.search(r"^## code-guardian-mcp 0\.5\.0 \((20\d\d-\d\d-\d\d)\)\s*$", text, re.M)
    assert m, "the 0.5.0 heading is not dated"
    assert "(unreleased)" not in text.split("## code-guardian-mcp 0.4.2", 1)[0]
    assert not re.search(r"^## Unreleased\s*$", text, re.M)
    section = text[m.end():].split("\n## ", 1)[0]
    assert "### Upgrading to 0.5.0" in section
    assert "P81 S5b" in section and "Advice in the file's language" in section


def test_readme_says_050():
    readme = _read("README.md")
    assert "Status: **0.5.0 is the current release.**" in readme
    assert "`code-guardian 0.5.0  scan of <name>`" in readme
    assert "code-guardian 0.5.0  scan of risky_repo" in readme
    assert "LuminariSoftwares/code-guardian@v0.5.0" in readme and "@v0.4.2" not in readme
    assert "rev: v0.5.0" in readme and "rev: v0.4.2" not in readme
    assert re.search(r"^## Upgrading to 0\.5\.0\s*$", readme, re.M)


def test_action_status_description():
    action = _read("action.yml")
    m = re.search(r"^  status:\s*\n\s*description:\s*\"([^\"]*)\"", action, re.M)
    assert m, "no status output description"
    assert "no Python source," not in m.group(1) and "JavaScript" in m.group(1), m.group(1)


def test_calibration_markdown_restored():
    cal = _read("calibration.md")
    section = cal.split("### JavaScript / TypeScript results (P81 S4)", 1)[1]
    assert "(head `6ed24c3`)" in section
    assert "**No false Safe FAIL on express, fastify or the two templates.**" in section
    assert "**False positives: 0.**" in section
    assert "\n- **Lexer-loss: 0 of 7.**" in section and "\n- **Marker recall: 0 of 2" in section


def test_result_screenshots_made_again():
    for name, old in OLD_SHOTS.items():
        path = ROOT / "docs" / "screenshots" / name
        assert path.is_file(), name
        assert hashlib.sha256(path.read_bytes()).hexdigest() != old, "%s is still the pre-JavaScript shot" % name


def test_upgrade_baseline_path_runs(tmp_path):
    import make_risky_js
    root = Path(make_risky_js.build(tmp_path / "js_risky"))
    r = _cg("baseline", root)
    assert r.returncode == 0, r.stdout + r.stderr
    base = root / "code-guardian.baseline.json"
    assert base.is_file(), r.stdout
    known = len(json.loads(base.read_text(encoding="utf-8"))["fingerprints"])
    assert known > 0
    r = _cg("scan", root, "--baseline", base)
    assert r.returncode == 0, r.stdout[-1500:]
    assert "baseline: 0 new, %d known" % known in r.stdout, r.stdout[-1500:]
    (root / "extra.js").write_text("module.exports.x = function (req) { return eval(req.query.x); };\n",
                                   encoding="utf-8")
    r = _cg("scan", root, "--baseline", base)
    assert r.returncode == 1, r.stdout[-1500:]
    assert "baseline: 1 new, %d known" % known in r.stdout, r.stdout[-1500:]
    new = [line for line in r.stdout.splitlines() if line.rstrip().endswith("[new]")]
    assert len(new) == 1 and "exec.dynamic" in new[0] and "extra.js:1" in new[0], new
