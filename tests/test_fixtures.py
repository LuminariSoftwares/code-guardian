"""The three fixture repos, checked against values worked out by hand from their files (not read back from the code)."""
import collections
import json
import shutil
import subprocess
import sys

import make_risky
from conftest import FIXTURES, HTTP, tailnet

from code_guardian import report

ALL_CODES = {"secret.key", "exec.dynamic", "exec.shell", "deser.unsafe", "net.egress", "net.bind_all", "tls.off",
             "install.hook", "obfuscation", "fs.outside", "deps.unpinned"}

# Every finding in risky_repo plus make_risky's generated files, counted by reading the fixture.
RISKY_COUNTS = {
    ("secret.key", "FAIL"): 3,      # settings.py sk- key, settings.py password literal, deploy/id_rsa key block
    ("exec.shell", "FAIL"): 1,      # runner.py os.system(input())
    ("exec.shell", "WARN"): 1,      # runner.py subprocess.run(shell=True)
    ("exec.dynamic", "WARN"): 2,    # runner.py eval(expression), loader.py exec(...)
    ("deser.unsafe", "WARN"): 2,    # storage.py pickle.load, yaml.load
    ("net.egress", "WARN"): 1,      # network.py plain-http URL to a host chosen at runtime
    ("net.egress", "INFO"): 3,      # network.py https URL, local-network IP literal, requests.post call
    ("net.bind_all", "WARN"): 1,    # network.py bind 0.0.0.0
    ("tls.off", "FAIL"): 1,         # network.py verify=False
    ("install.hook", "WARN"): 3,    # setup.py class + cmdclass, package.json postinstall
    ("obfuscation", "FAIL"): 1,     # loader.py exec(base64.b64decode(...))
    ("obfuscation", "WARN"): 2,     # loader.py base64 blob, settings.py high-entropy token
    ("fs.outside", "WARN"): 1,      # storage.py open("/tmp/...", "w")
    ("deps.unpinned", "INFO"): 3,   # setup.py requests, pyproject flask>=2, package.json left-pad *
}
# 3*40 + 30 + 10 + 2*10 + 2*10 + 2 + 0 + 5 + 25 + 3*15 + 40 + 2*10 + 3 + 0
RISKY_RAW = 120 + 30 + 10 + 20 + 20 + 2 + 0 + 5 + 25 + 45 + 40 + 20 + 3 + 0
RISKY_TRACKED_RAW = RISKY_RAW - 3 * 40 - 10  # without make_risky's three secrets and the high-entropy token


def risky(tmp_path):
    return make_risky.build(tmp_path / "risky_repo")


def cli(*args, env=None):
    return subprocess.run([sys.executable, "-m", "code_guardian", *map(str, args)], capture_output=True, text=True,
                          timeout=120, env=env)


def test_risky_counts_and_hand_computed_score(tmp_path):
    rep = report.scan(str(risky(tmp_path)))
    counts = collections.Counter((f["code"], f["level"]) for f in rep["findings"])
    assert dict(counts) == RISKY_COUNTS
    assert {c for c, _ in counts} == ALL_CODES  # every scanner fired
    assert RISKY_RAW == 340
    assert rep["threat"]["raw"] == RISKY_RAW
    assert rep["threat"]["score"] == 100
    assert rep["threat"]["grade"] == "F"


def test_risky_top_five(tmp_path):
    top = report.scan(str(risky(tmp_path)))["threat"]["top"]
    assert [(t["weight"], t["code"], t["node"]) for t in top] == [
        (40, "secret.key", "deploy/id_rsa:1"),
        (40, "obfuscation", "risky/loader.py:7"),
        (40, "secret.key", "risky/settings.py:1"),
        (40, "secret.key", "risky/settings.py:2"),
        (30, "exec.shell", "risky/runner.py:7"),
    ]


def test_risky_exact_nodes(tmp_path):
    rep = report.scan(str(risky(tmp_path)))
    nodes = {(f["code"], f["level"], f["node"]) for f in rep["findings"]}
    for expected in [("tls.off", "FAIL", "risky/network.py:11"), ("net.bind_all", "WARN", "risky/network.py:16"),
                     ("exec.shell", "WARN", "risky/runner.py:11"), ("deser.unsafe", "WARN", "risky/storage.py:8"),
                     ("deser.unsafe", "WARN", "risky/storage.py:12"), ("fs.outside", "WARN", "risky/storage.py:16"),
                     ("install.hook", "WARN", "setup.py:5"), ("install.hook", "WARN", "setup.py:14"),
                     ("install.hook", "WARN", "package.json:5"), ("obfuscation", "WARN", "risky/loader.py:3"),
                     ("obfuscation", "WARN", "risky/settings.py:3"), ("net.egress", "WARN", "risky/network.py:5")]:
        assert expected in nodes, expected
    assert [(e["level"], e["kind"], e["target"]) for e in rep["egress"]] == [
        ("WARN", "url", HTTP + "{host}:8080/upload"), ("INFO", "url", "https://example.com/docs"),
        ("INFO", "ip", tailnet(5)), ("INFO", "call", "requests.post")]
    assert any(".js 1" in n and "secret scan only" in n for n in rep["notes"])


def test_risky_secret_values_never_printed(tmp_path):
    out = cli("scan", risky(tmp_path), "--json").stdout
    assert ("sk-" + "A" * 24) not in out and ("Tr0ub4dor" + "-and-3") not in out
    assert "value redacted" in out


def test_tracked_risky_repo_without_secrets():
    rep = report.scan(str(FIXTURES / "risky_repo"))
    assert rep["threat"]["raw"] == RISKY_TRACKED_RAW == 210
    assert not [f for f in rep["findings"] if f["code"] == "secret.key"]


def test_clean_repo_grade_a():
    rep = report.scan(str(FIXTURES / "clean_repo"))
    assert rep["threat"] == {"score": 0, "raw": 0, "grade": "A", "top": []}
    assert [(f["code"], f["level"], f["node"]) for f in rep["findings"]] == [
        ("net.egress", "INFO", "cleanpkg/fetch.py:3"), ("net.egress", "INFO", "cleanpkg/fetch.py:7")]
    assert not [f for f in rep["findings"] if f["level"] == "FAIL"]
    assert rep["hygiene"]["source"] == "inferred"
    assert rep["hygiene"]["entry_points"] == ["cleanpkg.cli:main"]
    assert rep["hygiene"]["findings"] == []


def test_orphan_repo_exact_names():
    h = report.orphans(str(FIXTURES / "orphan_repo"))
    assert h["source"] == "contract"
    assert h["entry_points"] == ["greeter.cli:main"]
    assert [(f["code"], f["level"], f["evidence"][0], f["node"]) for f in h["findings"]] == [
        ("orphan.uncertain", "INFO", "name: greeter.cli.cmd_hello", "greeter/cli.py:6"),
        ("orphan.dead", "WARN", "name: greeter.core.shout", "greeter/core.py:5"),
        ("orphan.test_only", "INFO", "name: greeter.core.format_for_tests", "greeter/core.py:9"),
    ]
    assert h["counts"] == {"orphan.dead": 1, "orphan.test_only": 1, "orphan.uncertain": 1}
    assert not any("plugins" in f["evidence"][0] for f in h["findings"])  # keep-listed


def test_orphan_keep_is_what_hides_the_plugin(tmp_path):
    goal = tmp_path / "goal.toml"
    goal.write_text('entry_points = ["greeter.cli:main"]\n', encoding="utf-8")
    h = report.orphans(str(FIXTURES / "orphan_repo"), str(goal))
    assert ("orphan.dead", "name: greeter.plugins") in [(f["code"], f["evidence"][0]) for f in h["findings"]]


def test_orphans_never_touch_the_threat_score():
    rep = report.scan(str(FIXTURES / "orphan_repo"))
    assert rep["hygiene"]["counts"]["orphan.dead"] == 1
    assert rep["threat"]["raw"] == 0 and rep["threat"]["grade"] == "A"


def test_exit_codes(tmp_path):
    assert cli("scan", risky(tmp_path)).returncode == 1
    assert cli("scan", FIXTURES / "clean_repo").returncode == 0
    assert cli("scan", FIXTURES / "clean_repo", "--fail-on", "INFO").returncode == 1
    assert cli("scan", FIXTURES / "clean_repo", "--fail-on", "WARN").returncode == 0
    assert cli("scan", FIXTURES / "orphan_repo").returncode == 0  # orphans are hygiene: scan gates on threat only
    assert cli("orphans", FIXTURES / "orphan_repo").returncode == 0
    assert cli("orphans", FIXTURES / "orphan_repo", "--fail-on", "WARN").returncode == 1
    assert cli("scan", tmp_path / "missing").returncode == 2
    assert cli("scan").returncode == 2
    assert cli("frobnicate").returncode == 2
    assert cli().returncode == 2
    bad = tmp_path / "bad.toml"
    bad.write_text("entry_points = 3\n", encoding="utf-8")
    r = cli("scan", FIXTURES / "clean_repo", "--goal", bad)
    assert r.returncode == 2 and "entry_points must be a list" in r.stderr


def test_text_report(tmp_path):
    out = cli("scan", risky(tmp_path)).stdout
    assert "threat score 100/100 (raw 340)  grade F" in out
    assert "top contributors:" in out and "   40  secret.key    FAIL  deploy/id_rsa:1" in out
    assert "egress inventory (4):" in out
    assert "hygiene (inferred entry points: 1): 6 dead, 0 test-only, 0 uncertain" in out  # + generated settings.py


def test_init_writes_inferred_entry_points(tmp_path):
    dest = tmp_path / "clean"
    shutil.copytree(FIXTURES / "clean_repo", dest)
    r = cli("init", dest)
    assert r.returncode == 0, r.stderr
    text = (dest / "code-guardian.goal.toml").read_text(encoding="utf-8")
    assert 'entry_points = [\n  "cleanpkg.cli:main",\n]' in text
    assert cli("init", dest).returncode == 2  # never overwrites without --force
    h = json.loads(cli("orphans", dest, "--json").stdout)
    assert h["source"] == "contract" and h["entry_points"] == ["cleanpkg.cli:main"] and h["findings"] == []


def test_scan_is_deterministic(tmp_path):
    path = str(risky(tmp_path))
    a, b = report.scan(path), report.scan(path)
    a.pop("elapsed_ms")
    b.pop("elapsed_ms")
    assert a == b
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
