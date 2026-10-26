"""P88 S1 acceptance -- backups.py (which folders and files look like backup copies, and which of them may be offered)
and the exclude plumbing (report.scan(exclude=), the CLI's --exclude, POST /api/scan {exclude}) (plan P88 C1, C2).

Written by the overseer BEFORE the build session. The build session must add this file to the PR byte-for-byte and
must not edit it; a PR that changes it fails the section. This file is pure ASCII on purpose, and it holds no key-shaped
value: the one planted secret it needs is built by concatenation at test time, like tests/make_risky.py does.

Readings this file takes where the plan leaves a choice (the build follows them):
  - backups.offer(findings, inventory, graph=None, texts=None) returns a 2-tuple (offered, held): C1's "second return
    value held". graph is an orphans.Graph; texts maps rel -> file text.
  - A re-check of a scan id is POST /api/scan {"path": <same>, "again": "<scan id>"} with no "exclude" key: the server
    reuses the exclude it stored for that id. The POST and GET /api/scan?id= responses carry the stored list as
    top-level "exclude", and the POST response carries "backup_offer": {"offered": [...], "held": [...]}.
  - files.excluded counts what the walk skipped (a pruned folder may count once), so the checks compare the RISE of
    files.excluded with the sum of excluded_by_request[*].files, never with a count of files on disk.
  - No goal file and a requested exclude: the "excluded by the goal file" note is not written (it would be false).
  - Every subcommand that takes --goal today (scan, baseline, plan, orphans) also takes --exclude.

AMENDED by the overseer 2026-10-24 ~20:00 Central after review of PR #42 (deviation D10, pickup P88):
  - A kept file that NAMES the folder in a string no longer holds the group: on the owner's own folder 46 scripts name
    _archive/ because they WRITE their backups there, so the plan's rule held back the very copy (151 of 206 findings)
    P88 exists for. Imports and risky findings still hold. Every offered group carries "named_by": the sorted kept
    files that name its folder in a string ([] when none); the page shows them as a caution (S2).
  - looks_like_backup covers the whole plan section 2.6 list, including the owner's own "<name>.pre-<change>-<date>".
  - The text report's files line stays true: with a requested exclude it reads
    "(N skipped, N excluded by the goal file, N left out at your request)"; without one it is unchanged.

The 8 fixture digests were recorded on main on 2026-10-24 (code-guardian 0.4.0) with the overseer's recorder: the
report of each fixture with top-level "version" and "path" dropped, json.dumps(sort_keys=True, indent=1), sha256.
risky_repo is scanned as tests/make_risky.build makes it. Confirmed on Windows the same day (cg_review on main): the
digests match except complete_bare, whose CRLF checkout changes one README byte count, so it has its own Windows value.
"""
import hashlib
import http.client
import json
import os
import re
import shutil
import subprocess
import sys
import threading
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
FIXTURES = HERE / "fixtures"
sys.path.insert(0, str(HERE))

BEFORE_DIGESTS = {  # recorded on main 2026-10-24; re-recorded without "weights" on bf5e31e 2026-10-25 (P81 S2)
    "clean_repo": "5c1a5965f2978f22af70474f0ab81b264d48f2113c7af86fbbe9a2607a19f8d1",
    "complete_app": "4df1c2aa227cb223da14ff578a9a25005f8ab7c10e0c14a66dfe86bb467704d7",
    "complete_bare": "0fac84bb829c27cd90e3a45881ed17dd849012652422372483276ab7b0d65f9d",
    "orphan_repo": "d6d039fcb3b799626752c926cf048bc8af27dec17a4d8a808de98872bb81f69f",
    "supply_repo": "3574a3faaef76c5b18653cfb334785e8d6770859723bfb64e75fceb9c7eb0724",
    "works_broken": "ffb102455fc0e66f933fe52699079cdeed8227a950b991e89e49d7851e2ccd8f",
    "works_weak_tests": "15b979c7fc9c8a1554508bf6711512c2394a45030c8e88fc70a3c03d9ae32846",
}
if os.name == "nt":  # a CRLF checkout: complete_bare's README byte count differs (17 vs 14); recorded on Windows too
    BEFORE_DIGESTS["complete_bare"] = "aaebf8aaecbb12bb0b521dd1eef40c334d802e9a760accaa25c43e23be153657"
# sha256 of code_guardian/scanners.py on main (0.4.0), line endings normalised to \n: S1 must not touch it.
SCANNERS_SHA256_MAIN = "92f26b655e02e53348c50ebfeec9ae95ff36168ed4f34e52802815d0a0cc98b3"
COUNT_LINE = re.compile(r"(\d+) checks, (\d+) passed")


# ---- helpers -------------------------------------------------------------------------------------------------------

def canon(rep):
    d = json.loads(json.dumps(rep))
    d.pop("version", None)
    d.pop("path", None)
    d.pop("weights", None)  # P81 S2 adds weight rows; test_golden excludes weights the same way
    d.pop("schema_version", None)  # P81 S4 bumps it; the additive keys below are test_golden's
    d.get("files", {}).pop("javascript", None)
    d.get("files", {}).pop("generated", None)
    d.get("coverage", {}).pop("languages", None)
    return json.dumps(d, sort_keys=True, indent=1)


def digest(rep):
    return hashlib.sha256(canon(rep).encode("utf-8")).hexdigest()


def fixture_path(name, tmp_path):
    if name == "risky_repo":
        import make_risky
        return make_risky.build(tmp_path / "risky_repo")
    return FIXTURES / name


def run_cli(*args, timeout=300):
    return subprocess.run([sys.executable, "-m", "code_guardian"] + list(args), cwd=str(ROOT), capture_output=True,
                          text=True, encoding="utf-8", timeout=timeout, env=dict(os.environ, PYTHONPATH=str(ROOT)))


def make_backup_repo(dest):
    import make_backup_repo as mbr  # tests/make_backup_repo.py, S1's builder
    out = mbr.build(dest)
    return Path(out) if out is not None else Path(dest)


@pytest.fixture
def backup_repo(tmp_path):
    return make_backup_repo(tmp_path / "backup_repo")


def under(node, prefix):
    return node.split(":", 1)[0].startswith(prefix)


def inventory(**kw):
    inv = {"python": [], "manifests": [], "other": [], "skipped": [], "excluded": 0, "ignored": 0}
    inv.update(kw)
    for k in ("python", "manifests", "other"):
        inv[k] = sorted(inv[k])
    return inv


def finding(code, level, node):
    return {"code": code, "level": level, "node": node, "severity": "partial", "summary": code, "evidence": [],
            "try": [], "confidence": "LIKELY", "fix": None}


def graph_of(files):
    import ast
    from code_guardian import orphans
    return orphans.Graph({rel: ast.parse(src) for rel, src in files.items()})


# ---- C1: looks_like_backup -----------------------------------------------------------------------------------------

@pytest.mark.parametrize("rel,glob", [
    ("_archive/x/y.py", "_archive/*"),
    ("a/b.py.backup-20260824", "*.backup-*"),
    ("tools/old_timer.py", None),            # a name containing "old" is not a backup
    ("src/archive.py", None),                # a file named archive, not a folder
    ("_ARCHIVE/z.py", "_ARCHIVE/*"),         # case-insensitive; the glob keeps the segment as walked
    ("pkg/_backups/m.py", "pkg/_backups/*"),  # any depth: the glob names the folder's path
    ("app/main.py", None),
    # amended: the rest of plan section 2.6
    ("scripts/x.py.pre-p88-20261024", "*.pre-*"),
    ("a/settings.py.orig", "*.orig"),
    ("a/notes.txt~", "*~"),
    ("tmp/a.py", "tmp/*"),
    ("temp/a.py", "temp/*"),
    ("scratch/a.py", "scratch/*"),
    (".trash/a.py", ".trash/*"),
    ("src_old/a.py", "src_old/*"),
    ("backup_before_refactor/a.py", "backup_before_refactor/*"),
    ("_to_delete_2026-10-24/a.py", "_to_delete_2026-10-24/*"),
    ("archives/a.py", "archives/*"),
    ("bold/a.py", None),                      # ends in "old" but is not "_old"
    ("templates/a.py", None),                 # starts with "temp" but is not "temp"
])
def test_looks_like_backup(rel, glob):
    from code_guardian import backups
    assert backups.looks_like_backup(rel) == glob


# ---- C1: offer ------------------------------------------------------------------------------------------------------

def test_offer_empty_inventory_offers_nothing():
    from code_guardian import backups
    offered, held = backups.offer([], inventory())
    assert offered == [] and held == []


def test_offer_group_with_only_key_fails_is_offered_with_its_counts():
    from code_guardian import backups
    inv = inventory(python=["app/main.py", "_archive/a.py", "_archive/b.py"])
    fs = [finding("secret.key", "FAIL", "_archive/a.py:3"), finding("secret.key", "FAIL", "_archive/b.py:1"),
          finding("secret.key", "FAIL", "_archive/b.py:9"), finding("exec.shell", "WARN", "app/main.py:4")]
    files = {"app/main.py": "import os\n", "_archive/a.py": "X = 1\n", "_archive/b.py": "Y = 2\n"}
    offered, held = backups.offer(fs, inv, graph=graph_of(files), texts=files)
    assert held == []
    assert len(offered) == 1
    g = offered[0]
    assert {"glob", "files", "findings", "by_code", "fail"} <= set(g)
    assert g["glob"] == "_archive/*" and g["files"] == 2 and g["findings"] == 3
    assert g["by_code"] == {"secret.key FAIL": 3}


def test_offer_sorted_by_findings_desc():
    from code_guardian import backups
    inv = inventory(python=["app/main.py", "_archive/a.py", "_backup/b.py"])
    fs = [finding("secret.key", "FAIL", "_archive/a.py:1"),
          finding("secret.key", "FAIL", "_backup/b.py:1"), finding("secret.key", "FAIL", "_backup/b.py:2")]
    files = {"app/main.py": "import os\n", "_archive/a.py": "X = 1\n", "_backup/b.py": "Y = 2\n"}
    offered, _ = backups.offer(fs, inv, graph=graph_of(files), texts=files)
    assert [g["glob"] for g in offered] == ["_backup/*", "_archive/*"]


def test_offer_group_without_findings_is_neither_offered_nor_held():
    from code_guardian import backups
    inv = inventory(python=["app/main.py", "_archive/a.py"])
    files = {"app/main.py": "import os\n", "_archive/a.py": "X = 1\n"}
    offered, held = backups.offer([finding("exec.shell", "WARN", "app/main.py:1")], inv, graph=graph_of(files),
                                  texts=files)
    assert offered == [] and held == []


def test_offer_holds_a_group_the_kept_code_imports():
    from code_guardian import backups
    files = {"app/main.py": "from old import helper\n\nhelper.go()\n", "old/helper.py": "def go():\n    return 1\n",
             "old/__init__.py": ""}
    inv = inventory(python=list(files))
    fs = [finding("secret.key", "FAIL", "old/helper.py:1")]
    offered, held = backups.offer(fs, inv, graph=graph_of(files), texts=files)
    assert offered == []
    assert [h["glob"] for h in held] == ["old/*"]
    assert "app/main.py" in held[0]["why"]


def test_offer_a_kept_file_naming_the_folder_is_a_caution_not_a_hold():
    from code_guardian import backups
    files = {"app/main.py": 'DATA = "_archive/seed.json"\n', "tools/save.py": 'DEST = "_archive"\n',
             "_archive/a.py": "X = 1\n"}
    inv = inventory(python=list(files))
    offered, held = backups.offer([finding("secret.key", "FAIL", "_archive/a.py:1")], inv, graph=graph_of(files),
                                  texts=files)
    assert held == [] and [g["glob"] for g in offered] == ["_archive/*"], (offered, held)
    assert offered[0]["named_by"] == ["app/main.py", "tools/save.py"]


def test_offer_an_import_still_holds_even_when_also_named():
    from code_guardian import backups
    files = {"app/main.py": 'from old import helper\nP = "old/x"\n', "old/__init__.py": "", "old/helper.py": "X = 1\n"}
    inv = inventory(python=list(files))
    offered, held = backups.offer([finding("secret.key", "FAIL", "old/helper.py:1")], inv, graph=graph_of(files),
                                  texts=files)
    assert offered == [] and [h["glob"] for h in held] == ["old/*"] and "app/main.py" in held[0]["why"]


def test_offer_a_bare_word_in_a_string_does_not_hold():
    from code_guardian import backups
    files = {"app/main.py": 'MSG = "the old value was kept"\n', "old/a.py": "X = 1\n"}
    inv = inventory(python=list(files))
    offered, held = backups.offer([finding("secret.key", "FAIL", "old/a.py:1")], inv, graph=graph_of(files),
                                  texts=files)
    assert [g["glob"] for g in offered] == ["old/*"] and held == []
    assert offered[0]["named_by"] == []


@pytest.mark.parametrize("code,level", [("exec.shell", "FAIL"), ("exec.dynamic", "FAIL"), ("obfuscation", "FAIL"),
                                        ("install.hook", "WARN"), ("install.hook", "INFO")])
def test_offer_holds_a_group_with_a_dangerous_finding(code, level):
    from code_guardian import backups
    files = {"app/main.py": "import os\n", "_archive/a.py": "X = 1\n", "_archive/b.py": "Y = 1\n"}
    inv = inventory(python=list(files))
    fs = [finding("secret.key", "FAIL", "_archive/a.py:1"), finding(code, level, "_archive/b.py:1")]
    offered, held = backups.offer(fs, inv, graph=graph_of(files), texts=files)
    assert offered == [] and [h["glob"] for h in held] == ["_archive/*"]
    assert isinstance(held[0]["why"], str) and held[0]["why"].strip()


def test_offer_an_exec_shell_warn_alone_does_not_hold():
    from code_guardian import backups
    files = {"app/main.py": "import os\n", "_archive/a.py": "X = 1\n"}
    inv = inventory(python=list(files))
    fs = [finding("secret.key", "FAIL", "_archive/a.py:1"), finding("exec.shell", "WARN", "_archive/a.py:2")]
    offered, held = backups.offer(fs, inv, graph=graph_of(files), texts=files)
    assert [g["glob"] for g in offered] == ["_archive/*"] and held == []
    assert offered[0]["by_code"] == {"secret.key FAIL": 1, "exec.shell WARN": 1}


def test_offer_file_pattern_group():
    from code_guardian import backups
    files = {"app/main.py": "import os\n", "app/main.py.backup-20260824": "X = 1\n"}
    inv = inventory(python=["app/main.py"], other=["app/main.py.backup-20260824"])
    fs = [finding("secret.key", "FAIL", "app/main.py.backup-20260824:1")]
    offered, held = backups.offer(fs, inv, graph=graph_of({"app/main.py": "import os\n"}), texts=files)
    assert [(g["glob"], g["files"], g["findings"]) for g in offered] == [("*.backup-*", 1, 1)] and held == []


def test_backups_selftest_counts_at_least_18():
    r = subprocess.run([sys.executable, "-m", "code_guardian.backups", "--selftest"], cwd=str(ROOT),
                       capture_output=True, text=True, timeout=120, env=dict(os.environ, PYTHONPATH=str(ROOT)))
    m = COUNT_LINE.search(r.stdout + r.stderr)
    assert r.returncode == 0 and m, (r.returncode, (r.stdout + r.stderr)[-800:])
    assert int(m.group(1)) >= 18 and m.group(1) == m.group(2), m.group(0)


# ---- the backup_repo fixture and offer on it ------------------------------------------------------------------------

def test_backup_repo_tree_holds_no_key_shape():
    from code_guardian import report
    assert (FIXTURES / "backup_repo").is_dir(), "tests/fixtures/backup_repo/ is part of S1"
    rep = report.scan(str(FIXTURES / "backup_repo"))
    assert [f["node"] for f in rep["findings"] if f["code"] == "secret.key"] == []


def test_backup_repo_shape(backup_repo):
    from code_guardian import report
    main = (backup_repo / "app" / "main.py").read_text(encoding="utf-8")
    assert re.search(r"^\s*(from old import helper|import old\.helper|from old\.helper import)", main, re.M), main
    assert (backup_repo / "old" / "helper.py").is_file() and (backup_repo / "_archive").is_dir()
    rep = report.scan(str(backup_repo))
    arch = [f for f in rep["findings"] if under(f["node"], "_archive/")]
    assert arch and all(f["code"] == "secret.key" and f["level"] == "FAIL" for f in arch), \
        [(f["code"], f["level"], f["node"]) for f in arch]
    assert [f for f in rep["findings"] if under(f["node"], "old/")], "old/ needs >= 1 planted finding"


def _offer_on(root):
    import ast
    from code_guardian import backups, orphans, report, walk
    rep = report.scan(str(root))
    inv = walk.walk(str(root))
    texts, trees = {}, {}
    for rel in inv["python"] + inv["manifests"] + inv["other"]:
        texts[rel] = walk.read(str(root), rel)[1]
        if rel.endswith(".py"):
            try:
                trees[rel] = ast.parse(texts[rel])
            except SyntaxError:
                pass
    return backups.offer(rep["findings"], inv, graph=orphans.Graph(trees), texts=texts)


def test_offer_on_backup_repo(backup_repo):
    offered, held = _offer_on(backup_repo)
    assert "_archive/*" in [g["glob"] for g in offered], offered
    old = [h for h in held if h["glob"] == "old/*"]
    assert old and "app/main.py" in old[0]["why"], held
    assert "old/*" not in [g["glob"] for g in offered]


def test_offer_on_backup_repo_with_exec_shell_planted_in_archive(backup_repo):
    (backup_repo / "_archive" / "launcher.py").write_text(
        "import os\n\n\ndef run_user_command():\n    command = input(\"command: \")\n    os.system(command)\n",
        encoding="utf-8")
    from code_guardian import report
    rep = report.scan(str(backup_repo))
    assert [f for f in rep["findings"] if f["code"] == "exec.shell" and f["level"] == "FAIL"
            and under(f["node"], "_archive/")], "the planted launcher must be an exec.shell FAIL"
    offered, held = _offer_on(backup_repo)
    assert "_archive/*" not in [g["glob"] for g in offered]
    assert "_archive/*" in [h["glob"] for h in held]


# ---- C2: report.scan(exclude=) ----------------------------------------------------------------------------------------

@pytest.mark.parametrize("name", sorted(BEFORE_DIGESTS))
def test_cli_scan_byte_identical_to_main(name, tmp_path):
    r = run_cli("scan", str(fixture_path(name, tmp_path)), "--json")
    assert r.stdout.strip().startswith("{"), r.stderr[-500:]
    assert digest(json.loads(r.stdout)) == BEFORE_DIGESTS[name]


@pytest.mark.parametrize("name", sorted(BEFORE_DIGESTS))
def test_report_scan_empty_exclude_byte_identical(name, tmp_path):
    from code_guardian import report
    assert digest(report.scan(str(fixture_path(name, tmp_path)), exclude=())) == BEFORE_DIGESTS[name]


def test_report_scan_without_exclude_has_no_new_key(backup_repo):
    from code_guardian import report
    rep = report.scan(str(backup_repo))
    assert "excluded_by_request" not in rep
    assert not [n for n in rep["notes"] if "at your request" in n]
    rep = report.scan(str(backup_repo), exclude=())
    assert "excluded_by_request" not in rep


def test_report_scan_with_exclude(backup_repo):
    from code_guardian import report
    plain = report.scan(str(backup_repo))
    ex = report.scan(str(backup_repo), exclude=["_archive/*"])
    ebr = ex["excluded_by_request"]
    assert isinstance(ebr, list) and len(ebr) == 1 and set(ebr[0]) == {"glob", "files"}, ebr
    assert ebr[0]["glob"] == "_archive/*" and isinstance(ebr[0]["files"], int) and ebr[0]["files"] >= 1
    n = ebr[0]["files"]
    assert ex["files"]["excluded"] == plain["files"]["excluded"] + n
    assert "%d path(s) left out at your request: %s" % (n, "_archive/*") in ex["notes"], ex["notes"]
    assert not [x for x in ex["notes"] if "excluded by the goal file" in x], ex["notes"]
    assert not [f for f in ex["findings"] if under(f["node"], "_archive/")]
    kept = [f for f in plain["findings"] if not under(f["node"], "_archive/")]
    assert ex["findings"] == kept


def test_report_scan_unmatched_exclude_counts_zero(backup_repo):
    from code_guardian import report
    ex = report.scan(str(backup_repo), exclude=["_archive/*", "no_such_dir/*"])
    assert [(g["glob"], g["files"] >= 1) for g in ex["excluded_by_request"]] == [("_archive/*", True),
                                                                                ("no_such_dir/*", False)]
    assert ex["excluded_by_request"][1]["files"] == 0


# ---- C2: the CLI -----------------------------------------------------------------------------------------------------

def test_text_files_line_says_what_was_left_out_at_request(backup_repo):
    r = run_cli("scan", str(backup_repo), "--exclude", "_archive/*")
    line = [ln for ln in r.stdout.splitlines() if ln.startswith("files: ")]
    assert line, r.stdout[:500]
    m = re.search(r"\((\d+) skipped, (\d+) excluded by the goal file, (\d+) left out at your request\)$", line[0])
    assert m and m.group(2) == "0" and int(m.group(3)) >= 1, line[0]
    plain_run = run_cli("scan", str(backup_repo))
    plain_line = [ln for ln in plain_run.stdout.splitlines() if ln.startswith("files: ")][0]
    assert plain_line.endswith("excluded by the goal file)") and "at your request" not in plain_line, plain_line


def test_scan_help_shows_exclude():
    r = run_cli("scan", "--help")
    assert r.returncode == 0 and "--exclude" in r.stdout, r.stdout


@pytest.mark.parametrize("sub", ["scan", "baseline", "plan", "orphans"])
def test_every_goal_subcommand_takes_exclude(sub):
    r = run_cli(sub, "--help")
    assert r.returncode == 0 and "--goal" in r.stdout
    assert "--exclude" in r.stdout, "%s has --goal but no --exclude" % sub


def test_cli_exclude_repeatable(backup_repo):
    r = run_cli("scan", str(backup_repo), "--json", "--exclude", "_archive/*", "--exclude", "no_such_dir/*")
    assert r.stdout.strip().startswith("{"), r.stderr[-500:]
    rep = json.loads(r.stdout)
    assert [g["glob"] for g in rep["excluded_by_request"]] == ["_archive/*", "no_such_dir/*"]
    assert rep["excluded_by_request"][1]["files"] == 0
    assert not [f for f in rep["findings"] if under(f["node"], "_archive/")]


# ---- C2: the server --------------------------------------------------------------------------------------------------

class Server:
    def __init__(self):
        from code_guardian import ui
        self.s = ui.make_server(port=0)
        self.t = threading.Thread(target=self.s.serve_forever)
        self.t.start()
        self.port = self.s.server_address[1]

    def call(self, method, path, body=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=180)
        headers = {"Host": "127.0.0.1:%d" % self.port, "Content-Type": "application/json", "X-CG-Token": self.s.token}
        c.request(method, path, None if body is None else json.dumps(body), headers)
        r = c.getresponse()
        raw = r.read()
        c.close()
        try:
            return r.status, json.loads(raw.decode("utf-8"))
        except ValueError:
            return r.status, None

    def close(self):
        self.s.shutdown()
        self.s.server_close()
        self.t.join(10)


@pytest.fixture
def srv():
    s = Server()
    yield s
    s.close()


def test_api_scan_offers_and_holds(srv, backup_repo):
    status, js = srv.call("POST", "/api/scan", {"path": str(backup_repo), "goal_file": None})
    assert status == 200, js
    bo = js["backup_offer"]
    assert set(bo) == {"offered", "held"}, bo
    assert "_archive/*" in [g["glob"] for g in bo["offered"]]
    old = [h for h in bo["held"] if h["glob"] == "old/*"]
    assert old and "app/main.py" in old[0]["why"]
    assert js["exclude"] == [] and "excluded_by_request" not in js["report"]


def test_api_scan_with_exclude_and_recheck(srv, backup_repo):
    status, js = srv.call("POST", "/api/scan", {"path": str(backup_repo), "goal_file": None,
                                                 "exclude": ["_archive/*"]})
    assert status == 200, js
    assert js["exclude"] == ["_archive/*"]
    assert [g["glob"] for g in js["report"]["excluded_by_request"]] == ["_archive/*"]
    assert not [f for f in js["report"]["findings"] if under(f["node"], "_archive/")]
    status, got = srv.call("GET", "/api/scan?id=%s" % js["id"])
    assert status == 200 and got["exclude"] == ["_archive/*"], got
    status, again = srv.call("POST", "/api/scan", {"path": str(backup_repo), "goal_file": None, "again": js["id"]})
    assert status == 200, again
    assert again["id"] != js["id"] and again["exclude"] == ["_archive/*"]
    assert [g["glob"] for g in again["report"]["excluded_by_request"]] == ["_archive/*"]


@pytest.mark.parametrize("bad", [["x/*"] * 51, ["a" * 201], "_archive/*", [3], {"glob": "x"}])
def test_api_scan_refuses_bad_exclude(srv, bad):
    status, js = srv.call("POST", "/api/scan", {"path": str(FIXTURES / "clean_repo"), "goal_file": None,
                                                "exclude": bad})
    assert status == 400 and js and js.get("error") == "exclude", (status, js)


def test_api_scan_fifty_items_is_allowed(srv):
    status, js = srv.call("POST", "/api/scan", {"path": str(FIXTURES / "clean_repo"), "goal_file": None,
                                                "exclude": ["nothing_%d/*" % i for i in range(50)]})
    assert status == 200, js
    assert len(js["report"]["excluded_by_request"]) == 50


def test_open_and_get_read_no_folder_and_keep_the_exclude(srv, backup_repo, monkeypatch):
    r = run_cli("scan", str(backup_repo), "--json", "--exclude", "_archive/*")
    assert r.stdout.strip().startswith("{"), r.stderr[-500:]
    from code_guardian import ui
    calls = []
    real = ui.report.scan
    monkeypatch.setattr(ui.report, "scan", lambda *a, **kw: calls.append(a) or real(*a, **kw))
    status, js = srv.call("POST", "/api/open", {"json": r.stdout})
    assert status == 200, js
    assert [g["glob"] for g in js["report"]["excluded_by_request"]] == ["_archive/*"]
    assert srv.call("GET", "/api/scan?id=%s" % js["id"])[0] == 200
    assert calls == []


# ---- S1 leaves scanners.py alone -------------------------------------------------------------------------------------

def test_scanners_py_unchanged():
    # Amended 2026-10-24 ~20:50 (overseer): S1 must not touch scanners.py, but S3 (PR #43) does, legitimately. Once
    # S3's value signals are on the branch (scanners.test_value_reason exists) this S1 check has done its job.
    data = (ROOT / "code_guardian" / "scanners.py").read_bytes().replace(b"\r\n", b"\n")
    if b"def test_value_reason(" in data:
        pytest.skip("scanners.py carries P88 S3's change; S1's no-touch check applies only before S3 merges")
    assert hashlib.sha256(data).hexdigest() == SCANNERS_SHA256_MAIN
