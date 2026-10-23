"""P78 S3 acceptance -- every file (plan P78 C4): the inventory taken at scan time with the scan's own goal-file
excludes, GET /api/files, plain.file_rows with "Not read" / "Partly checked" / "No known risks found", and the Code
screen's filter and find box.

Written by the overseer BEFORE the build session. The build session must add this file to the PR byte-for-byte and
must not edit it; a PR that changes it fails the section. This file is pure ASCII on purpose: characters outside ASCII
are built with chr() so no escape sequence has to survive being retyped.

One correction to the plan's S3 row, made here on purpose (P78 deviation 16): the row says risky_repo gives
counts.all == 10 ("6 py + 3 manifests + 1 other"), but setup.py is in both walk lists, so the folder holds 9 distinct
files. A file is one row, so the test asserts all == the number of distinct paths walk.walk() returns (9).

The browser tests need Playwright and Chromium; CI has neither, so they skip there and run in the build session's
container and the overseer's. Everything else runs everywhere.
"""
import http.client
import json
import os
import re
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from code_guardian import goal, plain, report, walk

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
FIXTURES = HERE / "fixtures"
UI = ROOT / "code_guardian" / "ui"
VERDICT = re.compile(
    r"is safe|safe to run|\bsecure\b|\bclean\b|no risks|risk-free|\bharmless\b|\bguaranteed\b", re.IGNORECASE)
RISKS = ("High", "Medium", "Low", "No known risks found", "Partly checked", "Not read")
KINDS = ("python", "manifest", "other", "not_read")
LEVELS = ("High", "Medium", "Low", "Quality")
FILTER_LABELS = ("All files", "Files with findings", "No known risks found", "Partly checked", "Not read")
AWS_ID = "AKIA" + "Q7XZ" * 4  # built at runtime: the package's self-scan reads literals

FIVE = {
    "a.py": "def add(x, y):\n    return x + y\n",
    "b.py": 'import os\n\n\ndef run_user_command():\n    command = input("command: ")\n    os.system(command)\n',
    "c.py": "def broken(:\n    pass\n",
    "index.js": "console.log('hi');\n",
}


def _five(tmp_path):
    d = tmp_path / "five"
    d.mkdir()
    for name, text in FIVE.items():
        (d / name).write_text(text, encoding="utf-8")
    (d / "blob.bin").write_bytes(b"\x00\x01" + AWS_ID.encode("ascii") + b"\x00" * 16)
    return d


def _with_goal(tmp_path):
    d = tmp_path / "goal_repo"
    (d / "gen").mkdir(parents=True)
    (d / "main.py").write_text("def main():\n    return 1\n", encoding="utf-8")
    (d / "gen" / "made.py").write_text("X = 1\n", encoding="utf-8")
    (d / goal.FILENAME).write_text(goal.render("demo", ["main.py"], exclude=["gen/*"]), encoding="utf-8")
    return d


def _with_skip_dirs(tmp_path):
    d = tmp_path / "skips"
    (d / ".venv").mkdir(parents=True)
    (d / "node_modules").mkdir()
    (d / "app.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    (d / ".venv" / "x.py").write_text("X = 1\n", encoding="utf-8")
    (d / "node_modules" / "m.js").write_text("module.exports = 1;\n", encoding="utf-8")
    return d


def _distinct(inv):
    return sorted(set(inv["python"]) | set(inv["manifests"]) | set(inv["other"]) | {r for r, _ in inv["skipped"]})


def _inventory(root):
    contract, _ = report._contract(str(root), None)
    return walk.walk(str(root), exclude=contract["exclude"] if contract else ())


def _rows(root):
    return plain.file_rows(report.scan(str(root)), _inventory(root))


class Server:
    def __init__(self):
        from code_guardian import ui
        self.s = ui.make_server(port=0)
        self.t = threading.Thread(target=self.s.serve_forever)
        self.t.start()
        self.port = self.s.server_address[1]

    def call(self, method, path, body=None, token=True, host=None, origin=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=120)
        headers = {"Host": host or "127.0.0.1:%d" % self.port, "Content-Type": "application/json"}
        if token:
            headers["X-CG-Token"] = self.s.token
        if origin:
            headers["Origin"] = origin
        c.request(method, path, None if body is None else json.dumps(body), headers)
        r = c.getresponse()
        raw = r.read()
        c.close()
        try:
            return r.status, json.loads(raw.decode("utf-8"))
        except ValueError:
            return r.status, None

    def scan(self, path):
        status, js = self.call("POST", "/api/scan", {"path": str(path), "goal_file": None})
        assert status == 200, js
        return js["id"]

    def files(self, path):
        status, js = self.call("GET", "/api/files?id=%s" % self.scan(path))
        assert status == 200, js
        return js

    def close(self):
        self.s.shutdown()
        self.s.server_close()
        self.t.join(10)


@pytest.fixture
def srv():
    s = Server()
    yield s
    s.close()


def _by_rel(js):
    return {r["rel"]: r for r in js["files"]}


# ---- GET /api/files ------------------------------------------------------------------------------------------------

def test_risky_repo_lists_every_file_the_scan_saw(srv):
    root = FIXTURES / "risky_repo"
    js = srv.files(root)
    want = _distinct(_inventory(root))
    assert [r["rel"] for r in js["files"]] == want, "one row per distinct file, sorted by rel"
    assert js["counts"]["all"] == len(want) == 9
    rows = _by_rel(js)
    assert rows["web/setup.js"]["risk"] == "Partly checked" and rows["web/setup.js"]["kind"] == "other"
    assert rows["setup.py"]["kind"] in ("python", "manifest")
    assert rows["risky/runner.py"]["risk"] == "High"
    for r in js["files"]:
        assert set(r) >= {"rel", "kind", "why_not_read", "why_partly", "findings", "risk"}, r
        assert r["kind"] in KINDS and r["risk"] in RISKS, r
        assert set(r["findings"]) == set(LEVELS), r
    assert set(js) >= {"files", "counts", "ignored", "excluded"}


def test_the_five_file_repo(srv, tmp_path):
    js = srv.files(_five(tmp_path))
    rows = _by_rel(js)
    assert set(rows) == {"a.py", "b.py", "c.py", "index.js", "blob.bin"}
    assert rows["a.py"]["risk"] == "No known risks found"
    assert rows["b.py"]["risk"] == "High" and rows["b.py"]["findings"]["High"] >= 1
    assert rows["c.py"]["risk"] == "Partly checked" and "parse" in (rows["c.py"]["why_partly"] or "")
    assert rows["index.js"]["risk"] == "Partly checked" and "JavaScript" in (rows["index.js"]["why_partly"] or "")
    assert rows["blob.bin"]["risk"] == "Not read" and rows["blob.bin"]["kind"] == "not_read"
    assert rows["blob.bin"]["why_not_read"] == "binary"
    assert js["counts"] == {"all": 5, "with_findings": 2, "no_known_risks": 1, "partly_checked": 2, "not_read": 1}


def test_goal_file_excludes_are_honoured(srv, tmp_path):
    js = srv.files(_with_goal(tmp_path))
    assert not [r for r in js["files"] if r["rel"].startswith("gen/")], js["files"]
    assert js["excluded"] >= 1
    assert "main.py" in _by_rel(js)


def test_skipped_folders_are_absent(srv, tmp_path):
    rels = set(_by_rel(srv.files(_with_skip_dirs(tmp_path))))
    assert "app.py" in rels
    assert not [r for r in rels if r.startswith(".venv/") or r.startswith("node_modules/")], rels


def test_a_quality_only_file_counts_in_both(srv):
    js = srv.files(FIXTURES / "complete_bare")
    row = _by_rel(js)["app.py"]
    assert row["risk"] == "No known risks found"
    assert row["findings"]["Quality"] >= 1 and not any(row["findings"][k] for k in ("High", "Medium", "Low"))


def test_api_matches_plain_file_rows(srv, tmp_path):
    root = _five(tmp_path)
    js = srv.files(root)
    assert js["files"] == _rows(root)


def test_unknown_id_and_the_guard(srv, tmp_path):
    assert srv.call("GET", "/api/files?id=no-such-scan") == (404, {"error": "scan"})
    sid = srv.scan(_five(tmp_path))
    path = "/api/files?id=%s" % sid
    assert srv.call("GET", path, token=False) == (403, {"error": "token"})
    assert srv.call("GET", path, host="evil.example:80")[0] == 403
    assert srv.call("GET", path, origin="http://evil.example")[0] == 403
    assert srv.call("GET", path)[0] == 200


# ---- plain.file_rows over everything -------------------------------------------------------------------------------

def _all_roots(tmp_path):
    roots = [p for p in sorted(FIXTURES.iterdir()) if p.is_dir()]
    return roots + [_five(tmp_path), _with_goal(tmp_path), _with_skip_dirs(tmp_path)]


def _counts(rows):
    return {"all": len(rows),
            "with_findings": sum(1 for r in rows if any(r["findings"][k] for k in LEVELS)),
            "no_known_risks": sum(1 for r in rows if r["risk"] == "No known risks found"),
            "partly_checked": sum(1 for r in rows if r["risk"] == "Partly checked"),
            "not_read": sum(1 for r in rows if r["risk"] == "Not read")}


def test_no_partly_checked_or_not_read_row_is_ever_no_known_risks(tmp_path):
    for root in _all_roots(tmp_path):
        rows = _rows(root)
        for r in rows:
            if r["kind"] in ("other", "not_read"):
                assert r["risk"] != "No known risks found", (root.name, r)
            if r["kind"] == "not_read":
                assert r["risk"] == "Not read" and r["why_not_read"], (root.name, r)
            if r["risk"] == "Partly checked":
                assert r["why_partly"], (root.name, r)
        c = _counts(rows)
        hml = sum(1 for r in rows if r["risk"] in ("High", "Medium", "Low"))
        assert c["no_known_risks"] + c["partly_checked"] + c["not_read"] == c["all"] - hml, (root.name, c)


def test_counts_in_the_api_reconcile(srv, tmp_path):
    for root in (FIXTURES / "risky_repo", FIXTURES / "works_broken", _five(tmp_path)):
        js = srv.files(root)
        assert js["counts"] == _counts(js["files"]), root.name


def test_no_verdict_words_in_any_row(tmp_path):
    for root in _all_roots(tmp_path):
        for r in _rows(root):
            for value in (r["risk"], r["why_partly"], r["why_not_read"]):
                assert not VERDICT.search(value or ""), (root.name, r)


def test_plain_does_not_change_the_report(tmp_path):
    root = _five(tmp_path)
    rep = report.scan(str(root))
    kept = json.dumps(rep, sort_keys=True)
    plain.file_rows(rep, _inventory(root))
    assert json.dumps(rep, sort_keys=True) == kept


def test_plain_selftest_did_not_shrink():
    r = subprocess.run([sys.executable, "-m", "code_guardian.plain", "--selftest"], cwd=str(ROOT),
                       capture_output=True, text=True, timeout=180, env=dict(os.environ, PYTHONPATH=str(ROOT)))
    assert r.returncode == 0, r.stdout + r.stderr
    m = re.search(r"(\d+) checks, (\d+) passed, 0 failed", r.stdout)
    assert m and m.group(1) == m.group(2) and int(m.group(1)) > 33, r.stdout[-400:]


# ---- the Code screen -----------------------------------------------------------------------------------------------

def test_code_screen_has_the_filter_and_find_box():
    html = (UI / "index.html").read_text(encoding="utf-8")
    js = (UI / "app.js").read_text(encoding="utf-8")
    sel = re.search(r'<select\b[^>]*\bid="file-filter"[^>]*>(.*?)</select>', html, re.S)
    assert sel, "<select id=file-filter>"
    labels = [re.sub(r"<[^>]+>", "", o).strip() for o in re.findall(r"<option\b[^>]*>(.*?)</option>", sel.group(1),
                                                                    re.S)]
    assert len(labels) == 5, labels
    for want, got in zip(FILTER_LABELS, labels):
        assert got.startswith(want), (want, got)
    assert re.search(r'<input\b[^>]*\bid="file-find"[^>]*\btype="search"', html) or \
        re.search(r'<input\b[^>]*\btype="search"[^>]*\bid="file-find"', html), "#file-find"
    assert re.search(r'<h2\b[^>]*\bid="files-title"[^>]*>\s*Files\s*</h2>', html), "<h2 id=files-title>Files</h2>"
    assert "/api/files" in js
    assert "about the whole project" in js


# ---- browser (container only) --------------------------------------------------------------------------------------

@pytest.fixture(scope="module")
def browser():
    sync_api = pytest.importorskip("playwright.sync_api")
    with sync_api.sync_playwright() as pw:
        try:
            b = pw.chromium.launch()
        except Exception as exc:  # no Chromium here
            pytest.skip("no Chromium: %s" % exc)
        yield b
        b.close()


def _code_page(browser, srv, root):
    ctx = browser.new_context(viewport={"width": 1280, "height": 800})
    page = ctx.new_page()
    page.goto("http://127.0.0.1:%d/#t=%s" % (srv.port, srv.s.token))
    page.wait_for_selector("#screen-open:not([hidden]), #screen-result:not([hidden])", timeout=30000)
    page.wait_for_load_state("networkidle")
    if not page.locator("#screen-open").is_visible():
        page.click("#new-check")
        page.wait_for_selector("#screen-open:not([hidden])")
    page.fill("#path", str(root))
    page.click("#scan-button")
    page.wait_for_selector("#screen-result:not([hidden])", timeout=180000)
    page.click("#tabs button[data-screen=code]")
    page.wait_for_selector("#screen-code:not([hidden])")
    page.wait_for_selector("#file-list li", timeout=30000)
    return ctx, page


def _listed(page, names):
    text = page.inner_text("#file-list")
    return {n for n in names if n in text}


def _pick(page, label):
    value = page.evaluate("(want) => { const o = [...document.querySelectorAll('#file-filter option')]"
                          ".find(o => o.textContent.trim().startsWith(want)); return o ? o.value : null; }", label)
    assert value is not None, label
    page.select_option("#file-filter", value)


def test_filters_and_find_box_in_the_browser(browser, srv, tmp_path):
    names = ("a.py", "b.py", "c.py", "index.js", "blob.bin")
    ctx, page = _code_page(browser, srv, _five(tmp_path))
    try:
        assert page.evaluate("document.getElementById('file-filter').selectedOptions[0].textContent").strip() \
            .startswith("Files with findings"), "default filter when a file has findings"
        _pick(page, "No known risks found")
        assert _listed(page, names) == {"a.py"}
        _pick(page, "Partly checked")
        assert _listed(page, names) == {"c.py", "index.js"}
        _pick(page, "Not read")
        assert _listed(page, names) == {"blob.bin"}
        assert "binary" in page.inner_text("#file-list")
        _pick(page, "All files")
        assert _listed(page, names) == set(names)
        _pick(page, "Files with findings")
        page.fill("#file-find", "b")
        assert _listed(page, names) == {"b.py"}
    finally:
        ctx.close()


def test_a_big_folder_shows_the_first_2000(browser, srv, tmp_path):
    big = tmp_path / "big"
    big.mkdir()
    for i in range(2500):
        (big / ("note_%04d.txt" % i)).write_text("n\n", encoding="utf-8")
    ctx, page = _code_page(browser, srv, big)
    try:
        assert re.search(r"first 2,000 of 2,?500", page.inner_text("#screen-code")), "the first 2,000 line"
        assert page.locator("#file-list li").count() <= 2000
    finally:
        ctx.close()
