"""P78 S5 acceptance -- re-open vs re-check (plan P78 C7): GET /api/scan?id=, POST /api/open, the page opening stored
results without reading the folder again, saved-check mode, and "Checked at".

Written by the overseer BEFORE the build session. The build session must add this file to the PR byte-for-byte and
must not edit it; a PR that changes it fails the section. This file is pure ASCII on purpose.

The rule this file proves with a counter on report.scan: the only route that reads a folder is POST /api/scan, and the
only page actions that call it are the Open form, the Browse result, `code-guardian ui PATH` at start and the two
"Check again" buttons. Page load, a recent-list click and "Open a saved check" read nothing.

The browser test needs Playwright and Chromium; CI has neither, so it skips there and runs in the build session's
container and the overseer's. Everything else runs everywhere.
"""
import http.client
import io
import json
import os
import re
import subprocess
import sys
import threading
from contextlib import redirect_stdout
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
FIXTURES = HERE / "fixtures"
UI = ROOT / "code_guardian" / "ui"
SAVED_NOTE = "This is a saved check. The files are not open here; check the folder to see them."


class Server:
    def __init__(self):
        from code_guardian import ui
        self.s = ui.make_server(port=0)
        self.t = threading.Thread(target=self.s.serve_forever)
        self.t.start()
        self.port = self.s.server_address[1]

    def call(self, method, path, body=None, token=True):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=120)
        headers = {"Host": "127.0.0.1:%d" % self.port, "Content-Type": "application/json"}
        if token:
            headers["X-CG-Token"] = self.s.token
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


@pytest.fixture(scope="module")
def saved_json(tmp_path_factory):
    r = subprocess.run([sys.executable, "-m", "code_guardian", "scan", str(FIXTURES / "risky_repo"), "--json"],
                       cwd=str(ROOT), capture_output=True, text=True, timeout=180,
                       env=dict(os.environ, PYTHONPATH=str(ROOT)))
    assert r.stdout.strip().startswith("{"), r.stderr[-500:]
    path = tmp_path_factory.mktemp("saved") / "before.json"
    path.write_text(r.stdout, encoding="utf-8")
    return path


# ---- GET /api/scan?id= ---------------------------------------------------------------------------------------------

def test_get_scan_returns_what_the_post_returned(srv):
    status, posted = srv.call("POST", "/api/scan", {"path": str(FIXTURES / "risky_repo"), "goal_file": None})
    assert status == 200
    status, got = srv.call("GET", "/api/scan?id=%s" % posted["id"])
    assert status == 200, got
    assert got["id"] == posted["id"] and got["report"] == posted["report"] and got["plain"] == posted["plain"]
    assert got["saved"] is False
    assert isinstance(got["files"], dict) and got["files"]["counts"]["all"] >= 1


def test_get_scan_unknown_and_guarded(srv):
    assert srv.call("GET", "/api/scan?id=no-such-scan") == (404, {"error": "scan"})
    assert srv.call("GET", "/api/scan?id=no-such-scan", token=False) == (403, {"error": "token"})


# ---- POST /api/open ------------------------------------------------------------------------------------------------

def test_open_a_saved_check(srv, saved_json):
    status, js = srv.call("POST", "/api/open", {"json": saved_json.read_text(encoding="utf-8")})
    assert status == 200, js
    assert js["saved"] is True and js["files"] is None and js["report"]["scores"] and "plain" in js
    entry = [e for e in srv.call("GET", "/api/scans")[1] if e["id"] == js["id"]]
    assert entry and entry[0]["state"] == "done" and entry[0].get("saved") is True, entry
    assert srv.call("GET", "/api/file?id=%s&rel=setup.py" % js["id"]) == (404, {"error": "scan"})
    assert srv.call("GET", "/api/files?id=%s" % js["id"]) == (404, {"error": "scan"})
    again = srv.call("GET", "/api/scan?id=%s" % js["id"])
    assert again[0] == 200 and again[1]["saved"] is True and again[1]["report"] == js["report"]


def test_open_refuses_what_is_not_a_saved_check(srv):
    status, js = srv.call("POST", "/api/open", {"json": "{"})
    assert status == 400 and js["error"] == "json", js
    assert srv.call("POST", "/api/open", {"json": json.dumps({"hello": 1})})[0] == 400
    assert srv.call("POST", "/api/open", {})[0] == 400
    assert srv.call("POST", "/api/open", {"json": "{}"}, token=False) == (403, {"error": "token"})


def test_open_never_reads_a_folder(srv, saved_json, monkeypatch):
    from code_guardian import ui
    calls = []
    real = ui.report.scan
    monkeypatch.setattr(ui.report, "scan", lambda *a, **kw: calls.append(a) or real(*a, **kw))
    assert srv.call("POST", "/api/open", {"json": saved_json.read_text(encoding="utf-8")})[0] == 200
    assert calls == []


# ---- the page --------------------------------------------------------------------------------------------------------

def test_page_wiring():
    html = (UI / "index.html").read_text(encoding="utf-8")
    js = (UI / "app.js").read_text(encoding="utf-8")
    assert re.search(r'<input\b[^>]*\btype="file"[^>]*\bid="open-saved"', html) or \
        re.search(r'<input\b[^>]*\bid="open-saved"[^>]*\btype="file"', html), "#open-saved"
    assert "/api/open" in js and "/api/scan?id=" in js
    assert 'title="Reads the files again now"' in html or "Reads the files again now" in js
    assert SAVED_NOTE in html or SAVED_NOTE in js
    assert "Checked at" in js and "Saved check from" in js


def test_ui_selftest_count():
    from code_guardian import ui
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = ui.selftest()
    out = buf.getvalue()
    m = re.search(r"(\d+) checks, (\d+) passed, 0 failed", out)
    assert rc == 0 and m and m.group(1) == m.group(2) and int(m.group(1)) >= 26, out[-400:]


# ---- browser (container only): the call counter --------------------------------------------------------------------

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


def test_only_check_again_reads_the_folder(browser, saved_json, monkeypatch):
    from code_guardian import ui
    calls = []
    real = ui.report.scan
    monkeypatch.setattr(ui.report, "scan", lambda *a, **kw: calls.append(a) or real(*a, **kw))
    srv = Server()
    ctx = browser.new_context(viewport={"width": 1280, "height": 800})
    page = ctx.new_page()
    try:
        srv.s.scan(str(FIXTURES / "risky_repo"))  # what `code-guardian ui PATH` does before the page opens
        assert len(calls) == 1

        page.goto("http://127.0.0.1:%d/#t=%s" % (srv.port, srv.s.token))
        page.wait_for_selector("#screen-result:not([hidden])", timeout=30000)
        page.wait_for_load_state("networkidle")
        assert len(calls) == 1, "page load read the folder again"
        assert page.inner_text("#rail-when").strip().startswith("Checked at")
        assert page.get_attribute("#check-again", "title") == "Reads the files again now"

        page.click("#new-check")
        page.wait_for_selector("#recent li")
        page.locator("#recent li").first.click()
        page.wait_for_selector("#screen-result:not([hidden])", timeout=30000)
        page.wait_for_load_state("networkidle")
        assert len(calls) == 1, "a recent-list click read the folder again"

        page.click("#check-again")
        page.wait_for_selector("#check-again:not([disabled])", timeout=120000)
        page.wait_for_load_state("networkidle")
        assert len(calls) == 2, "Check again must read the folder exactly once (%d calls)" % (len(calls) - 1)

        page.click("#new-check")
        page.wait_for_selector("#screen-open:not([hidden])")
        page.set_input_files("#open-saved", str(saved_json))
        page.wait_for_selector("#screen-result:not([hidden])", timeout=30000)
        page.wait_for_load_state("networkidle")
        assert len(calls) == 2, "opening a saved check read a folder"
        assert page.inner_text("#rail-when").strip().startswith("Saved check from")

        page.click("#tabs button[data-screen=code]")
        page.wait_for_selector("#screen-code:not([hidden])")
        assert SAVED_NOTE in page.inner_text("#screen-code")
        for control in ("#file-filter", "#file-find"):
            assert page.locator(control).is_disabled(), control
        assert len(calls) == 2
    finally:
        ctx.close()
        srv.close()
