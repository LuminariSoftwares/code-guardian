"""P78 S4 acceptance -- Browse (plan P78 C6), the refusal list applied (C5) to POST /api/scan and `code-guardian ui
PATH`, the Browse button and its messages, ADR 0009, and one more screenshot.

Written by the overseer BEFORE the build session. The build session must add this file to the PR byte-for-byte and
must not edit it; a PR that changes it fails the section. This file is pure ASCII on purpose.

No test here ever opens a real folder window: the server's dialog runner is replaced by a fake, and the real
DIALOG_SOURCE is run as a child against stub `tkinter` packages written into a temp folder. The one real click is the
owner's, on Windows, at P76 S6.

Also here, as P78 deviation (13): `code-guardian ui --port N` on a port that is already taken exits 2 with one plain
line, not a Python traceback (the plan said "exits 2 as today"; on main it exits 1 with a traceback).
"""
import http.client
import io
import json
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from code_guardian import refuse

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
UI = ROOT / "code_guardian" / "ui"
SHOTS = ROOT / "docs" / "screenshots"
ADR = ROOT / "docs" / "adr"
HOME = os.path.expanduser("~")
NO_TK = "this Python has no tkinter"
NO_DISPLAY = "no display to open a window on"
SHOT_SCREENS = ("open", "result", "fixfirst", "findings", "code", "diff")
SHOTS_ALL = ({"%s_%s.png" % (s, z) for s in SHOT_SCREENS for z in ("390x844", "520x900", "1280x800")}
             | {"rail_mini_1280x800.png", "settings_390x844.png", "settings_1280x800.png",
                "result_light_390x844.png", "result_light_1280x800.png", "browse_refused_390x844.png"})
SHOTS_ALL |= {"result_js_dark_390x844.png", "result_js_light_390x844.png", "findings_js_dark_1280x800.png", "findings_js_light_1280x800.png"}  # P81 S5


class Done:
    def __init__(self, returncode, stdout=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, ""


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

    def browse(self, start=None):
        return self.call("POST", "/api/browse", {"start": start})

    def close(self):
        self.s.shutdown()
        self.s.server_close()
        self.t.join(10)


@pytest.fixture
def srv():
    s = Server()
    yield s
    s.close()


def _runner(code, out="", calls=None):
    def run(args, **kw):
        if calls is not None:
            calls.append((list(args), kw))
        return Done(code, out)
    return run


# ---- POST /api/browse with a fake runner ---------------------------------------------------------------------------

def test_browse_chosen_and_allowed(srv, tmp_path):
    calls = []
    srv.s.dialog_runner = _runner(0, str(tmp_path) + "\n", calls)
    status, js = srv.browse(str(tmp_path))
    assert status == 200 and js == {"path": str(tmp_path), "refused": None}, js
    from code_guardian import ui
    args, kw = calls[0]
    assert args[:4] == [sys.executable, "-I", "-c", ui.DIALOG_SOURCE] and args[4] == str(tmp_path), args
    assert kw.get("timeout") == 600 and kw.get("capture_output") is True and kw.get("text") is True, kw


def test_browse_start_defaults_to_home(srv, tmp_path):
    calls = []
    srv.s.dialog_runner = _runner(1, "", calls)
    srv.browse(None)
    assert calls and calls[0][0][4] == HOME


def test_browse_chosen_but_refused(srv):
    drive = "C:" + chr(92) if os.name == "nt" else "/"
    srv.s.dialog_runner = _runner(0, drive + "\n")
    status, js = srv.browse(None)
    assert status == 200 and js["path"] and js["refused"] == refuse.refused(drive), js
    assert js["refused"].startswith("That is a whole drive")


@pytest.mark.parametrize("code,want", [
    (1, (200, {"path": None, "cancelled": True})),
    (3, (501, {"error": "no_dialog", "detail": NO_TK})),
    (4, (501, {"error": "no_dialog", "detail": NO_DISPLAY})),
    (7, (501, {"error": "no_dialog", "detail": "the folder window could not open (exit 7)"})),
])
def test_browse_exit_codes(srv, code, want):
    srv.s.dialog_runner = _runner(code)
    assert srv.browse(None) == want


def test_browse_timeout_is_cancelled(srv):
    def run(args, **kw):
        raise subprocess.TimeoutExpired(args, kw.get("timeout"))
    srv.s.dialog_runner = run
    assert srv.browse(None) == (200, {"path": None, "cancelled": True})


def test_one_dialog_at_a_time(srv, tmp_path):
    entered, release = threading.Event(), threading.Event()

    def slow(args, **kw):
        entered.set()
        release.wait(30)
        return Done(1)
    srv.s.dialog_runner = slow
    first = {}
    t = threading.Thread(target=lambda: first.setdefault("r", srv.browse(None)))
    t.start()
    try:
        assert entered.wait(30), "the first call never reached the runner"
        assert srv.browse(None) == (409, {"error": "busy"})
    finally:
        release.set()
        t.join(30)
    assert first["r"] == (200, {"path": None, "cancelled": True})


def test_browse_needs_the_token(srv):
    srv.s.dialog_runner = _runner(1)
    assert srv.call("POST", "/api/browse", {"start": None}, token=False) == (403, {"error": "token"})


# ---- the real DIALOG_SOURCE, against stub tkinter packages ---------------------------------------------------------

STUB_NO_TK = "raise ImportError('stub: no tkinter')\n"
STUB_TK = (
    "class TclError(Exception):\n    pass\n\n\n"
    "class Tk:\n"
    "    def __init__(self):\n        if MODE == 'nodisplay':\n            raise TclError('stub: no display')\n\n"
    "    def __getattr__(self, name):\n"
    "        return lambda *a, **kw: None\n"
)
STUB_DIALOG = (
    "import tkinter\n\n\n"
    "def askdirectory(**kw):\n"
    "    return {'pick': kw.get('initialdir', ''), 'cancel': ''}.get(tkinter.MODE, '')\n"
)


def _stub(tmp_path, mode):
    d = tmp_path / ("stub_" + mode)
    (d / "tkinter").mkdir(parents=True)
    if mode == "notk":
        (d / "tkinter" / "__init__.py").write_text(STUB_NO_TK, encoding="utf-8")
    else:
        (d / "tkinter" / "__init__.py").write_text("MODE = %r\n\n\n" % mode + STUB_TK, encoding="utf-8")
        (d / "tkinter" / "filedialog.py").write_text(STUB_DIALOG, encoding="utf-8")
    return d


def _run_source(tmp_path, mode, start):
    from code_guardian import ui
    d = _stub(tmp_path, mode)
    env = dict(os.environ, PYTHONPATH=str(d))
    # no -I here on purpose: -I would ignore PYTHONPATH and find the real tkinter
    return subprocess.run([sys.executable, "-c", ui.DIALOG_SOURCE, start], cwd=str(d), env=env,
                          capture_output=True, text=True, timeout=60)


def test_dialog_source_exit_codes(tmp_path):
    from code_guardian import ui
    assert len(ui.DIALOG_SOURCE.strip().splitlines()) <= 25
    assert _run_source(tmp_path, "notk", str(tmp_path)).returncode == 3
    assert _run_source(tmp_path, "nodisplay", str(tmp_path)).returncode == 4
    picked = _run_source(tmp_path, "pick", str(tmp_path))
    assert picked.returncode == 0 and picked.stdout.strip() == str(tmp_path), (picked.stdout, picked.stderr)
    assert _run_source(tmp_path, "cancel", str(tmp_path)).returncode == 1


# ---- refusals on POST /api/scan and `code-guardian ui PATH` ---------------------------------------------------------

def test_scan_refuses_home_before_reading(srv, tmp_path):
    status, js = srv.call("POST", "/api/scan", {"path": HOME, "goal_file": None})
    assert status == 400 and js == {"error": "refused", "detail": refuse.refused(HOME)}, js
    assert srv.call("GET", "/api/scans")[1] == []
    (tmp_path / "a.py").write_text("X = 1\n", encoding="utf-8")
    assert srv.call("POST", "/api/scan", {"path": str(tmp_path), "goal_file": None})[0] == 200


def _cli(*args):
    return subprocess.run([sys.executable, "-m", "code_guardian", "ui"] + list(args), cwd=str(ROOT),
                          capture_output=True, text=True, timeout=60, env=dict(os.environ, PYTHONPATH=str(ROOT)))


def test_ui_path_refuses_home_and_opens_no_socket():
    r = _cli(HOME, "--no-browser")
    assert r.returncode == 2, (r.stdout, r.stderr)
    assert ("code-guardian: " + refuse.refused(HOME)) in r.stderr
    assert "http://" not in r.stdout and "Traceback" not in r.stderr


def test_busy_port_exits_2_without_a_traceback():
    held = socket.socket()
    held.bind(("127.0.0.1", 0))
    held.listen(1)
    try:
        r = _cli("--port", str(held.getsockname()[1]), "--no-browser")
    finally:
        held.close()
    assert r.returncode == 2, (r.stdout, r.stderr)
    assert "Traceback" not in r.stderr and r.stderr.strip().startswith("code-guardian: "), r.stderr
    assert len(r.stderr.strip().splitlines()) == 1, r.stderr


def test_ui_selftest_never_starts_a_process(monkeypatch):
    from code_guardian import ui

    def boom(*a, **kw):
        raise AssertionError("ui --selftest started a process")
    monkeypatch.setattr(subprocess, "run", boom)
    monkeypatch.setattr(subprocess, "Popen", boom)
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = ui.selftest()
    out = buf.getvalue()
    assert rc == 0, out
    m = re.search(r"(\d+) checks, (\d+) passed, 0 failed", out)
    assert m and m.group(1) == m.group(2) and int(m.group(1)) >= 24, out[-400:]


# ---- the page, the ADR, the screenshot -----------------------------------------------------------------------------

def test_page_has_browse_and_its_hint():
    html = (UI / "index.html").read_text(encoding="utf-8")
    js = (UI / "app.js").read_text(encoding="utf-8")
    assert re.search(r'<button\b[^>]*\btype="button"[^>]*\bid="browse"', html) or \
        re.search(r'<button\b[^>]*\bid="browse"[^>]*\btype="button"', html), "#browse"
    hint = re.search(r'\bid="browse-hint"[^>]*>(.*?)<', html, re.S)
    assert hint and "Opens a folder window on the computer running code-guardian." in hint.group(1), hint
    assert "/api/browse" in js
    assert "paste the path instead" in js or "paste the path instead" in html


def test_adr_0009():
    adr = list(ADR.glob("0009-*.md"))
    assert len(adr) == 1, adr
    text = adr[0].read_text(encoding="utf-8")
    for word in ("tkinter", "refuse", "127.0.0.1", "/api/scan"):
        assert word in text, word
    assert "0009" in (ADR / "README.md").read_text(encoding="utf-8")


def test_screenshots_count_24():
    have = {p.name for p in SHOTS.glob("*.png")}
    assert have == SHOTS_ALL, (sorted(SHOTS_ALL - have), sorted(have - SHOTS_ALL))
    p = SHOTS / "browse_refused_390x844.png"
    assert p.stat().st_size > 10 * 1024
    with open(p, "rb") as fh:
        head = fh.read(24)
    assert head[:8] == b"\x89PNG\r\n\x1a\n" and struct.unpack(">II", head[16:24])[0] in (390, 780, 1170)


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


def _open_screen(browser, srv):
    ctx = browser.new_context(viewport={"width": 390, "height": 844})
    page = ctx.new_page()
    page.goto("http://127.0.0.1:%d/#t=%s" % (srv.port, srv.s.token))
    page.wait_for_selector("#screen-open:not([hidden])", timeout=30000)
    page.wait_for_load_state("networkidle")
    return ctx, page


def test_a_501_hides_browse_for_the_session(browser, srv):
    ctx, page = _open_screen(browser, srv)
    try:
        page.route("**/api/browse", lambda route: route.fulfill(
            status=501, content_type="application/json", body=json.dumps({"error": "no_dialog", "detail": NO_TK})))
        assert page.locator("#browse").is_visible()
        page.click("#browse")
        page.wait_for_selector("#browse", state="hidden", timeout=10000)
        assert page.locator("#browse-hint").is_hidden()
        assert "paste the path instead" in page.inner_text("#screen-open")
    finally:
        ctx.close()


def test_a_refused_answer_shows_the_sentence_and_leaves_the_field_empty(browser, srv):
    sentence = "That is a whole drive. Pick the folder your project is in."
    ctx, page = _open_screen(browser, srv)
    try:
        page.route("**/api/browse", lambda route: route.fulfill(
            status=200, content_type="application/json", body=json.dumps({"path": "/", "refused": sentence})))
        page.click("#browse")
        page.wait_for_selector("#screen-open :text('%s')" % sentence, timeout=10000)
        assert page.input_value("#path") == ""
        assert page.locator("#screen-result").is_hidden()
    finally:
        ctx.close()


def test_a_typed_home_path_shows_the_refusal(browser, srv):
    ctx, page = _open_screen(browser, srv)
    try:
        page.fill("#path", HOME)
        page.click("#scan-button")
        sentence = refuse.refused(HOME)
        deadline = time.time() + 20
        while sentence not in page.inner_text("#screen-open") and time.time() < deadline:
            page.wait_for_timeout(200)
        assert sentence in page.inner_text("#screen-open")
        assert page.locator("#screen-result").is_hidden()
    finally:
        ctx.close()
