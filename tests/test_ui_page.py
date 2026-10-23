"""The page's own rules (P76 S3): it reaches only the local API and its own three files, it takes the token from the
link's fragment and nowhere else, and without a token it tells the reader to open the printed link."""
import json
import re

from conftest import ROOT

UI = ROOT / "code_guardian" / "ui"
ALLOWED = {"/api/scan", "/api/scans", "/api/file", "/api/explain", "/app.js", "/app.css", "/"}
PREFIX = "/api/"  # the guard in call(), not a URL


def _js():
    return (UI / "app.js").read_text(encoding="utf-8")


def _strings(js):
    return re.findall(r'"((?:[^"\\\n]|\\.)*)"', js) + re.findall(r"'((?:[^'\\\n]|\\.)*)'", js)


def test_every_url_in_the_page_is_the_local_api_or_its_own_files():
    js = _js()
    paths = {s.split("?")[0] for s in _strings(js) if s.startswith("/") and not s.startswith("//")} - {PREFIX}
    assert paths and paths <= ALLOWED, paths - ALLOWED
    assert paths >= {"/api/scan", "/api/scans", "/api/file", "/api/explain"}, paths
    html = (UI / "index.html").read_text(encoding="utf-8")
    refs = set(re.findall(r'\b(?:src|href|action)="([^"]*)"', html))
    assert refs <= ALLOWED, refs - ALLOWED
    for text in (js, html):
        assert not re.search(r"https?:|//[a-z0-9]|\bws:|wss:", text, re.I)


def test_every_request_goes_through_one_api_function():
    js = _js()
    assert js.count("fetch(") == 1, "only call() may fetch"
    assert 'url.indexOf("/api/") !== 0' in js, "call() must refuse anything outside /api/"
    for banned in ("XMLHttpRequest", "WebSocket", "EventSource", "sendBeacon", "import(", ".innerHTML", "eval("):
        assert banned not in js, banned


def test_the_token_is_read_only_from_the_fragment():
    js = _js()
    for banned in ("location.search", "localStorage", "sessionStorage", "document.cookie", "indexedDB", "URLSearchParams"):
        assert banned not in js, banned
    assert re.search(r"window\.location\.hash", js)
    reads = re.findall(r"function readToken\(\) \{(.*?)\n  \}", js, re.S)
    assert len(reads) == 1 and "location.hash" in reads[0]
    assert len(re.findall(r"\blocation\.(?!hash|href)\w+", js)) == 0
    # the token goes in the header, never into a URL
    assert '"X-CG-Token": state.token' in js
    assert not re.search(r"[?&]t(oken)?=", js.replace("#t=", ""))


def test_no_token_screen_says_to_open_the_printed_link():
    html = (UI / "index.html").read_text(encoding="utf-8")
    m = re.search(r'<section id="screen-notoken".*?</section>', html, re.S)
    assert m and "Open the link printed in the terminal" in m.group(0)
    js = _js()
    assert re.search(r'if \(!state\.token\) return noToken\(\);', js)


def test_no_token_message_renders_in_a_browser():
    """Loads the real page without a fragment in Chromium when Playwright is installed (dev only)."""
    import pytest
    sync = pytest.importorskip("playwright.sync_api")
    import threading

    from code_guardian import ui
    server = ui.make_server(port=0)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        with sync.sync_playwright() as pw:
            try:
                browser = pw.chromium.launch()
            except Exception as exc:  # no browser on this machine
                pytest.skip("no Chromium: %s" % type(exc).__name__)
            page = browser.new_page(viewport={"width": 390, "height": 844})
            page.goto("http://127.0.0.1:%d/" % server.server_address[1])
            page.wait_for_selector("#screen-notoken:not([hidden])")
            assert "Open the link printed in the terminal" in page.inner_text("#screen-notoken")
            assert page.is_hidden("#screen-open")
            assert page.evaluate("document.documentElement.scrollWidth") <= 390
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        t.join(10)


# ---- the Code screen: pick lines, see where they go, send, read the answer (P76 S4; Chromium when available) -------

def _code_screen(tmp_path, monkeypatch, model_url=None):
    """Yield-style helper: (page, server, close) on the Code screen of a copy of the risky fixture whose runner has
    300 lines. Skips when Playwright or Chromium is missing."""
    import os
    import shutil
    import threading

    import pytest
    sync = pytest.importorskip("playwright.sync_api")
    from code_guardian import ui
    for k in ("CODE_GUARDIAN_LLM_URL", "CODE_GUARDIAN_LLM_MODEL", "CODE_GUARDIAN_LLM_KEY"):
        monkeypatch.delenv(k, raising=False)
    if model_url:
        monkeypatch.setenv("CODE_GUARDIAN_LLM_URL", model_url + "/api/chat")
        monkeypatch.setenv("CODE_GUARDIAN_LLM_MODEL", "tiny")
    project = tmp_path / "proj"
    shutil.copytree(ROOT / "tests" / "fixtures" / "risky_repo", project)
    runner = project / "risky" / "runner.py"
    runner.write_text(runner.read_text(encoding="utf-8") + "".join("# pad %d\n" % i for i in range(300)),
                      encoding="utf-8")
    server = ui.make_server(port=0)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    pw = sync.sync_playwright().start()
    exe = os.environ.get("CG_CHROMIUM")
    try:
        browser = pw.chromium.launch(executable_path=exe) if exe else pw.chromium.launch()
    except Exception as exc:  # no browser on this machine
        pw.stop()
        server.shutdown()
        server.server_close()
        pytest.skip("no Chromium: %s" % type(exc).__name__)
    page = browser.new_page(viewport={"width": 390, "height": 844})
    page.goto("http://127.0.0.1:%d/#t=%s" % (server.server_address[1], server.token))
    page.fill("#path", str(project))
    page.click("#scan-button")
    page.wait_for_selector("#screen-result:not([hidden])", timeout=60000)
    page.click("#tabs button[data-screen=code]")
    page.click("#file-list .file-btn[data-rel='risky/runner.py']")
    page.wait_for_selector("#L7")

    def close():
        browser.close()
        pw.stop()
        server.shutdown()
        server.server_close()
        t.join(10)
    return page, close


def test_code_screen_pick_preview_send_and_answer(stub, tmp_path, monkeypatch):
    model = stub({("POST", "/api/chat"): (200, {"message": {"content": "Sample answer from a test model."}}, 0)})
    page, close = _code_screen(tmp_path, monkeypatch, model.url)
    try:
        assert page.is_disabled("#explain")
        # typing highlights those lines; the button wakes up
        page.fill("#line-start", "3")
        page.fill("#line-end", "5")
        assert page.eval_on_selector_all("#code .line.picked", "els => els.map(e => e.id)") == ["L3", "L4", "L5"]
        assert page.is_enabled("#explain")
        # dragging fills the fields
        page.evaluate("""() => {
            const r = document.createRange();
            r.setStart(document.querySelector('#L7 .src'), 0);
            r.setEnd(document.querySelector('#L9 .src'), 1);
            const s = window.getSelection(); s.removeAllRanges(); s.addRange(r);
        }""")
        page.wait_for_selector("#selection-note:has-text('Lines 7')")
        assert (page.input_value("#line-start"), page.input_value("#line-end")) == ("7", "9")
        # step 1: the panel says where the lines would go, and nothing has been sent
        page.click("#explain")
        page.wait_for_selector("#explain-body button.primary")
        host = model.url.split("//")[1]
        assert page.inner_text("#explain-body p") == \
            "These 3 lines go to your model at %s (tiny). Nothing else is sent." % host
        assert model.requests == []
        # step 2: send, then the answer under the fixed heading
        page.click("#explain-body button.primary")
        page.wait_for_selector("#explain-body .explain-body-text")
        assert page.inner_text("#explain-body .explain-body-text") == "Sample answer from a test model."
        assert "AI explanation — may be wrong; does not change any score" in page.inner_text("#explain-panel h3")
        assert len(model.requests) == 1
        sent = json.loads(model.requests[0][2]["messages"][1]["content"])
        assert (sent["file"], sent["start"], sent["end"]) == ("risky/runner.py", 7, 9)
        assert sent["code"].count("\n") == 2
        # changing the lines closes the stale answer
        page.fill("#line-end", "10")
        assert page.is_hidden("#explain-panel")
    finally:
        close()


def test_code_screen_clamps_and_explains_in_plain_words(tmp_path, monkeypatch):
    page, close = _code_screen(tmp_path, monkeypatch)
    try:
        page.fill("#line-start", "1")
        page.fill("#line-end", "250")
        assert page.input_value("#line-end") == "200"
        assert "Up to 200 lines" in page.inner_text("#range-msg")
        page.fill("#line-end", "99999")
        assert int(page.input_value("#line-end")) <= 200
        page.fill("#line-start", "400")
        assert "This file has" in page.inner_text("#range-msg")
        page.fill("#line-start", "5")
        page.fill("#line-end", "2")
        assert "cannot come before" in page.inner_text("#range-msg")
        assert page.is_disabled("#explain")
        # with no model set up the panel says the one step and offers no Send button
        page.fill("#line-start", "2")
        page.fill("#line-end", "4")
        page.click("#explain")
        page.wait_for_selector("#explain-body:has-text('then restart code-guardian ui')")
        assert page.inner_text("#explain-body") == \
            "set CODE_GUARDIAN_LLM_URL and CODE_GUARDIAN_LLM_MODEL, then restart code-guardian ui"
        assert page.query_selector("#explain-body button") is None
    finally:
        close()
