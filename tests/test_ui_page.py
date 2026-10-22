"""The page's own rules (P76 S3): it reaches only the local API and its own three files, it takes the token from the
link's fragment and nowhere else, and without a token it tells the reader to open the printed link."""
import re

from conftest import ROOT

UI = ROOT / "code_guardian" / "ui"
ALLOWED = {"/api/scan", "/api/scans", "/api/file", "/app.js", "/app.css", "/"}
PREFIX = "/api/"  # the guard in call(), not a URL


def _js():
    return (UI / "app.js").read_text(encoding="utf-8")


def _strings(js):
    return re.findall(r'"((?:[^"\\\n]|\\.)*)"', js) + re.findall(r"'((?:[^'\\\n]|\\.)*)'", js)


def test_every_url_in_the_page_is_the_local_api_or_its_own_files():
    js = _js()
    paths = {s.split("?")[0] for s in _strings(js) if s.startswith("/") and not s.startswith("//")} - {PREFIX}
    assert paths and paths <= ALLOWED, paths - ALLOWED
    assert paths >= {"/api/scan", "/api/scans", "/api/file"}, paths
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
