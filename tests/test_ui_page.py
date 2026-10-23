"""The page's own rules (P76 S3): it reaches only the local API and its own three files, it takes the token from the
link's fragment and nowhere else, and without a token it tells the reader to open the printed link. P78 S1 adds the
Settings panel: what it stores, where, and that it applies before the page is drawn."""
import contextlib
import json
import re

import pytest
from conftest import ROOT

UI = ROOT / "code_guardian" / "ui"
ALLOWED = {"/api/scan", "/api/scans", "/api/files", "/api/file", "/api/explain", "/api/diff", "/api/browse",
           "/api/open", "/app.js", "/app.css", "/"}
PREFIX = "/api/"  # the guard in call(), not a URL
LUMINARI = "https://github.com/LuminariSoftwares"  # the one outside address the page names: a plain link, never fetched


def _js():
    return (UI / "app.js").read_text(encoding="utf-8")


def _strings(js):
    return re.findall(r'"((?:[^"\\\n]|\\.)*)"', js) + re.findall(r"'((?:[^'\\\n]|\\.)*)'", js)


def test_every_url_in_the_page_is_the_local_api_or_its_own_files():
    js = _js()
    paths = {s.split("?")[0] for s in _strings(js) if s.startswith("/") and not s.startswith("//")} - {PREFIX}
    assert paths and paths <= ALLOWED, paths - ALLOWED
    assert paths >= {"/api/scan", "/api/scans", "/api/files", "/api/file", "/api/explain", "/api/diff"}, paths
    html = (UI / "index.html").read_text(encoding="utf-8")
    link = re.search(r'<a\b[^>]*\bid="luminari"[^>]*>', html)
    assert html.count(LUMINARI) == 1 and link and 'href="%s"' % LUMINARI in link.group(0), "the Luminari link, once"
    refs = set(re.findall(r'\b(?:src|href|action)="([^"]*)"', html)) - {LUMINARI}
    assert refs <= ALLOWED, refs - ALLOWED
    for text in (js, html.replace(LUMINARI, "")):
        assert not re.search(r"https?:|//[a-z0-9]|\bws:|wss:", text, re.I)


def test_every_request_goes_through_one_api_function():
    js = _js()
    assert js.count("fetch(") == 1, "only call() may fetch"
    assert 'url.indexOf("/api/") !== 0' in js, "call() must refuse anything outside /api/"
    for banned in ("XMLHttpRequest", "WebSocket", "EventSource", "sendBeacon", "import(", ".innerHTML", "eval("):
        assert banned not in js, banned


def test_the_token_is_read_only_from_the_fragment():
    js = _js()
    for banned in ("location.search", "sessionStorage", "document.cookie", "indexedDB", "URLSearchParams"):
        assert banned not in js, banned
    # the person's own choices are the only things the page keeps in the browser: the settings and whether the summary
    # column is open or a slim rail (P78 S2), each under one key, read and written in two small functions, never the token
    assert 'var STORE_KEY = "cg.settings";' in js and 'var RAIL_KEY = "cg.rail";' in js
    stores = re.findall(r"localStorage\.(\w+)\(([^)]*)\)", js)
    assert sorted(method for method, _ in stores) == ["getItem", "getItem", "setItem", "setItem"], stores
    assert sorted(args.split(",")[0] for _, args in stores) == ["RAIL_KEY", "RAIL_KEY", "STORE_KEY", "STORE_KEY"], stores
    assert not re.search(r"setItem\([^)]*token", js, re.I)
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


# ---- the Compare screen (P76 S5) ----------------------------------------------------------------------------------

AWS_ID = "AKIA" + "Q7XZ" * 4  # built at runtime: the package's self-scan reads literals
WITH_KEY = 'import os\n\nKEY = "%s"\n\n\ndef run(cmd):\n    os.system(cmd)\n' % AWS_ID
WITHOUT_KEY = 'import os\n\n\ndef run(cmd):\n    os.system(cmd)\n'


def test_compare_screen_markup_and_wiring():
    html = (UI / "index.html").read_text(encoding="utf-8")
    m = re.search(r'<section id="screen-compare".*?\n</section>', html, re.S)
    assert m, "the Compare screen"
    screen = m.group(0)
    assert "later version" not in screen
    for needed in ('id="pick-before"', 'id="pick-after"', 'id="compare-sentence"', 'id="list-fixed"', 'id="list-new"',
                   'id="list-unchanged"', ">Fixed<", ">New<", ">Still there<"):
        assert needed in screen, needed
    assert len(re.findall(r'<input type="file" id="file-(?:before|after)" accept="\.json,application/json">', screen)) == 2
    js = _js()
    assert "FileReader" in js and "readAsText" in js and "New High" in js


def _browser(sync):
    import os
    import pytest
    pw = sync.sync_playwright().start()
    exe = os.environ.get("CG_CHROMIUM")
    try:
        return pw, pw.chromium.launch(executable_path=exe) if exe else pw.chromium.launch()
    except Exception as exc:  # no browser on this machine
        pw.stop()
        pytest.skip("no Chromium: %s" % type(exc).__name__)


def test_check_again_then_compare_shows_what_was_fixed(tmp_path):
    import threading

    import pytest
    sync = pytest.importorskip("playwright.sync_api")
    from code_guardian import ui
    project = tmp_path / "proj"
    project.mkdir()
    (project / "app.py").write_text(WITH_KEY, encoding="utf-8")
    server = ui.make_server(port=0)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    pw, browser = _browser(sync)
    try:
        page = browser.new_page(viewport={"width": 390, "height": 844})
        page.goto("http://127.0.0.1:%d/#t=%s" % (server.server_address[1], server.token))
        page.fill("#path", str(project))
        page.click("#scan-button")
        page.wait_for_selector("#screen-result:not([hidden])", timeout=60000)
        page.click("#tabs button[data-screen=compare]")
        assert "same check" in page.inner_text("#pick-hint") and page.is_disabled("#pick-compare")
        rail_before = page.inner_text("#rail-grade")
        (project / "app.py").write_text(WITHOUT_KEY, encoding="utf-8")
        page.click("#rail-toggle")  # on a phone the strip starts collapsed; Check again is in its details
        page.click("#check-again")
        page.wait_for_selector("#compare-result:not([hidden])", timeout=60000)
        assert page.inner_text("#compare-sentence").startswith("1 fixed, 0 new, grade ")
        fixed = page.inner_text("#list-fixed")
        assert "High" in fixed and "app.py at line 3" in fixed
        assert page.inner_text("#list-new") == "None."
        assert page.inner_text("#rail-grade") != rail_before  # the rail shows the newer check
        assert page.evaluate("document.documentElement.scrollWidth") <= 390
    finally:
        browser.close()
        pw.stop()
        server.shutdown()
        server.server_close()
        t.join(10)


def test_two_saved_files_compare_and_a_new_high_stands_out(tmp_path):
    import threading

    import pytest
    sync = pytest.importorskip("playwright.sync_api")
    from code_guardian import report, ui
    project = tmp_path / "proj"
    project.mkdir()
    saved = []
    for name, src in (("old.json", WITHOUT_KEY), ("new.json", WITH_KEY)):
        (project / "app.py").write_text(src, encoding="utf-8")
        (tmp_path / name).write_text(json.dumps(report.scan(str(project))), encoding="utf-8")
        saved.append(str(tmp_path / name))
    server = ui.make_server(port=0)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    pw, browser = _browser(sync)
    try:
        page = browser.new_page(viewport={"width": 390, "height": 844})
        page.goto("http://127.0.0.1:%d/#t=%s" % (server.server_address[1], server.token))
        page.click("#screen-open button[data-screen=compare]")
        assert page.is_hidden("#pick-form") and page.is_disabled("#files-compare")
        page.set_input_files("#file-before", saved[0])
        page.set_input_files("#file-after", saved[1])
        page.click("#files-compare")
        page.wait_for_selector("#compare-result:not([hidden])", timeout=30000)
        assert page.inner_text("#compare-sentence").startswith("0 fixed, 1 new, grade ")
        item = page.text_content("#list-new .diff-item.new-high")
        assert "New High" in item and "High" in item  # a word, not colour alone
        page.set_input_files("#file-before", saved[0])
        page.set_input_files("#file-after", str(project / "app.py"))
        page.click("#files-compare")
        page.wait_for_selector("#compare-error:not([hidden])")
        assert "The after file is not a report saved with code-guardian scan --json" in page.inner_text("#compare-error")
    finally:
        browser.close()
        pw.stop()
        server.shutdown()
        server.server_close()
        t.join(10)


# ---- Settings (P78 S1): the panel, what it keeps, and that it applies before the page is drawn ---------------------

STORE = "cg.settings"
RESULT_SCREENS = ("result", "fixfirst", "findings", "code", "compare")


@contextlib.contextmanager
def _page(width=390, height=844, init=None, token=True):
    """(page, url) on a fresh server in Chromium; skips when Playwright or Chromium is missing. init is a script that
    runs in the page before the page's own."""
    import threading

    sync = pytest.importorskip("playwright.sync_api")
    from code_guardian import ui
    pw, browser = _browser(sync)
    server = ui.make_server(port=0)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        context = browser.new_context(viewport={"width": width, "height": height})
        if init:
            context.add_init_script(init)
        yield context.new_page(), "http://127.0.0.1:%d/%s" % (server.server_address[1], "#t=" + server.token if token else "")
    finally:
        browser.close()
        pw.stop()
        server.shutdown()
        server.server_close()
        t.join(10)


def _pick(page, name, value):
    page.click("#settings-button")
    page.check('input[name="%s"][value="%s"]' % (name, value))
    page.keyboard.press("Escape")


def _applied(page):
    """(theme, size, brand) as the page shows them."""
    return tuple(page.evaluate("""() => [document.documentElement.dataset.theme, document.documentElement.dataset.size,
                                          document.getElementById('luminari').hidden ? 'off' : 'on']"""))


def test_escape_closes_the_settings_panel():
    with _page() as (page, url):
        page.goto(url)
        assert page.is_hidden("#settings")
        page.click("#settings-button")
        assert page.is_visible("#settings") and page.get_attribute("#settings-button", "aria-expanded") == "true"
        page.keyboard.press("Escape")
        assert page.is_hidden("#settings") and page.get_attribute("#settings-button", "aria-expanded") == "false"
        assert page.evaluate("document.activeElement.id") == "settings-button"


@pytest.mark.parametrize("size", [(390, 844), (1280, 800)], ids=["phone", "wide"])
def test_a_tap_outside_or_on_close_closes_the_settings_panel_and_a_tap_inside_does_not(size):
    with _page(*size) as (page, url):
        page.goto(url)
        page.click("#settings-button")
        page.click("#settings-title")  # inside the panel
        page.click('input[name="size"][value="larger"]')
        assert page.is_visible("#settings")
        page.click("#settings-close")
        assert page.is_hidden("#settings")
        page.click("#settings-button")
        page.mouse.click(10, 10)  # outside the panel: the dimmed page
        assert page.is_hidden("#settings")
        assert page.get_attribute("#settings-button", "aria-expanded") == "false"


def test_tab_stays_inside_the_open_settings_panel():
    with _page() as (page, url):
        page.goto(url)
        page.click("#settings-button")
        for key in ["Tab"] * 12 + ["Shift+Tab"] * 12:
            page.keyboard.press(key)
            assert page.evaluate("document.getElementById('settings').contains(document.activeElement)"), key


def test_the_gear_and_the_name_are_on_the_screen_with_no_token():
    with _page(token=False) as (page, url):
        page.goto(url)
        page.wait_for_selector("#screen-notoken:not([hidden])")
        assert page.is_visible("#luminari") and page.is_visible("#settings-button")
        assert page.is_hidden("#luminari-mark"), "an empty mark slot takes no room"
        page.click("#settings-button")
        assert page.is_visible("#settings")
        page.check('input[name="theme"][value="light"]')
        assert _applied(page)[0] == "light"


# The probe runs before the page's own scripts: it saves a light theme, notes when <html> becomes light and when the
# browser first paints. (document.documentElement does not exist yet, so it watches the whole document.)
FLASH_PROBE = """
(() => {
  localStorage.setItem('cg.settings', JSON.stringify({theme: 'light', size: 'normal', brand: 'on'}));
  const log = window.__cg = {theme: null, paint: null};
  new MutationObserver(() => {
    if (log.theme === null && document.documentElement.dataset.theme === 'light') log.theme = performance.now();
  }).observe(document, {attributes: true, subtree: true, attributeFilter: ['data-theme']});
  new PerformanceObserver(list => {
    for (const e of list.getEntries()) if (e.name === 'first-paint' && log.paint === null) log.paint = e.startTime;
  }).observe({type: 'paint', buffered: true});
})();
"""


def test_a_saved_light_theme_is_applied_before_the_first_paint():
    html = (UI / "index.html").read_text(encoding="utf-8")
    tag = re.search(r'<script\b[^>]*\bsrc="/app\.js"[^>]*>', html).group(0)
    assert re.search(r"\bdefer\b", tag) and 'blocking="render"' in tag, \
        "a deferred script alone can run after the first paint (3 in 60 loads in Chromium); blocking=render cannot"
    with _page(init=FLASH_PROBE) as (page, url):
        page.goto(url)
        for load in range(6):
            if load:
                page.reload()
            page.wait_for_selector("#screen-open:not([hidden])")
            log = page.evaluate("window.__cg")
            if log["paint"] is None:
                pytest.skip("this Chromium reports no paint timing")
            assert log["theme"] is not None and log["theme"] <= log["paint"], \
                "the page was drawn dark before the saved light theme was applied: %r" % log


def test_the_color_scheme_meta_follows_the_theme():
    with _page() as (page, url):
        page.goto(url)
        meta = lambda: page.get_attribute('meta[name="color-scheme"]', "content")  # noqa: E731
        assert meta() == "dark"
        _pick(page, "theme", "light")
        assert meta() == "light"
        page.reload()
        assert meta() == "light"
        _pick(page, "theme", "dark")
        assert meta() == "dark"


@pytest.mark.parametrize("raw, want", [
    ('{"theme":"light","size":"largest","brand":"off"}', ("light", "largest", "off")),
    ('{"theme":"light","size":"huge","brand":3}', ("light", "normal", "on")),  # a value it does not know is the default
    ('{"theme":"neon"}', ("dark", "normal", "on")),
    ('{"theme":"light"', ("dark", "normal", "on")),  # not JSON
    ("null", ("dark", "normal", "on")),
    ('["light"]', ("dark", "normal", "on")),
    ('"light"', ("dark", "normal", "on")),
    ("", ("dark", "normal", "on")),
])
def test_the_saved_settings_are_read_back_and_anything_else_is_the_default(raw, want):
    with _page() as (page, url):
        page.goto(url)
        page.evaluate("v => localStorage.setItem('%s', v)" % STORE, raw)
        page.reload()
        assert _applied(page) == want
        page.click("#settings-button")  # the radios show what is in force
        for name, value in zip(("theme", "size", "brand"), want):
            assert page.is_checked('input[name="%s"][value="%s"]' % (name, value)), (name, value)


def test_every_change_is_written_under_one_key_and_nothing_else_is_stored():
    with _page() as (page, url):
        page.goto(url)
        assert page.evaluate("localStorage.length") == 0, "nothing is written until a choice is made"
        _pick(page, "size", "largest")
        _pick(page, "brand", "off")
        assert page.evaluate("Object.keys(localStorage)") == [STORE]
        assert json.loads(page.evaluate("localStorage.getItem('%s')" % STORE)) == \
            {"theme": "dark", "size": "largest", "brand": "off"}
        assert url.split("#t=")[1] not in page.evaluate("JSON.stringify(localStorage)"), "the token is never stored"


@pytest.mark.parametrize("size", ["larger", "largest"])
def test_larger_text_still_fits_a_phone_on_every_screen(tmp_path, size):
    project = tmp_path / "proj"
    project.mkdir()
    (project / "app.py").write_text(WITH_KEY, encoding="utf-8")
    fits = "document.documentElement.scrollWidth"
    with _page() as (page, url):
        page.goto(url)
        _pick(page, "size", size)
        assert page.evaluate(fits) <= 390
        page.click("#settings-button")
        assert page.evaluate(fits) <= 390, "the open panel"
        page.keyboard.press("Escape")
        page.fill("#path", str(project))
        page.click("#scan-button")
        page.wait_for_selector("#screen-result:not([hidden])", timeout=60000)
        for screen in RESULT_SCREENS:
            page.click("#tabs button[data-screen=%s]" % screen)
            assert page.evaluate(fits) <= 390, (size, screen)


def test_a_restart_gets_the_same_default_port_so_the_browser_keeps_its_settings():
    """The server that closes a connection first is left with that port in TIME_WAIT; on Linux and macOS a restart
    cannot bind it again unless the listener sets SO_REUSEADDR, and lands on the next port, where every setting
    is lost. Reading to the server's close makes the server the side that closes first."""
    import socket
    import threading

    from code_guardian import ui

    def serve_one_request():
        server = ui.make_server()
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        port = server.server_address[1]
        try:
            conn = socket.create_connection(("127.0.0.1", port), timeout=10)
            conn.sendall(("GET / HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n" % port).encode("ascii"))
            try:
                while conn.recv(65536):
                    pass
            except ConnectionError:  # a reset also means the server closed first
                pass
            conn.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(10)
        return port

    first = serve_one_request()
    if first not in ui.DEFAULT_PORTS:
        pytest.skip("every default port is busy on this machine")
    assert [serve_one_request() for _ in range(3)] == [first] * 3


# ---- sizes (P78 S2): the tabs, the summary rail and the strip -----------------------------------------------------

def _checked(page, url, tmp_path):
    project = tmp_path / "proj"
    project.mkdir(parents=True)
    (project / "app.py").write_text(WITH_KEY, encoding="utf-8")
    page.goto(url)
    page.fill("#path", str(project))
    page.click("#scan-button")
    page.wait_for_selector("#screen-result:not([hidden])", timeout=60000)
    page.wait_for_selector("#summary-rail:not([hidden])")


def test_the_active_tab_is_scrolled_into_view_on_a_phone(tmp_path):
    with _page(390, 844) as (page, url):
        _checked(page, url, tmp_path)
        page.click("#tabs button[data-screen=compare]")
        box = page.evaluate("""() => {
          const row = document.getElementById('tabs').getBoundingClientRect();
          const tab = document.querySelector('#tabs button[aria-current=page]').getBoundingClientRect();
          return {rowL: row.left, rowR: row.right, l: tab.left, r: tab.right,
                  scrolled: document.getElementById('tabs').scrollLeft, page: document.documentElement.scrollWidth};
        }""")
        assert box["scrolled"] > 0, "the row did not scroll to the last tab"
        assert box["l"] >= box["rowL"] and box["r"] <= box["rowR"] + 0.5, box
        assert box["page"] <= 390, "only the row scrolls sideways, never the page"


def test_a_refused_rail_store_still_renders_the_column(tmp_path):
    refuse = ("Storage.prototype.getItem = function () { throw new Error('blocked'); };"
              "Storage.prototype.setItem = function () { throw new Error('blocked'); };")
    with _page(1280, 800, init=refuse) as (page, url):
        _checked(page, url, tmp_path)
        rem = "parseFloat(getComputedStyle(document.documentElement).fontSize)"
        assert page.evaluate("document.getElementById('summary-rail').getBoundingClientRect().width / " + rem) >= 13
        assert page.get_attribute("#rail-toggle", "aria-expanded") == "true"
        page.click("#rail-toggle")  # the choice holds for this visit even though nothing can be saved
        assert page.evaluate("document.getElementById('summary-rail').getBoundingClientRect().width / " + rem) <= 4
        assert page.get_attribute("#rail-toggle", "aria-expanded") == "false"


STRIP_LINE = re.compile(r"^Grade [A-F] \(\d+/100\) High \d+ Medium \d+ Low \d+ Quality \d+$")


def _strip_text(page):
    text = page.evaluate("""() => ['.rail-grade', '.rail-counts'].map(
        s => document.querySelector('#summary-rail ' + s).innerText).join(' ')""")
    return " ".join(text.split())


def test_the_strip_line_on_a_phone_is_the_grade_and_the_counts(tmp_path):
    with _page(390, 844) as (page, url):
        _checked(page, url, tmp_path)
        assert STRIP_LINE.match(_strip_text(page)), _strip_text(page)
        assert page.get_attribute("#rail-toggle", "aria-expanded") == "false"
        assert page.get_attribute("#frame", "data-rail") == "strip"
        assert page.is_hidden("#rail-harm-word") and page.is_hidden("#check-again")


def test_the_side_window_width_uses_the_phone_strip_collapsed(tmp_path):
    with _page(520, 900) as (page, url):
        _checked(page, url, tmp_path)
        assert page.get_attribute("#frame", "data-rail") == "strip"
        assert page.get_attribute("#rail-toggle", "aria-expanded") == "false"
        assert page.evaluate("document.getElementById('rail-details').hidden")
        assert STRIP_LINE.match(_strip_text(page)), _strip_text(page)
        page.click("#rail-toggle")
        assert page.is_visible("#check-again") and page.is_visible("#rail-harm-word")


# ---- P78 S3: the Code screen lists every file; the S2 design nits (a)-(d) -----------------------------------------

RISKY = ROOT / "tests" / "fixtures" / "risky_repo"
CSS = (UI / "app.css").read_text(encoding="utf-8")


def _code_of(page, url, project=RISKY, wait="#file-list li"):
    page.goto(url)
    page.fill("#path", str(project))
    page.click("#scan-button")
    page.wait_for_selector("#screen-result:not([hidden])", timeout=60000)
    page.click("#tabs button[data-screen=code]")
    page.wait_for_selector("#screen-code:not([hidden])")
    page.wait_for_selector(wait, timeout=30000)


def _box(page, selector):
    return page.evaluate("""(s) => { const b = document.querySelector(s).getBoundingClientRect();
      return {l: b.left, t: b.top, w: b.width, h: b.height, r: b.right}; }""", selector)


def test_the_page_has_no_inline_style_anywhere():
    html = (UI / "index.html").read_text(encoding="utf-8")
    js = _js()
    assert not re.search(r"\sstyle\s*=", html)
    for banned in ('setAttribute("style"', "setAttribute('style'", ".style.", ".cssText", "<style"):
        assert banned not in js, banned


def test_the_file_list_rows_say_the_word_the_server_gave_and_why(tmp_path):
    with _page(1280, 800) as (page, url):
        _code_of(page, url)
        page.select_option("#file-filter", "all")
        rows = {li.get_attribute("data-rel"): li for li in page.query_selector_all("#file-list .file-btn")}
        assert "web/setup.js" in rows and "risky/runner.py" in rows and "setup.py" in rows
        js = rows["web/setup.js"].inner_text()
        assert "Partly checked" in js and "JavaScript code is not analysed yet" in js
        assert "High" in rows["risky/runner.py"].inner_text()
        assert page.locator("#file-list .file-btn[data-rel='web/setup.js'] .file-risk.lvl-Partly").count() == 1
        assert page.locator("#file-list .file-btn[data-rel='risky/runner.py'] .file-risk.lvl-High").count() == 1
        assert "files-title" == page.get_attribute("#files-drawer h2", "id")
        assert page.inner_text("#files-title") == "Files"
        assert [o.inner_text().rsplit(" (", 1)[0] for o in page.query_selector_all("#file-filter option")] == [
            "All files", "Files with findings", "No known risks found", "Partly checked", "Not read"]


def test_the_default_filter_is_all_files_when_nothing_has_a_finding(tmp_path):
    project = tmp_path / "quiet"
    project.mkdir()
    (project / "a.py").write_text("def add(x, y):\n    return x + y\n", encoding="utf-8")
    (project / "notes.txt").write_text("hello\n", encoding="utf-8")
    with _page(1280, 800) as (page, url):
        _code_of(page, url, project)
        assert page.evaluate("document.getElementById('file-filter').value") == "all"
        assert page.evaluate("document.getElementById('file-filter').selectedOptions[0].textContent").startswith(
            "All files (2)")


def test_the_code_screen_counts_the_findings_about_the_whole_project(tmp_path):
    with _page(1280, 800) as (page, url):
        _code_of(page, url)
        assert re.search(r"\d+ findings? (is|are) about the whole project, not one file", page.inner_text("#files-note"))


def test_a_phone_shows_the_picked_file_name_once(tmp_path):
    """Nit (b): the drawer's summary keeps the name for a screen reader only; the viewer bar draws it."""
    with _page(390, 844) as (page, url):
        _code_of(page, url)
        page.click("#file-list .file-btn[data-rel='risky/runner.py']")
        page.wait_for_selector("#L7")
        shown = page.evaluate("""(name) => [...document.querySelectorAll('#screen-code *')].filter(
            e => !e.children.length && e.textContent.includes(name) && e.getBoundingClientRect().width > 2
                 && e.getBoundingClientRect().height > 2 && e.checkVisibility({checkVisibilityCSS: true}))
            .map(e => e.id || e.className)""", "risky/runner.py")
        assert shown == ["file-name"], shown
        assert page.get_attribute("#file-name", "data-must-show") is not None
        assert "risky/runner.py" in page.evaluate("document.getElementById('files-picked').textContent")
        assert "risky/runner.py" in page.inner_text("#files-drawer > summary"), "the summary still names it for a reader"
        assert page.evaluate("document.getElementById('files-drawer').open") is False


def test_a_wide_screen_does_not_name_the_file_in_the_summary():
    with _page(1280, 800) as (page, url):
        _code_of(page, url)
        page.click("#file-list .file-btn[data-rel='risky/runner.py']")
        page.wait_for_selector("#L7")
        assert page.evaluate("document.getElementById('files-picked').textContent") == ""


def test_the_tabs_fade_at_the_edge_only_with_css(tmp_path):
    """Nit (a): on a phone the row scrolls and says so; the fade is background gradients, no script and no style."""
    rule = re.search(r"\n\.tabs \{(.*?)\n\}", CSS, re.S).group(1)
    assert rule.count("linear-gradient") == 4 and "local" in rule and "scroll" in rule
    with _page(390, 844) as (page, url):
        _checked(page, url, tmp_path / "phone")
        got = page.evaluate("""() => { const r = document.getElementById('tabs'), c = getComputedStyle(r);
          return {scrolls: r.scrollWidth > r.clientWidth, image: c.backgroundImage, attach: c.backgroundAttachment,
                  inline: r.getAttribute('style')}; }""")
        assert got["scrolls"] and got["inline"] is None
        assert got["image"].count("linear-gradient") == 4 and "local" in got["attach"] and "scroll" in got["attach"]
    with _page(1280, 800) as (page, url):
        _checked(page, url, tmp_path / "wide")
        assert page.evaluate("document.getElementById('tabs').scrollWidth <= document.getElementById('tabs').clientWidth")


def test_the_two_line_fields_stay_on_one_line_in_the_right_column():
    """Nit (c): at 1280 "to line" no longer wraps under "From line"."""
    with _page(1280, 800) as (page, url):
        _code_of(page, url)
        a, b = _box(page, "#line-start"), _box(page, "#line-end")
        assert abs(a["t"] - b["t"]) < 1 and b["l"] >= a["r"], (a, b)
        aside = _box(page, "#code-aside")
        assert b["r"] <= aside["r"] and a["l"] >= aside["l"]
        labels = page.evaluate("""() => ['line-start', 'line-end'].map(
            id => { const l = document.querySelector('label[for=' + id + ']').getBoundingClientRect();
                    return [Math.round(l.top), Math.round(l.height)]; })""")
        assert labels[0] == labels[1], labels
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")


def test_the_code_viewer_is_at_least_34rem_wide_at_1280_with_the_summary_open():
    """Nit (d): the file list and the right column are narrower (and the rail's share and the gaps smaller) from 900 to
    1439 px, so the viewer keeps about 34rem at 1280 x 800 and the right column stays beside it."""
    with _page(1280, 800) as (page, url):
        _code_of(page, url)
        assert page.get_attribute("#rail-toggle", "aria-expanded") == "true"
        rem = page.evaluate("parseFloat(getComputedStyle(document.documentElement).fontSize)")
        viewer, aside, files = _box(page, "#screen-code .viewer"), _box(page, "#code-aside"), _box(page, "#files-drawer")
        assert viewer["w"] / rem >= 33.9, viewer["w"] / rem
        assert aside["l"] >= viewer["r"] - 1 and files["r"] <= viewer["l"] + 1
        assert files["w"] / rem >= 11.9 and aside["w"] / rem >= 14.9, "nothing was hidden to make room"
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")


# ---- Save this check (P76 S6b): a saved check for people who do not use the command line ---------------------------

def _scanned(page, url, project):
    page.goto(url)
    page.fill("#path", str(project))
    page.click("#scan-button")
    page.wait_for_selector("#screen-result:not([hidden])", timeout=60000)


def _saved_as(page):
    with page.expect_download() as got:
        page.click("#save-check")
    return got.value


def test_the_saved_file_name_is_the_folder_and_the_time_with_odd_characters_replaced(tmp_path):
    project = tmp_path / "my app é日本"
    project.mkdir()
    (project / "app.py").write_text(WITH_KEY, encoding="utf-8")
    with _page(1280, 800) as (page, url):
        _scanned(page, url, project)
        dl = _saved_as(page)
        assert re.fullmatch(r"code-guardian-my-app-{5}\d{4}-\d\d-\d\d-\d{4}\.json", dl.suggested_filename), dl.suggested_filename
        saved = tmp_path / "out.json"
        dl.save_as(str(saved))
        data = json.loads(saved.read_text(encoding="utf-8"))
        assert data["path"] == str(project) and data["findings"]
        # A saved check can be saved again, and a folder from a Windows computer is cut at its last backslash.
        data["path"] = "D:\\work\\my proj\\"
        saved.write_text(json.dumps(data), encoding="utf-8")
        page.click("#new-check")
        page.set_input_files("#open-saved", str(saved))
        page.wait_for_selector("#rail-when:has-text('Saved check from')")
        assert re.fullmatch(r"code-guardian-my-proj-\d{4}-\d\d-\d\d-\d{4}\.json", _saved_as(page).suggested_filename)


def test_the_command_line_wording_is_folded_and_opens_on_a_tap():
    html = (UI / "index.html").read_text(encoding="utf-8")
    assert len(re.findall(r'<details class="cli-note">', html)) == 2, "closed by default: no open attribute"
    with _page(390, 844) as (page, url):
        page.goto(url)
        page.wait_for_selector("#screen-open:not([hidden])")
        assert page.evaluate("document.querySelector('#saved-form details').open") is False
        assert not page.is_visible("#saved-form details p")
        page.click("#saved-form summary")
        assert page.is_visible("#saved-form details p")
        page.click("#screen-open button[data-screen=compare]")
        assert page.evaluate("document.querySelector('#files-form details').open") is False
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")


def test_the_save_line_appears_after_a_click_and_goes_when_another_check_is_drawn(tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    (project / "app.py").write_text(WITH_KEY, encoding="utf-8")
    with _page(390, 844) as (page, url):
        _scanned(page, url, project)
        assert page.is_hidden("#save-note")
        box = _box(page, "#save-check")
        assert box["l"] >= 0 and box["r"] <= 390, "reachable without scrolling sideways"
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
        _saved_as(page)
        page.wait_for_selector("#save-note:not([hidden])")
        assert page.inner_text("#save-note") == "Saved to your Downloads folder (or wherever your browser saves files)."
        page.click("#check-again-summary")
        page.wait_for_selector("#check-again-summary:not([disabled])")
        assert page.is_hidden("#save-note")
