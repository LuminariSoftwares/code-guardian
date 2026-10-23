"""P76 S6b acceptance -- the owner's design reaction at P76 S6 (decisions_log 2026-10-23 ~11:57): the saved-check and
saved-file boxes assume someone who uses the command line. People who do not get a plain path -- a "Save this check"
button that saves the current check as a file in the browser -- and the command-line wording stays, folded into a
"Using the command line?" detail.

Written by the overseer BEFORE the build session. The build session must add this file to the PR byte-for-byte and
must not edit it; a PR that changes it fails the section. This file is pure ASCII on purpose.

Names this file fixes: `#save-check` (the button), `#saved-form` (Open a saved check, already on main), `#files-form`
(Compare two saved files, already on main), and a `<details>` inside each form for the command-line wording.
"""
import json
import re
import threading
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
FIXTURES = HERE / "fixtures"
UI = ROOT / "code_guardian" / "ui"
CLI_WORDS = re.compile(r"code-guardian scan|--json|&gt;|>\s*\w+\.json")
CSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'"


def _html():
    return (UI / "index.html").read_text(encoding="utf-8")


def _form(html, ident):
    m = re.search(r'<form\b[^>]*\bid="%s"[^>]*>(.*?)</form>' % ident, html, re.S)
    assert m, "no <form id=%s>" % ident
    return m.group(1)


def _outside_details(fragment):
    return re.sub(r"<details\b.*?</details>", "", fragment, flags=re.S)


def _text(fragment):
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", fragment))


# ---- static -------------------------------------------------------------------------------------------------------

def test_save_this_check_button():
    html = _html()
    assert re.search(r'<button\b[^>]*\btype="button"[^>]*\bid="save-check"', html) or \
        re.search(r'<button\b[^>]*\bid="save-check"[^>]*\btype="button"', html), "#save-check"
    btn = re.search(r'\bid="save-check"[^>]*>(.*?)</button>', html, re.S)
    assert btn and "Save this check" in _text(btn.group(1)), btn
    js = (UI / "app.js").read_text(encoding="utf-8")
    assert "save-check" in js and "createObjectURL" in js and re.search(r"\.download\s*=", js)


@pytest.mark.parametrize("ident", ["saved-form", "files-form"])
def test_plain_words_first_command_line_folded(ident):
    form = _form(_html(), ident)
    plain = _text(_outside_details(form))
    assert not CLI_WORDS.search(plain), "command-line wording outside the detail in #%s: %s" % (ident, plain[:300])
    assert "Save this check" in plain, "#%s does not tell a non-coder how to get a saved file" % ident
    assert "nothing is uploaded" in plain.lower(), plain[:300]
    det = re.search(r"<details\b[^>]*>(.*?)</details>", form, re.S)
    assert det, "#%s has no <details> for the command-line wording" % ident
    summary = re.search(r"<summary\b[^>]*>(.*?)</summary>", det.group(1), re.S)
    assert summary and "command line" in _text(summary.group(1)).lower(), summary
    assert "code-guardian scan" in _text(det.group(1)) and "--json" in _text(det.group(1))


def test_csp_unchanged_and_no_inline_style():
    from code_guardian import ui
    assert ui.CSP == CSP
    assert not re.search(r"\sstyle=", _html())


def test_readme_names_the_button():
    assert "Save this check" in (ROOT / "README.md").read_text(encoding="utf-8")


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


def test_save_then_open_and_compare_without_reading_the_folder(browser, monkeypatch, tmp_path):
    from code_guardian import ui
    calls = []
    real = ui.report.scan
    monkeypatch.setattr(ui.report, "scan", lambda *a, **kw: calls.append(a) or real(*a, **kw))
    srv = ui.make_server(port=0)
    t = threading.Thread(target=srv.serve_forever)
    t.start()
    ctx = browser.new_context(viewport={"width": 1280, "height": 800}, accept_downloads=True)
    page = ctx.new_page()
    try:
        page.goto("http://127.0.0.1:%d/#t=%s" % (srv.server_address[1], srv.token))
        page.wait_for_selector("#screen-open:not([hidden])", timeout=30000)
        page.fill("#path", str(FIXTURES / "risky_repo"))
        page.click("#scan-button")
        page.wait_for_selector("#screen-result:not([hidden])", timeout=90000)
        page.wait_for_load_state("networkidle")
        assert len(calls) == 1

        with page.expect_download() as got:
            page.click("#save-check")
        dl = got.value
        assert re.fullmatch(r"code-guardian-[\w.-]+\.json", dl.suggested_filename), dl.suggested_filename
        saved = tmp_path / dl.suggested_filename
        dl.save_as(str(saved))
        data = json.loads(saved.read_text(encoding="utf-8"))
        assert data["scores"] and isinstance(data["findings"], list) and data["path"]

        page.click("#new-check")
        page.wait_for_selector("#screen-open:not([hidden])")
        page.set_input_files("#open-saved", str(saved))
        page.wait_for_selector("#screen-result:not([hidden])", timeout=30000)
        page.wait_for_load_state("networkidle")
        assert page.inner_text("#rail-when").strip().startswith("Saved check from")

        page.click("#tabs button[data-screen=compare]")
        page.wait_for_selector("#screen-compare:not([hidden])")
        inputs = page.locator("#files-form input[type=file]")
        assert inputs.count() == 2
        inputs.nth(0).set_input_files(str(saved))
        inputs.nth(1).set_input_files(str(saved))
        page.locator("#files-form button[type=submit]").click()
        page.wait_for_selector("#compare-result:not([hidden])", timeout=30000)
        assert "0 fixed, 0 new" in page.inner_text("#compare-result")
        assert len(calls) == 1, "saving, opening or comparing a saved check read the folder"
    finally:
        ctx.close()
        srv.shutdown()
        srv.server_close()
        t.join(10)
