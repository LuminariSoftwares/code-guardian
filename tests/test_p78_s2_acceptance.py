"""P78 S2 acceptance -- sizes (plan P78 C3): four width tiers, the summary rail as strip / column / mini rail, the Code
file drawer and the wide right column, text-holding widths in rem or clamp(), and every screenshot at three sizes.

Written by the overseer BEFORE the build session. The build session must add this file to the PR byte-for-byte and
must not edit it; a PR that changes it fails the section. This file is pure ASCII on purpose.

Names this file fixes (the S2 prompt quotes them): `#rail-toggle` (the one button that expands the strip below 900 px
and hides / shows the column at 900 px and up, with `aria-expanded`), `localStorage["cg.rail"]` = "open" | "mini",
`<details id="files-drawer">` around the file list, `#code-aside` (the wide right column, which holds
`#explain-panel`), and the `data-must-show` attribute.

The "nothing cut off" rule, as code: on every screen, document.documentElement.scrollWidth <= window.innerWidth, and
every element carrying data-must-show with no `hidden` attribute on itself or an ancestor has a non-zero box whose
left >= 0 and right <= innerWidth after it is scrolled into view (so a tab scrolled inside the tab row still counts).
A part that is collapsed (the phone strip's details) is collapsed with the `hidden` attribute.

The browser tests need Playwright and Chromium; CI has neither, so they skip there and run in the build session's
container and the overseer's. Everything else runs everywhere.
"""
import ast
import json
import re
import struct
import threading
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
FIXTURES = HERE / "fixtures"
UI = ROOT / "code_guardian" / "ui"
SHOTS = ROOT / "docs" / "screenshots"
TOOL = ROOT / "tools" / "ui_screenshots.py"

SWEEP = ((390, 844), (520, 900), (768, 1024), (1280, 800), (1600, 900))
LARGEST = ((390, 844), (1280, 800))
SCREENS = ("result", "fixfirst", "findings", "code", "compare", "open")
CODE_LINK = "risky/runner.py line 7"
SHOT_SCREENS = ("open", "result", "fixfirst", "findings", "code", "diff")
SHOT_SIZES = ((390, 844), (520, 900), (1280, 800))
SHOTS_S2 = ({"%s_%dx%d.png" % (s, w, h) for s in SHOT_SCREENS for (w, h) in SHOT_SIZES}
            | {"rail_mini_1280x800.png", "settings_390x844.png", "settings_1280x800.png",
               "result_light_390x844.png", "result_light_1280x800.png"})
SHOTS_LATER = {"browse_refused_390x844.png"}  # P78 S4 adds this one (plan section 6: 24 after S4)


def _css():
    return (UI / "app.css").read_text(encoding="utf-8")


def _html():
    return (UI / "index.html").read_text(encoding="utf-8")


def _rules(css):
    """(selector, declarations) for every innermost rule; @media wrappers fall away."""
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    return [(sel.strip(), body) for sel, body in re.findall(r"([^{}]+)\{([^{}]*)\}", css)]


# ---- static: widths, markers, names, the screenshot tool --------------------------------------------------------

TEXT_BOXES = re.compile(r"\.(rail|files|frame|code-layout|code-aside)(?![-\w])|#code-aside(?![-\w])")
WIDTH_PROPS = ("width", "min-width", "max-width", "flex-basis", "flex", "grid-template-columns")


def test_text_holding_widths_are_rem_or_clamp():
    bad = []
    for sel, body in _rules(_css()):
        if not TEXT_BOXES.search(sel):
            continue
        for prop, value in re.findall(r"(?:^|;)\s*([-\w]+)\s*:\s*([^;]+)", body):
            if prop.strip().lower() in WIDTH_PROPS and re.search(r"(?<![\w.])\d*\.?\d+px", value):
                bad.append("%s { %s: %s }" % (sel, prop.strip(), value.strip()))
    assert not bad, "fixed px widths on a box that holds text (use rem or clamp()): %s" % bad[:6]


def test_four_tiers_in_the_css():
    css = _css()
    for w in (600, 900, 1280):
        assert re.search(r"@media[^{]*min-width:\s*%dpx" % w, css), "no min-width: %dpx tier" % w


def test_must_show_markers():
    html = _html()
    assert len(re.findall(r"\sdata-must-show(?=[\s=>])", html)) >= 12
    tags = re.findall(r"<[a-z][^>]*>", html)

    def tag_of(ident):
        found = [t for t in tags if re.search(r'\sid="%s"' % ident, t)]
        assert len(found) == 1, ident
        return found[0]

    for ident in ("settings-button", "check-again", "rail-grade", "rail-harm-word", "rail-partial", "rail-high",
                  "rail-medium", "rail-low", "rail-quality", "file-name"):
        assert "data-must-show" in tag_of(ident), "#%s carries no data-must-show" % ident
    tabs = re.search(r'<nav[^>]*\bid="tabs"[^>]*>(.*?)</nav>', html, re.S)
    assert tabs, "no <nav id=\"tabs\">"
    buttons = re.findall(r"<button\b[^>]*>", tabs.group(1))
    assert len(buttons) == 5 and all("data-must-show" in b for b in buttons), buttons


def test_named_parts_exist():
    html = _html()
    assert re.search(r'<button\b[^>]*\bid="rail-toggle"[^>]*\baria-expanded="(true|false)"', html) or \
        re.search(r'<button\b[^>]*\baria-expanded="(true|false)"[^>]*\bid="rail-toggle"', html), "#rail-toggle"
    assert re.search(r'<details\b[^>]*\bid="files-drawer"', html), "<details id=files-drawer>"
    aside = re.search(r'\bid="code-aside"', html)
    assert aside, "#code-aside"
    assert html.index('id="explain-panel"') > aside.start(), "#explain-panel lives inside #code-aside"
    js = (UI / "app.js").read_text(encoding="utf-8")
    assert "cg.rail" in js and "rail-toggle" in js


def test_screenshot_tool_sizes():
    tree = ast.parse(TOOL.read_text(encoding="utf-8"))
    sizes = None
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "SIZES" for t in node.targets):
            sizes = ast.literal_eval(node.value)
    assert sizes is not None, "no SIZES in tools/ui_screenshots.py"
    assert len(sizes) == 3 and (520, 900, 1) in sizes, sizes
    assert {(w, h) for w, h, _ in sizes} == set(SHOT_SIZES), sizes


def _png_size(path):
    with open(path, "rb") as fh:
        head = fh.read(24)
    assert head[:8] == b"\x89PNG\r\n\x1a\n", path
    return struct.unpack(">II", head[16:24])


def test_screenshots_at_three_sizes():
    have = {p.name for p in SHOTS.glob("*.png")}
    missing = SHOTS_S2 - have
    extra = have - SHOTS_S2 - SHOTS_LATER
    assert not missing, sorted(missing)
    assert not extra, sorted(extra)
    for name in SHOTS_S2:
        p = SHOTS / name
        assert p.stat().st_size > 10 * 1024, name
        w = int(re.search(r"_(\d+)x(\d+)\.png$", name).group(1))
        pw, _ = _png_size(p)
        assert pw / w in (1, 2, 3), (name, pw)


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


@pytest.fixture(scope="module")
def server():
    from code_guardian import ui
    s = ui.make_server(port=0)
    t = threading.Thread(target=s.serve_forever)
    t.start()
    yield s
    s.shutdown()
    s.server_close()
    t.join(10)


def _open(browser, server, w, h, size="normal"):
    ctx = browser.new_context(viewport={"width": w, "height": h})
    if size != "normal":
        ctx.add_init_script("try { localStorage.setItem('cg.settings', '%s'); } catch (e) {}"
                            % json.dumps({"theme": "dark", "size": size, "brand": "on"}))
    page = ctx.new_page()
    page.goto("http://127.0.0.1:%d/#t=%s" % (server.server_address[1], server.token))
    page.wait_for_selector("#screen-open:not([hidden]), #screen-result:not([hidden])", timeout=30000)
    page.wait_for_load_state("networkidle")  # the page may open the server's last result by itself; let it settle
    if not page.locator("#screen-result").is_visible():
        page.wait_for_selector("#path", state="visible", timeout=30000)
        page.fill("#path", str(FIXTURES / "risky_repo"))
        page.click("#scan-button")
    page.wait_for_selector("#screen-result:not([hidden])", timeout=90000)
    page.wait_for_selector("#summary-rail:not([hidden])", timeout=10000)
    return ctx, page


def _go(page, screen):
    if screen == "open":
        page.click("#new-check")
    elif screen == "code":
        page.click("#tabs button[data-screen=findings]")
        page.wait_for_selector("#screen-findings:not([hidden])")
        page.get_by_role("button", name=CODE_LINK).first.click()
        page.wait_for_selector("#L7")
    else:
        page.click("#tabs button[data-screen=%s]" % screen)
    page.wait_for_selector("#screen-%s:not([hidden])" % screen, timeout=30000)


MEASURE = """() => {
  const view = window.innerWidth, out = {scroll: document.documentElement.scrollWidth, view: view, bad: [], n: 0};
  for (const el of document.querySelectorAll('[data-must-show]')) {
    if (el.closest('[hidden]')) continue;
    el.scrollIntoView({block: 'nearest', inline: 'nearest'});
    const r = el.getBoundingClientRect(), cs = getComputedStyle(el);
    out.n += 1;
    if (!(r.width > 0 && r.height > 0) || r.left < -0.5 || r.right > view + 0.5 || cs.visibility === 'hidden')
      out.bad.push((el.id || el.textContent.trim().slice(0, 24)) + ' ' + Math.round(r.left) + '..' +
                   Math.round(r.right) + ' of ' + view);
  }
  window.scrollTo(0, 0);
  return out;
}"""


def _sweep(browser, server, w, h, size):
    ctx, page = _open(browser, server, w, h, size)
    problems = []
    try:
        if size != "normal":
            assert page.evaluate("document.documentElement.dataset.size") == size
        for screen in SCREENS:
            _go(page, screen)
            m = page.evaluate(MEASURE)
            if m["scroll"] > m["view"]:
                problems.append("%s: scrolls sideways (%d > %d)" % (screen, m["scroll"], m["view"]))
            if m["bad"]:
                problems.append("%s: cut off %s" % (screen, m["bad"][:4]))
            if m["n"] < (1 if screen == "open" else 7):
                problems.append("%s: only %d data-must-show elements on screen" % (screen, m["n"]))
    finally:
        ctx.close()
    assert not problems, "%dx%d %s: %s" % (w, h, size, problems)


@pytest.mark.parametrize("w,h", SWEEP, ids=["%dx%d" % s for s in SWEEP])
def test_nothing_cut_off(browser, server, w, h):
    _sweep(browser, server, w, h, "normal")


@pytest.mark.parametrize("w,h", LARGEST, ids=["%dx%d" % s for s in LARGEST])
def test_nothing_cut_off_at_largest_text(browser, server, w, h):
    _sweep(browser, server, w, h, "largest")


def _rail_width_rem(page):
    return page.evaluate("document.getElementById('summary-rail').getBoundingClientRect().width / "
                         "parseFloat(getComputedStyle(document.documentElement).fontSize)")


def _store(page, key):
    return page.evaluate("(k) => { try { return localStorage.getItem(k); } catch (e) { return null; } }", key)


def test_rail_hides_to_a_mini_rail_and_comes_back(browser, server):
    ctx, page = _open(browser, server, 1280, 800)
    try:
        assert _rail_width_rem(page) >= 13
        page.click("#rail-toggle")
        assert _rail_width_rem(page) <= 4, _rail_width_rem(page)
        assert _store(page, "cg.rail") == "mini"
        assert page.get_attribute("#rail-toggle", "aria-expanded") == "false"
        again = page.locator("#check-again")
        assert again.is_visible()
        assert (again.get_attribute("aria-label") or "").strip() and (again.get_attribute("title") or "").strip()
        labels = page.evaluate("[...document.querySelectorAll('#summary-rail [aria-label]')]"
                               ".map(e => e.getAttribute('aria-label')).join(' | ')")
        assert re.search(r"High|Medium|Low|No known risks found", labels), labels
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
        page.reload()
        page.wait_for_selector("#summary-rail:not([hidden])", timeout=30000)
        assert _rail_width_rem(page) <= 4, "the mini rail must survive a reload"
        page.click("#rail-toggle")
        assert _rail_width_rem(page) >= 13
        assert _store(page, "cg.rail") == "open"
        assert page.get_attribute("#rail-toggle", "aria-expanded") == "true"
    finally:
        ctx.close()


def test_phone_strip_expands_on_tap(browser, server):
    ctx, page = _open(browser, server, 390, 844)
    try:
        assert page.get_attribute("#rail-toggle", "aria-expanded") == "false"
        assert not page.locator("#check-again").is_visible()
        page.click("#rail-toggle")
        assert page.get_attribute("#rail-toggle", "aria-expanded") == "true"
        assert page.locator("#check-again").is_visible()
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    finally:
        ctx.close()


def test_side_panel_strip_starts_expanded(browser, server):
    ctx, page = _open(browser, server, 768, 1024)
    try:
        assert page.get_attribute("#rail-toggle", "aria-expanded") == "true"
        assert page.locator("#check-again").is_visible()
    finally:
        ctx.close()


def test_phone_file_drawer_closes_on_a_pick(browser, server):
    ctx, page = _open(browser, server, 390, 844)
    try:
        page.click("#tabs button[data-screen=code]")
        page.wait_for_selector("#screen-code:not([hidden])")
        assert page.evaluate("document.getElementById('files-drawer').open") is True
        _go(page, "code")
        assert page.evaluate("document.getElementById('files-drawer').open") is False
        assert "runner.py" in page.inner_text("#files-drawer > summary")
    finally:
        ctx.close()


@pytest.mark.parametrize("w,h", ((1280, 800), (1600, 900)), ids=["1280x800", "1600x900"])
def test_wide_code_has_a_right_column(browser, server, w, h):
    ctx, page = _open(browser, server, w, h)
    try:
        _go(page, "code")
        box = page.evaluate("""() => {
          const a = document.getElementById('code-aside').getBoundingClientRect();
          const v = document.querySelector('#screen-code .viewer').getBoundingClientRect();
          return {aw: a.width, al: a.left, vr: v.right, view: window.innerWidth};
        }""")
        assert box["aw"] > 0 and box["al"] >= box["vr"] - 1, box
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    finally:
        ctx.close()
