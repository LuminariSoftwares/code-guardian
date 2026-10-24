"""P78 S1 acceptance -- Settings (theme, text size, brand), the light palette, the stable default port, ADR 0008.

Written by the overseer from plan P78 contracts C1 (+ Port, Brand mark), C2 and C8 BEFORE the build session. The build
session must add this file to the PR byte-for-byte and must not edit it; a PR that changes it fails the section. Pure
ASCII on purpose (lesson: escape sequences do not survive being retyped).

Deviation (10), owner 2026-10-22 ~21:36: the old star mark is retired, so `<svg id="luminari-mark">` ships EMPTY (a slot
for the new mark) with the "Luminari" word beside it; the three --brand-* tokens stay for the new mark's colours.

Browser checks need Playwright + Chromium and skip without them (CI and the owner's PC have neither); the build session
and the overseer run them in their containers.
"""
import json
import re
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
UI = ROOT / "code_guardian" / "ui"
SHOTS = ROOT / "docs" / "screenshots"
DEFAULT_PORTS = tuple(range(8765, 8776))
TOKENS_19 = {"--bg", "--surface", "--surface-2", "--border", "--text", "--muted", "--high", "--medium", "--low",
             "--ok", "--none", "--accent", "--on-accent", "--focus", "--hl", "color-scheme",
             "--brand-1", "--brand-2", "--brand-3"}
BLOCK = re.compile(r':root(\[data-theme="light"\])?\s*\{(.*?)\}', re.S)


def css():
    return (UI / "app.css").read_text(encoding="utf-8")


def html():
    return (UI / "index.html").read_text(encoding="utf-8")


def js():
    return (UI / "app.js").read_text(encoding="utf-8")


def blocks():
    found = BLOCK.findall(css())
    return {("light" if attr else "dark"): dict((k, v.strip()) for k, v in
                                                 re.findall(r"(--[\w-]+|color-scheme)\s*:\s*([^;]+);", body))
            for attr, body in found}


def rgb_text(hexval):
    h = hexval.strip().lstrip("#")
    if len(h) == 3:
        h = "".join(c * 2 for c in h)
    return "rgb(%d, %d, %d)" % tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


# ---- C2 palettes -------------------------------------------------------------------------------------------------

def test_two_palettes_with_the_same_19_names():
    b = blocks()
    assert set(b) == {"dark", "light"}, set(b)
    assert set(b["dark"]) == TOKENS_19, sorted(set(b["dark"]) ^ TOKENS_19)
    assert set(b["light"]) == TOKENS_19, sorted(set(b["light"]) ^ TOKENS_19)
    assert b["dark"]["color-scheme"] == "dark" and b["light"]["color-scheme"] == "light"
    assert b["dark"]["--bg"] != b["light"]["--bg"]


def test_text_size_steps_and_no_px_font_sizes():
    c = css()
    assert not re.search(r"font-size\s*:\s*\d+(\.\d+)?px", c), "font sizes are rem/em/% only"
    assert re.search(r'html\[data-size="larger"\]\s*\{[^}]*font-size\s*:\s*112\.5%', c)
    assert re.search(r'html\[data-size="largest"\]\s*\{[^}]*font-size\s*:\s*125%', c)
    assert not re.search(r"prefers-color-scheme\s*:\s*light", c + html() + js(), re.I)


def _contrast(path):
    return subprocess.run([sys.executable, str(ROOT / "tools" / "contrast_check.py"), str(path)],
                          capture_output=True, text=True, timeout=60)


def test_contrast_tool_checks_both_palettes_and_still_fails_bad_ones(tmp_path):
    r = _contrast(UI / "app.css")
    assert r.returncode == 0, r.stdout + r.stderr
    assert re.search(r"^ok: \d+ pairs in 2 palettes", r.stdout, re.M), r.stdout
    one_bad = tmp_path / "one.css"
    one_bad.write_text(":root {\n" + "".join("  %s: #222222;\n" % k for k in sorted(TOKENS_19) if k != "color-scheme")
                       + "  color-scheme: dark;\n}\n", encoding="utf-8")
    r = _contrast(one_bad)
    assert r.returncode == 1 and not re.search(r"^ok:", r.stdout, re.M), r.stdout + r.stderr
    b = blocks()
    light_bad = dict(b["light"], **{"--text": b["light"]["--bg"]})
    two = ":root {\n%s}\n:root[data-theme=\"light\"] {\n%s}\n" % (
        "".join("  %s: %s;\n" % kv for kv in sorted(b["dark"].items())),
        "".join("  %s: %s;\n" % kv for kv in sorted(light_bad.items())))
    two_bad = tmp_path / "two.css"
    two_bad.write_text(two, encoding="utf-8")
    r = _contrast(two_bad)
    assert r.returncode == 1 and "light" in r.stdout, r.stdout + r.stderr


# ---- C1 settings markup ------------------------------------------------------------------------------------------

def test_settings_panel_matches_the_settings_constant():
    m = re.search(r"SETTINGS\s*=\s*\{(.*?)\}\s*\}", js(), re.S)
    assert m, "no SETTINGS constant in app.js"
    keys = re.findall(r"(\w+)\s*:\s*\{\s*default", m.group(0))
    assert keys == ["theme", "size", "brand"], keys
    h = html()
    assert re.search(r'<button\b[^>]*\bid="settings-button"', h)
    assert re.search(r'<section\b[^>]*\bid="settings"[^>]*\bhidden', h)
    fieldsets = re.findall(r'<fieldset\b[^>]*\bdata-setting="(\w+)"', h)
    assert fieldsets == keys, fieldsets
    radios = set()
    for tag in re.findall(r"<input\b[^>]*>", h):
        attrs = dict(re.findall(r'(\w[\w-]*)="([^"]*)"', tag))
        if attrs.get("type") == "radio":
            radios.add((attrs.get("name"), attrs.get("value")))
    for name, values in (("theme", ("dark", "light")), ("size", ("normal", "larger", "largest")),
                         ("brand", ("on", "off"))):
        for v in values:
            assert (name, v) in radios, (name, v)
    assert 'id="settings-more"' in h and "More options will appear here in later versions." in h
    assert re.search(r'<html\b[^>]*\bdata-theme="dark"[^>]*\bdata-size="normal"', h)
    assert re.search(r'<head>.*<script\b[^>]*\bsrc="/?app\.js"[^>]*\bdefer\b.*</head>', h, re.S)
    assert "cg.settings" in js() and "localStorage" in js()


def test_brand_slot_and_link():
    h = html()
    a = re.search(r'<a\b[^>]*\bid="luminari"[^>]*>(.*?)</a>', h, re.S)
    assert a, "no #luminari link"
    tag = a.group(0)[:a.group(0).index(">") + 1]
    assert 'href="https://github.com/LuminariSoftwares"' in tag
    assert 'rel="noopener noreferrer"' in tag
    assert re.search(r'<svg\b[^>]*\bid="luminari-mark"', a.group(1))
    assert "Luminari" in re.sub(r"<[^>]+>", "", a.group(1))
    assert not re.search(r'stop-color=|fill="#|\sstyle=', h)


def test_adr_0008():
    adrs = sorted((ROOT / "docs" / "adr").glob("0008-*.md"))
    assert adrs, "docs/adr/0008-*.md missing"
    text = adrs[0].read_text(encoding="utf-8")
    assert "localStorage" in text and "8765" in text and "dark" in text.lower()
    assert "0008" in (ROOT / "docs" / "adr" / "README.md").read_text(encoding="utf-8")


# ---- Port ----------------------------------------------------------------------------------------------------------

def _free(port):
    # bind the way the server does: SO_REUSEADDR on POSIX (so a port in TIME_WAIT counts as free), plain on Windows
    s = socket.socket()
    if sys.platform != "win32":
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def _hold(port):
    # a listening socket on the port, bound like the server binds (a listener blocks the port on every OS)
    h = socket.socket()
    if sys.platform != "win32":
        h.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    h.bind(("127.0.0.1", port))
    h.listen(1)
    return h


def test_default_port_walks_8765_to_8775_then_ephemeral():
    from code_guardian import ui
    if not all(_free(p) for p in DEFAULT_PORTS):
        pytest.skip("a default port is busy on this machine")
    s = ui.make_server()
    try:
        assert s.server_address[1] == 8765
    finally:
        s.server_close()
    hold = _hold(8765)
    try:
        s = ui.make_server()
        try:
            assert s.server_address[1] == 8766
        finally:
            s.server_close()
    finally:
        hold.close()
    holds = []
    try:
        for p in DEFAULT_PORTS:
            holds.append(_hold(p))
        s = ui.make_server()
        try:
            assert s.server_address[1] not in DEFAULT_PORTS and s.server_address[1] > 0
        finally:
            s.server_close()
    finally:
        for h in holds:
            h.close()
    s = ui.make_server(port=0)
    try:
        assert s.server_address[0] == "127.0.0.1"
    finally:
        s.server_close()


# ---- screenshots ---------------------------------------------------------------------------------------------------

def test_four_new_screenshots():
    import struct
    for name, w in (("settings_390x844", 390), ("settings_1280x800", 1280), ("result_light_390x844", 390),
                    ("result_light_1280x800", 1280)):
        p = SHOTS / (name + ".png")
        assert p.is_file(), p
        assert p.stat().st_size > 10 * 1024, p
        head = p.read_bytes()[:24]
        assert head[:8] == b"\x89PNG\r\n\x1a\n"
        pw, _ = struct.unpack(">II", head[16:24])
        assert pw / w in (1, 2, 3), (name, pw)


# ---- browser (container only) --------------------------------------------------------------------------------------

@pytest.fixture
def browser():
    sync_api = pytest.importorskip("playwright.sync_api")
    with sync_api.sync_playwright() as pw:
        try:
            b = pw.chromium.launch()
        except Exception as exc:  # no Chromium here
            pytest.skip("no Chromium: %s" % exc)
        yield b
        b.close()


def _serve(port=None):
    from code_guardian import ui
    s = ui.make_server() if port is None else ui.make_server(port=port)
    t = threading.Thread(target=s.serve_forever)
    t.start()
    return s, t


def _stop(s, t):
    s.shutdown()
    s.server_close()
    t.join(10)


def _bg(page):
    return page.evaluate("getComputedStyle(document.body).backgroundColor")


def _pick(page, name, value):
    page.click("#settings-button")
    page.check('input[name="%s"][value="%s"]' % (name, value))
    page.keyboard.press("Escape")


def test_settings_apply_persist_and_survive_a_restart(browser):
    b = blocks()
    dark, light = rgb_text(b["dark"]["--bg"]), rgb_text(b["light"]["--bg"])
    if not all(_free(p) for p in DEFAULT_PORTS):
        pytest.skip("a default port is busy on this machine")
    s, t = _serve()
    ctx = browser.new_context()
    page = ctx.new_page()
    try:
        url = "http://127.0.0.1:%d/" % s.server_address[1]
        page.goto(url)
        assert _bg(page) == dark
        _pick(page, "theme", "light")
        assert _bg(page) == light
        page.reload()
        assert _bg(page) == light
        _pick(page, "size", "larger")
        assert page.evaluate("getComputedStyle(document.documentElement).fontSize") == "18px"
        _pick(page, "size", "largest")
        assert page.evaluate("getComputedStyle(document.documentElement).fontSize") == "20px"
        _pick(page, "brand", "off")
        page.reload()
        assert page.locator("#luminari").is_hidden()
    finally:
        _stop(s, t)
    s, t = _serve()
    try:
        page.goto("http://127.0.0.1:%d/" % s.server_address[1])
        assert _bg(page) == light, "a restart on the default port must keep the setting"
    finally:
        ctx.close()
        _stop(s, t)


def test_a_throwing_storage_still_renders_dark_and_the_panel_works(browser):
    dark = rgb_text(blocks()["dark"]["--bg"])
    s, t = _serve(port=0)
    ctx = browser.new_context()
    ctx.add_init_script("Object.defineProperty(window, 'localStorage', {get() { throw new Error('blocked'); }});")
    page = ctx.new_page()
    try:
        page.goto("http://127.0.0.1:%d/" % s.server_address[1])
        assert _bg(page) == dark
        page.click("#settings-button")
        assert page.locator("#settings").is_visible()
        page.check('input[name="theme"][value="light"]')
        assert _bg(page) != dark
    finally:
        ctx.close()
        _stop(s, t)
