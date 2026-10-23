"""P76 S3 acceptance -- the page (code_guardian/ui/index.html, app.css, app.js), the contrast checker and the
screenshots.

Written by the overseer from plan P76 contracts C9 and C10 BEFORE the build session. The build session must add this
file to the PR byte-for-byte and must not edit it; a PR that changes it fails the section.

Contrast is checked twice: by the repo's tools/contrast_check.py (C10), and independently here with the WCAG 2.x
relative-luminance formula over the :root tokens, so a checker that always prints "ok" cannot pass this file.
"""
import importlib
import re
import struct
import subprocess
import sys
import threading
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
UI = ROOT / "code_guardian" / "ui"
SHOTS = ROOT / "docs" / "screenshots"
TOKENS = ("--bg", "--surface", "--text", "--muted", "--high", "--medium", "--low", "--ok", "--accent", "--border")
SCREENS = ("open", "result", "fixfirst", "findings", "code")
SIZES = ((390, 844), (1280, 800))
CSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'"
COLOR = re.compile(r"(?<![\w&-])#[0-9a-fA-F]{3,8}\b|\b(?:rgba?|hsla?)\s*\(", re.IGNORECASE)


def read(name):
    p = UI / name
    assert p.is_file(), "missing %s" % p
    return p.read_text(encoding="utf-8")


def root_block(css):
    m = re.search(r":root\s*\{(.*?)\}", css, re.S)
    assert m, "app.css has no :root block"
    return m


def tokens(css):
    body = root_block(css).group(1)
    return {k: v.strip() for k, v in re.findall(r"(--[\w-]+)\s*:\s*([^;]+);", body)}


def rgb(value):
    v = value.strip().lower()
    m = re.fullmatch(r"#([0-9a-f]{3}|[0-9a-f]{6})", v)
    if m:
        h = m.group(1)
        if len(h) == 3:
            h = "".join(c * 2 for c in h)
        return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))
    m = re.fullmatch(r"rgb\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)", v)
    if m:
        return tuple(int(x) for x in m.groups())
    raise AssertionError("token value %r is not #rgb, #rrggbb or rgb(r, g, b)" % value)


def luminance(c):
    def ch(x):
        x = x / 255.0
        return x / 12.92 if x <= 0.04045 else ((x + 0.055) / 1.055) ** 2.4
    r, g, b = (ch(x) for x in c)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def ratio(a, b):
    la, lb = sorted((luminance(a), luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def png_size(path):
    with open(path, "rb") as fh:
        head = fh.read(24)
    assert head[:8] == b"\x89PNG\r\n\x1a\n", "%s is not a PNG" % path
    return struct.unpack(">II", head[16:24])


# ---- C9 files, CSP-safety, dark only -----------------------------------------------------------------------------

def test_three_files_exist_and_are_csp_safe():
    html = read("index.html")
    read("app.css")
    read("app.js")
    assert '<meta name="viewport"' in html and "width=device-width" in html
    assert "<style" not in html.lower(), "inline <style> is blocked by the CSP"
    assert not re.search(r"\sstyle\s*=", html, re.I), "inline style= is blocked by the CSP"
    assert not re.search(r"\son[a-z]+\s*=", html, re.I), "inline event handlers are blocked by the CSP"
    for tag in re.findall(r"<script\b[^>]*>(.*?)</script>", html, re.I | re.S):
        assert not tag.strip(), "inline script body is blocked by the CSP"
    assert re.search(r"<script\b[^>]*\bsrc=\"/?app\.js\"", html), "index.html must load app.js"
    assert re.search(r"<link\b[^>]*\bhref=\"/?app\.css\"", html), "index.html must load app.css"


def test_served_with_the_csp_header():
    ui = importlib.import_module("code_guardian.ui")
    import http.client
    s = ui.make_server(port=0)
    t = threading.Thread(target=s.serve_forever)
    t.start()
    try:
        for path, kind in (("/", "text/html"), ("/app.css", "text/css"), ("/app.js", "javascript")):
            c = http.client.HTTPConnection("127.0.0.1", s.server_address[1], timeout=30)
            c.request("GET", path)
            r = c.getresponse()
            body = r.read()
            c.close()
            assert r.status == 200 and kind in (r.getheader("Content-Type") or ""), (path, r.status)
            assert r.getheader("Content-Security-Policy") == CSP, path
            assert body == (UI / ("index.html" if path == "/" else path[1:])).read_bytes(), path
    finally:
        s.shutdown()
        s.server_close()
        t.join(10)


def test_required_strings_and_dark_only():
    html = read("index.html")
    for needed in ("No known risks found", "partial check", "AI explanation"):
        assert needed in html, needed
    everything = html + read("app.css") + read("app.js")
    # P78 (TJ 2026-10-22 ~16:12): a Settings panel may offer light mode; the page must never switch on its own.
    assert not re.search(r"prefers-color-scheme\s*:\s*light", everything, re.I)
    assert re.search(r"color-scheme\s*:\s*dark", read("app.css"))


def test_no_network_reference_in_the_page():
    # P78 S0: the only outside address the page may name is the Luminari link in index.html (a plain link, never
    # fetched -- the CSP still allows no outside connection, script, style or image).
    for name in ("index.html", "app.css", "app.js"):
        text = read(name).lower()
        if name == "index.html":
            assert text.count('href="https://github.com/luminarisoftwares"') <= 1, name
            text = text.replace('href="https://github.com/luminarisoftwares"', "")
        assert "https://" not in text and "cdn" not in text, name


# ---- C9 palette in one place -------------------------------------------------------------------------------------

def test_every_color_is_a_root_token():
    # P78 S0: exactly two token blocks may hold colours -- ":root {...}" and ':root[data-theme="light"] {...}'.
    css = read("app.css")
    blocks = list(re.finditer(r':root(\[data-theme="light"\])?\s*\{(.*?)\}', css, re.S))
    assert 1 <= len(blocks) <= 2 and blocks[0].group(1) is None, "the first :root block is the dark palette"
    assert len(blocks) == 1 or blocks[1].group(1) is not None, "only one light block is allowed"
    outside, last = "", 0
    for b in blocks:
        outside += css[last:b.start()]
        last = b.end()
    outside += css[last:]
    hits = COLOR.findall(outside) + COLOR.findall(read("index.html"))
    assert not hits, "literal colors outside :root: %r" % hits[:10]
    t = tokens(css)
    missing = [k for k in TOKENS if k not in t]
    assert not missing, missing


# ---- C10 contrast ------------------------------------------------------------------------------------------------

def test_contrast_independently():
    t = {k: rgb(v) for k, v in tokens(read("app.css")).items() if k in TOKENS}
    low = []
    for fg in ("--text", "--muted"):
        for bg in ("--bg", "--surface"):
            if ratio(t[fg], t[bg]) < 4.5:
                low.append((fg, bg, round(ratio(t[fg], t[bg]), 2)))
    for fg in ("--high", "--medium", "--low", "--ok", "--accent"):
        for bg in ("--bg", "--surface"):
            if ratio(t[fg], t[bg]) < 3.0:
                low.append((fg, bg, round(ratio(t[fg], t[bg]), 2)))
    assert not low, low


def test_contrast_check_tool_passes_the_page_and_fails_a_bad_palette(tmp_path):
    tool = ROOT / "tools" / "contrast_check.py"
    assert tool.is_file()
    r = subprocess.run([sys.executable, str(tool), str(UI / "app.css")], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stdout + r.stderr
    m = re.search(r"^ok: (\d+) pairs", r.stdout, re.M)
    assert m and int(m.group(1)) >= 4, r.stdout
    bad = tmp_path / "bad.css"
    bad.write_text(":root {\n" + "".join("  %s: #222222;\n" % k for k in TOKENS) + "  color-scheme: dark;\n}\n",
                   encoding="utf-8")
    r = subprocess.run([sys.executable, str(tool), str(bad)], capture_output=True, text=True, timeout=60)
    assert r.returncode != 0 and not re.search(r"^ok:", r.stdout, re.M), r.stdout


# ---- screenshots -------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("screen", SCREENS)
@pytest.mark.parametrize("size", SIZES, ids=lambda s: "%dx%d" % s)
def test_screenshot_exists_and_has_the_right_viewport(screen, size):
    w, h = size
    p = SHOTS / ("%s_%dx%d.png" % (screen, w, h))
    assert p.is_file(), p
    assert p.stat().st_size > 10 * 1024, "%s is %d bytes" % (p, p.stat().st_size)
    pw, ph = png_size(p)
    scale = pw / w
    assert scale in (1, 2, 3), (p.name, pw, ph)
    assert ph >= h * scale, (p.name, pw, ph)


@pytest.mark.parametrize("size", SIZES, ids=lambda s: "%dx%d" % s)
def test_the_five_screens_are_different_pictures(size):
    import hashlib
    digests = {}
    for screen in SCREENS:
        p = SHOTS / ("%s_%dx%d.png" % (screen, size[0], size[1]))
        assert p.is_file(), p
        digests.setdefault(hashlib.sha256(p.read_bytes()).hexdigest(), []).append(screen)
    same = [names for names in digests.values() if len(names) > 1]
    assert not same, "identical screenshots: %r" % same


def test_screenshot_tool_is_dev_only():
    assert (ROOT / "tools" / "ui_screenshots.py").is_file()
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "playwright" not in text.lower(), "Playwright must not become a dependency or extra of the package"
    assert re.search(r"^dependencies = \[\]$", text, re.M)
