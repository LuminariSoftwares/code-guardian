"""Capture the screenshots of `code-guardian ui` in docs/screenshots/ (plan P76 S3).

Development only: Playwright is not a dependency or an extra of the package, so install it into a scratch
environment first (pip install playwright, plus a Chromium it can find). The scanned folder is visible on the page,
so the projects are copied into a neutral folder (default /tmp/demo) and only that path ever appears.

    python tools/ui_screenshots.py [--out docs/screenshots] [--root /tmp/demo]

Writes {open,result,fixfirst,findings,code}_{390x844,1280x800}.png. result_390x844 is a JavaScript-only project, so
its first screen shows the PARTIAL banner, the grey "No known risks found" and the "partial check" flag; every other
screen is a copy of tests/fixtures/risky_repo, whose Fix first screen shows the scan's notes above the list and whose
Code screen shows one inline note opened. Fails if any screen scrolls sideways.
"""
import argparse
import os
import shutil
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from code_guardian import ui  # noqa: E402

SIZES = ((390, 844, 2), (1280, 800, 1))  # width, height, device scale
JS_FILES = {
    "index.js": "const http = require(\"http\");\n\n"
                "http.createServer((req, res) => res.end(\"hello\")).listen(3000);\n",
    "package.json": "{\n  \"name\": \"my-js-app\",\n  \"version\": \"1.0.0\",\n  \"main\": \"index.js\",\n"
                    "  \"license\": \"MIT\"\n}\n",
    "README.md": "# my-js-app\n\nA tiny web server.\n",
}
CODE_LINK = "risky/runner.py line 7"


def make_projects(root):
    """Fresh copies under root: my-project (the risky fixture) and my-js-app. Only these two folders are replaced."""
    root.mkdir(parents=True, exist_ok=True)
    risky, js = root / "my-project", root / "my-js-app"
    for d in (risky, js):
        if d.exists():
            shutil.rmtree(d)
    shutil.copytree(ROOT / "tests" / "fixtures" / "risky_repo", risky)
    js.mkdir()
    for name, text in JS_FILES.items():
        (js / name).write_text(text, encoding="utf-8")
    return risky, js


def no_side_scroll(page, name):
    width = page.evaluate("document.documentElement.scrollWidth")
    view = page.evaluate("window.innerWidth")
    if width > view:
        raise SystemExit("%s scrolls sideways: %d px wide in a %d px window" % (name, width, view))


def check(page, path):
    page.fill("#path", str(path))
    page.click("#scan-button")
    page.wait_for_selector("#screen-result:not([hidden])", timeout=60000)
    # Selectors, not wait_for_function: that one evaluates a string, which the page's CSP (no unsafe-eval) refuses.
    page.wait_for_selector("#scanned-when:has-text('checked at')", timeout=10000)


def shoot(page, out, name):
    no_side_scroll(page, name)
    page.evaluate("window.scrollTo(0, 0)")
    page.screenshot(path=str(out / name), full_page=True)
    print("wrote %s (%d bytes)" % (name, (out / name).stat().st_size))


def capture(browser, out, risky, js, width, height, scale):
    server = ui.make_server(port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    size = "%dx%d" % (width, height)
    try:
        context = browser.new_context(viewport={"width": width, "height": height}, device_scale_factor=scale)
        page = context.new_page()
        page.goto("http://127.0.0.1:%d/#t=%s" % (server.server_address[1], server.token))
        page.wait_for_selector("#screen-open:not([hidden])")
        if width < 600:
            check(page, js)
            shoot(page, out, "result_%s.png" % size)
            page.click("#new-check")
            check(page, risky)
        else:
            check(page, js)
            page.click("#new-check")
            check(page, risky)
            shoot(page, out, "result_%s.png" % size)
        page.click("#tabs button[data-screen=fixfirst]")
        shoot(page, out, "fixfirst_%s.png" % size)
        page.click("#tabs button[data-screen=findings]")
        shoot(page, out, "findings_%s.png" % size)
        page.get_by_role("button", name=CODE_LINK).first.click()
        page.wait_for_selector("#L7.target")
        page.click("#L7 + .line-note .note-toggle")
        page.wait_for_selector("#L7 + .line-note .note-toggle[aria-expanded=true]")
        # Select lines 7-9 the way a finger or a mouse would, so the selection note shows.
        page.evaluate("""() => {
            const r = document.createRange();
            r.setStart(document.querySelector('#L7 .src'), 0);
            r.setEnd(document.querySelector('#L9 .src'), 1);
            const s = window.getSelection(); s.removeAllRanges(); s.addRange(r);
        }""")
        page.wait_for_selector("#selection-note:has-text('Lines 7')")
        page.evaluate("document.getElementById('code').scrollTop = 0")
        shoot(page, out, "code_%s.png" % size)
        page.click("#new-check")
        page.wait_for_selector("#recent li")
        shoot(page, out, "open_%s.png" % size)
        context.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(10)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default=str(ROOT / "docs" / "screenshots"))
    ap.add_argument("--root", default="/tmp/demo")
    args = ap.parse_args(argv)
    try:
        from playwright.sync_api import sync_playwright  # dev only: never imported by the package
    except ImportError:
        sys.stderr.write("ui_screenshots: Playwright is not installed here (pip install playwright); "
                         "it is a development tool, not a dependency of code-guardian\n")
        return 2

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    risky, js = make_projects(Path(args.root))
    exe = os.environ.get("CG_CHROMIUM")
    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path=exe) if exe else pw.chromium.launch()
        try:
            for width, height, scale in SIZES:
                capture(browser, out, risky, js, width, height, scale)
        finally:
            browser.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
