"""Capture the screenshots of `code-guardian ui` in docs/screenshots/ (plan P76 S3, P78 S1, S2, S3).

Development only: Playwright is not a dependency or an extra of the package, so install it into a scratch
environment first (pip install playwright, plus a Chromium it can find). The scanned folder is visible on the page,
so the projects are copied into a neutral folder (default /tmp/demo) and only that path ever appears.

    python tools/ui_screenshots.py [--out docs/screenshots] [--root /tmp/demo]

Writes {open,result,fixfirst,findings,code,diff}_{390x844,520x900,1280x800}.png (a phone, the narrow side window and a
full screen), rail_mini_1280x800.png (the result with the summary column shrunk to the slim icon rail) and, at 390 and
1280 only, {settings,result_light}_<size>.png. result_390x844 and result_520x900 are a JavaScript-only project, so
the first screen shows the PARTIAL banner, the grey "No known risks found" and the "partial check" flag; every other
screen is a copy of tests/fixtures/risky_repo, whose Fix first screen shows the scan's notes above the list and whose
Code screen shows one inline note opened. Below 600 px the summary is a collapsed strip; the tool opens it before it
clicks "Check again" and closes it again. Fails if any screen scrolls sideways.

The Code screens show the file list with the "All files" filter chosen, scrolled so that a Partly checked row (the
risky project's web/setup.js, a language this tool does not analyse yet) is on screen. Below 900 px a pick closes the
file drawer, so the tool opens it again for the picture.

The Code screens also show a selection, the filled start and end fields and an answer in the explanation panel. The
answer comes from a stub model started here, a tiny HTTP server on the loopback address that returns one fixed
sample reply, so no real model is ever involved and the picture says plainly that it is a sample.

The diff screens are before / after (P76 S5): a small project (my-app) with a key-shaped line is checked, the line is
removed, "Check again" runs, and the Compare tab shows what changed. The key-shaped value is built at runtime from two
pieces, so no file in this repository holds one.

The settings screens (P78 S1) are the Settings panel open over the Open screen, one screenful as a person sees it (the
panel is fixed to the window, so a full-page capture would put it at the bottom of a tall page). Then Light is picked
in that panel and the risky project is checked again: result_light is the Summary in the light palette.
"""
import argparse
import http.server
import json
import os
import shutil
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from code_guardian import ui  # noqa: E402

SIZES = ((390, 844, 2), (520, 900, 1), (1280, 800, 1))  # width, height, device scale
JS_FILES = {
    "index.js": "const http = require(\"http\");\n\n"
                "http.createServer((req, res) => res.end(\"hello\")).listen(3000);\n",
    "package.json": "{\n  \"name\": \"my-js-app\",\n  \"version\": \"1.0.0\",\n  \"main\": \"index.js\",\n"
                    "  \"license\": \"MIT\"\n}\n",
    "README.md": "# my-js-app\n\nA tiny web server.\n",
}
APP_KEY = "AKIA" + "Q7XZ" * 4  # built at runtime: the package's self-scan reads literals
APP_AFTER = ("import os\nimport subprocess\n\n\ndef run(cmd):\n    os.system(cmd)\n\n\n"
             "def build(target):\n    return subprocess.run(\"make \" + target, shell=True)\n")
APP_BEFORE = APP_AFTER.replace("import subprocess\n", "import subprocess\n\nKEY = \"%s\"\n" % APP_KEY, 1)
APP_README = "# my-app\n\nA small helper that runs build commands.\n"
CODE_LINK = "risky/runner.py line 7"
SAMPLE_ANSWER = ("Sample answer from a test model: these lines start another program and wait for it to finish. "
                 "This is a fixed sample reply, not a real analysis.")


def start_stub_model():
    """A model on 127.0.0.1 that answers every /api/chat with SAMPLE_ANSWER; returns (server, url)."""
    class Stub(http.server.BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            data = json.dumps({"message": {"role": "assistant", "content": SAMPLE_ANSWER}}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Stub)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, "http://127.0.0.1:%d/api/chat" % server.server_port


def make_projects(root):
    """Fresh copies under root: my-project (the risky fixture), my-js-app and my-app. Only these folders are
    replaced."""
    root.mkdir(parents=True, exist_ok=True)
    risky, js, app = root / "my-project", root / "my-js-app", root / "my-app"
    for d in (risky, js, app):
        if d.exists():
            shutil.rmtree(d)
    shutil.copytree(ROOT / "tests" / "fixtures" / "risky_repo", risky)
    js.mkdir()
    for name, text in JS_FILES.items():
        (js / name).write_text(text, encoding="utf-8")
    app.mkdir()
    (app / "README.md").write_text(APP_README, encoding="utf-8")
    return risky, js, app


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


def shoot(page, out, name, full_page=True):
    no_side_scroll(page, name)
    page.evaluate("window.scrollTo(0, 0)")
    page.screenshot(path=str(out / name), full_page=full_page)
    print("wrote %s (%d bytes)" % (name, (out / name).stat().st_size))


def show_all_files(page):
    """The Code screen's list as a reader would see it with every file chosen: "All files", the drawer open (a pick
    closes it below 900 px) and the list scrolled to the Partly checked row."""
    if not page.evaluate("document.getElementById('files-drawer').open"):
        page.click("#files-drawer > summary")
    page.select_option("#file-filter", "all")
    row = "#file-list .file-btn[data-rel='web/setup.js']"
    page.wait_for_selector(row)
    if "Partly checked" not in page.inner_text(row):
        raise SystemExit("code screenshot: web/setup.js is not a Partly checked row")
    page.evaluate("document.querySelector(\"#file-list .file-btn[data-rel='web/setup.js']\")"
                  ".scrollIntoView({block: 'nearest'})")


def compare(page, out, app, size):
    """Check my-app with its key-shaped line, remove the line, Check again, then open Compare."""
    (app / "app.py").write_text(APP_BEFORE, encoding="utf-8")
    page.click("#new-check")
    check(page, app)
    (app / "app.py").write_text(APP_AFTER, encoding="utf-8")
    phone = page.get_attribute("#rail-toggle", "aria-expanded") == "false"  # the strip starts collapsed on a phone
    if phone:
        page.click("#rail-toggle")
    page.click("#check-again")
    page.wait_for_selector("#check-again:not([disabled])", timeout=60000)
    page.wait_for_selector("#rail-when:has-text('checked at')", timeout=10000)
    if phone:
        page.click("#rail-toggle")
    page.click("#tabs button[data-screen=compare]")
    page.wait_for_selector("#compare-result:not([hidden])", timeout=30000)
    shoot(page, out, "diff_%s.png" % size)


def settings_and_light(page, out, risky, size):
    """The Settings panel open, then Light picked in it and a result drawn in the light palette."""
    page.click("#settings-button")
    page.wait_for_selector("#settings:not([hidden])")
    shoot(page, out, "settings_%s.png" % size, full_page=False)
    page.check('input[name="theme"][value="light"]')
    page.keyboard.press("Escape")
    page.wait_for_selector("#settings", state="hidden")
    check(page, risky)
    shoot(page, out, "result_light_%s.png" % size)


def capture(browser, out, risky, js, app, width, height, scale):
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
            page.click("#rail-toggle")  # the column shrinks to the slim icon rail, and comes back
            page.wait_for_selector("#rail-toggle[aria-expanded=false]")
            shoot(page, out, "rail_mini_%s.png" % size)
            page.click("#rail-toggle")
            page.wait_for_selector("#rail-toggle[aria-expanded=true]")
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
        page.click("#explain")
        page.click("#explain-body button.primary")
        page.wait_for_selector("#explain-body .explain-body-text")
        page.evaluate("document.getElementById('code').scrollTop = 0")
        show_all_files(page)
        shoot(page, out, "code_%s.png" % size)
        compare(page, out, app, size)
        page.click("#new-check")
        page.wait_for_selector("#recent li")
        shoot(page, out, "open_%s.png" % size)
        if width != 520:  # the Settings panel and the light palette are shown at the two older sizes only
            settings_and_light(page, out, risky, size)
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
    risky, js, app = make_projects(Path(args.root))
    exe = os.environ.get("CG_CHROMIUM")
    model, url = start_stub_model()
    os.environ["CODE_GUARDIAN_LLM_URL"] = url
    os.environ["CODE_GUARDIAN_LLM_MODEL"] = "sample-model"
    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path=exe) if exe else pw.chromium.launch()
        try:
            for width, height, scale in SIZES:
                capture(browser, out, risky, js, app, width, height, scale)
        finally:
            browser.close()
            model.shutdown()
            model.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
