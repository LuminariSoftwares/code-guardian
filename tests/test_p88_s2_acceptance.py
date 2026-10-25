"""P88 S2 acceptance -- the backup-copies banner, the held and left-out lines, the test-value line, their four plain
sentence builders and four screenshots (plan P88 contract C5, proof row S2).

Written by the overseer BEFORE the build session. The build session must add this file to the PR byte-for-byte and
must not edit it; a PR that changes it fails the section. This file is pure ASCII on purpose, and it holds no
key-shaped string: the one key the browser fixture needs is built at test time by concatenation.

The contract this file fixes (the plan leaves these open; the S2 prompt repeats them):

  plain.backup_offer_line(offered, total) -> str      offered = backup_offer["offered"] (the list, not the dict)
      "<sum of findings> of <total> findings are in <groups> that look(s) like backup copies: <glob>, <glob>"
      where <groups> counts folder globs (ending "/*") as "folder(s)" and every other glob as "set(s) of files",
      joined by " and ", and the verb is "looks like a backup copy" for one group, "look like backup copies" for more.
        ([_archive/* 151 findings], 206)  -> "151 of 206 findings are in 1 folder that looks like a backup copy: _archive/*"
        ([_archive/* 151, *.backup-* 3], 206)
            -> "154 of 206 findings are in 1 folder and 1 set of files that look like backup copies: _archive/*, *.backup-*"
        ([_archive/* 5, old/* 2], 9) -> "7 of 9 findings are in 2 folders that look like backup copies: _archive/*, old/*"
  plain.held_line(held) -> list of str, one per held group: "<glob> was not offered: <why>"; [] for [].
  plain.left_out_line(groups) -> str, groups = report["excluded_by_request"]; the "Put them back" link is a separate
      element, not part of the string:
        with counts: "Left out at your request: <globs> (<files> files, <n> findings left out: <n1> secret.key, <n2> other)"
            n1 = the by_code entries whose code is secret.key (any level), n2 = n - n1
        without counts (a CLI result, which has only glob + files): "Left out at your request: <globs> (<files> files)"
  plain.test_values_line(n) -> "<n> key-shaped values were graded as test values -- check they are fake"

  Element ids in index.html (C5):
      #backup-banner       the banner (hidden when there is no offer)
      #backup-offer-text   its sentence (= backup_offer_line(offered, len(report["findings"])))
      #backup-exclude      button "Check again without them" (sends exclude = the offered globs)
      #backup-keep         button "Keep them in" (hides the banner, sends nothing, keeps no state)
      #backup-held         one line per held group (= held_line(held))
      #backup-named        one caution line per offered group whose "named_by" is not empty (= named_line(group))
      #backup-cli          a <details> "Using the command line?" naming the equivalent --exclude flags
      #left-out            the left-out line in the summary header (hidden when nothing was left out)
      #left-out-text       its sentence (= left_out_line(report["excluded_by_request"]))
      #left-out-put-back   link "Put them back" (rescans with exclude: [])
      #test-values         the test-value line (hidden when the report has no test_values_graded)
      #test-values-show    its link: opens Findings filtered to the "looks like a test value" findings

  "total" in the banner is len(report["findings"]) of the result the banner sits on.

AMENDED by the overseer 2026-10-24 ~20:00 Central (deviation D10, after review of PR #42): a kept file that names a
backup folder in a string no longer holds it back; S1's offered groups carry "named_by" (sorted rels) and the page
shows a caution line for each such group:
  plain.named_line(group) -> None when group["named_by"] is empty, else
      "<glob> is named in a string by <n> file(s) (<first three> and <k> more): leave it out only if they just write
       copies there"   ("1 file" / "<n> files"; " and <k> more" only when n > 3)
  "Check again" on an excluded result keeps the exclude SERVER-side (C2: the scan entry keeps it): the page's
  Check again request carries no "exclude" key, and its button title ends with "(without <globs>)".

Deviation from the plan, recorded here: C5/S2 name the four screenshots `docs/screenshots/<name>.png`, but the P78 S2
and S4 acceptance files on main (which must stay untouched and green) pin the exact set of PNGs in docs/screenshots/.
The four P88 screenshots therefore live one folder down, in docs/screenshots/0.4.1/ (SHOTS_DIR below), and the
top-level set is proven unchanged.

Browser checks need Playwright + Chromium and skip without them (CI and the owner's PC have neither); the build session
and the overseer run them in their containers. They also need S1 (backups.offer and the exclude plumbing) on main.
"""
import hashlib
import http.client
import json
import re
import struct
import subprocess
import sys
import threading
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
FIXTURES = HERE / "fixtures"
UI = ROOT / "code_guardian" / "ui"
SHOTS = ROOT / "docs" / "screenshots"
SHOTS_DIR = SHOTS / "0.4.1"
P88_SHOTS = ("backup_banner_dark_390x844.png", "backup_banner_light_390x844.png",
             "left_out_dark_1280x800.png", "left_out_light_1280x800.png")
TEST_VALUE = "looks like a test value"

# The :root token sets of code-guardian 0.4.0 (main at v0.4.0), name -> value; S2 adds no token and changes none.
TOKENS_040 = {
    "dark": {"--bg": "#0e1116", "--surface": "#171b22", "--surface-2": "#1f242d", "--border": "#2d333d",
             "--text": "#e9ecf1", "--muted": "#a6aebb", "--high": "#ff7b72", "--medium": "#f2b84b", "--low": "#79b8ff",
             "--ok": "#5fd39b", "--none": "#b8bcc3", "--accent": "#8cb4ff", "--on-accent": "#0e1116",
             "--focus": "#8cb4ff", "--hl": "#2a3446", "--brand-1": "#6f7b91", "--brand-2": "#9aa5b8",
             "--brand-3": "#c2cad8", "color-scheme": "dark"},
    "light": {"--bg": "#f6f7f9", "--surface": "#ffffff", "--surface-2": "#eef1f5", "--border": "#c3cad6",
              "--text": "#14181f", "--muted": "#4f5968", "--high": "#a8231a", "--medium": "#7a5300", "--low": "#0b57b8",
              "--ok": "#126b47", "--none": "#525a66", "--accent": "#1f4fc2", "--on-accent": "#ffffff",
              "--focus": "#1f4fc2", "--hl": "#dfe8ff", "--brand-1": "#6f7b91", "--brand-2": "#4a566b",
              "--brand-3": "#2f3a4d", "color-scheme": "light"},
}
BLOCK = re.compile(r':root(\[data-theme="light"\])?\s*\{(.*?)\}', re.S)

# sha256 of every P76/P78 acceptance file on main at v0.4.0, after \r\n -> \n (a Windows checkout may add CR).
OLD_ACCEPTANCE = {
    "test_p76_s1_acceptance.py": "d66e45310b6074593c9c732a38fb774a945d0435cae77ec0aa195b7abfe80209",
    "test_p76_s2_acceptance.py": "380d50a888170170d9df7a3e9f2553067014db0d2f646e664623995423a1ff37",
    "test_p76_s3_acceptance.py": "25cb879354f58994c85e7037f5b848d69b9e21340eadd45361193c61b7aa0691",
    "test_p76_s3b_acceptance.py": "fb63e105ac63e6a2b40578e0009bea4c6d6f6fe1ed50c3de8465a9319ba9d6f6",
    "test_p76_s4_acceptance.py": "bd6fb989cc63c0db28bc08dfaa558c51ca362367a364144c2f9393bacd84eb28",
    "test_p76_s5_acceptance.py": "dd2383325d7896486fe2f74180f6c7ec5c0f3e6284d0f62f608818750c01c4e1",
    "test_p76_s6b_acceptance.py": "8fab8ef03555e627dcd9a9200fde132c167503275f23e0b2f857e6b7f9f8f219",
    "test_p76_s7_acceptance.py": "9162706a19944f253c0992752bf083ef32501a9e74e9c03c3cf168cb5f515586",
    "test_p78_s1_acceptance.py": "e9a5fdb5b231a0cbd52026d201da1bc68b6f650088872ed846997637f6721438",
    "test_p78_s2_acceptance.py": "c43c90dce9f45ab356c73fcbc1585af830d98e47c8678cf7dc8417568bb3d68d",
    "test_p78_s3_acceptance.py": "3180263c607435489fd6f851ce76c0e0ea1e3ac3e27373f66e8831b3442aa0fc",
    "test_p78_s4_acceptance.py": "b77f54ab4300170ec577be41345bfa1e66558a0a2e565979a967d563fe476b32",
    "test_p78_s4a_acceptance.py": "4c123a0fb8775cb4f27bfd9a5797036098142001ab1b1688450fbeb7936af316",
    "test_p78_s5_acceptance.py": "a4b7c3a176138abab079bf682f3be356c0d67c9a6f60d66f848087716a9c3f57",
    "test_p78_s6_acceptance.py": "1ac3bbd23d942cd8068287c0e1f72555c880dfff5934ce6f628ad31778458c9a",
}
# The 24 PNGs directly in docs/screenshots/ on main at v0.4.0 (P78 S2/S4 pin this set).
SHOTS_040 = {"%s_%s.png" % (s, z) for s in ("open", "result", "fixfirst", "findings", "code", "diff")
             for z in ("390x844", "520x900", "1280x800")} | {
    "rail_mini_1280x800.png", "settings_390x844.png", "settings_1280x800.png",
    "result_light_390x844.png", "result_light_1280x800.png", "browse_refused_390x844.png"}


def html():
    return (UI / "index.html").read_text(encoding="utf-8")


def js():
    return (UI / "app.js").read_text(encoding="utf-8")


# ---- C5 plain sentence builders --------------------------------------------------------------------------------------

def _group(glob, findings, files=None, by_code=None):
    return {"glob": glob, "files": findings if files is None else files, "findings": findings,
            "by_code": by_code if by_code is not None else {"secret.key FAIL": findings}, "fail": findings}


def test_backup_offer_line_exact():
    from code_guardian import plain
    assert plain.backup_offer_line([_group("_archive/*", 151)], 206) == \
        "151 of 206 findings are in 1 folder that looks like a backup copy: _archive/*"
    assert plain.backup_offer_line([_group("_archive/*", 151), _group("*.backup-*", 3)], 206) == \
        "154 of 206 findings are in 1 folder and 1 set of files that look like backup copies: _archive/*, *.backup-*"
    assert plain.backup_offer_line([_group("_archive/*", 5), _group("old/*", 2)], 9) == \
        "7 of 9 findings are in 2 folders that look like backup copies: _archive/*, old/*"


def test_held_line_exact():
    from code_guardian import plain
    held = [{"glob": "old/*", "why": "app/main.py imports old/helper.py"},
            {"glob": "_backup/*", "why": "it holds a file that runs a shell command"}]
    assert plain.held_line(held) == ["old/* was not offered: app/main.py imports old/helper.py",
                                     "_backup/* was not offered: it holds a file that runs a shell command"]
    assert plain.held_line([]) == []


def test_named_line_exact():
    from code_guardian import plain
    four = {"glob": "_archive/*", "named_by": ["a.py", "b.py", "c.py", "d.py"]}
    assert plain.named_line(four) == ("_archive/* is named in a string by 4 files (a.py, b.py, c.py and 1 more): "
                                      "leave it out only if they just write copies there")
    one = {"glob": "old/*", "named_by": ["app/main.py"]}
    assert plain.named_line(one) == ("old/* is named in a string by 1 file (app/main.py): leave it out only if they "
                                     "just write copies there")
    assert plain.named_line({"glob": "old/*", "named_by": []}) is None


def test_left_out_line_exact():
    from code_guardian import plain
    one = [{"glob": "_archive/*", "files": 151, "findings": 151, "by_code": {"secret.key FAIL": 151}}]
    assert plain.left_out_line(one) == \
        "Left out at your request: _archive/* (151 files, 151 findings left out: 151 secret.key, 0 other)"
    two = [{"glob": "_archive/*", "files": 40, "findings": 12,
            "by_code": {"secret.key FAIL": 7, "secret.key INFO": 2, "exec.shell WARN": 3}},
           {"glob": "*.backup-*", "files": 3, "findings": 5, "by_code": {"secret.key FAIL": 3, "quality.todo INFO": 2}}]
    assert plain.left_out_line(two) == \
        "Left out at your request: _archive/*, *.backup-* (43 files, 17 findings left out: 12 secret.key, 5 other)"
    cli = [{"glob": "_archive/*", "files": 151}, {"glob": "old/*", "files": 4}]
    assert plain.left_out_line(cli) == "Left out at your request: _archive/*, old/* (155 files)"


def test_test_values_line_exact():
    from code_guardian import plain
    assert plain.test_values_line(3) == "3 key-shaped values were graded as test values -- check they are fake"
    assert plain.test_values_line(20) == "20 key-shaped values were graded as test values -- check they are fake"


# ---- C5 markup, wiring, tokens, contrast -----------------------------------------------------------------------------

def test_index_html_holds_the_elements():
    h = html()
    for el_id in ("backup-banner", "backup-offer-text", "backup-exclude", "backup-keep", "backup-held", "backup-named",
                  "backup-cli", "left-out", "left-out-text", "left-out-put-back", "test-values", "test-values-show"):
        assert re.search(r'\bid="%s"' % el_id, h), "#%s missing from index.html" % el_id
    assert re.search(r'<button\b[^>]*\bid="backup-exclude"[^>]*>\s*Check again without them\s*<', h), "#backup-exclude"
    assert re.search(r'<button\b[^>]*\bid="backup-keep"[^>]*>\s*Keep them in\s*<', h), "#backup-keep"
    assert re.search(r'<[a-z]+\b[^>]*\bid="left-out-put-back"[^>]*>\s*Put them back\s*<', h), "#left-out-put-back"
    assert re.search(r'<details\b[^>]*\bid="backup-cli"', h), "#backup-cli must be a <details>"
    m = re.search(r'<details\b[^>]*\bid="backup-cli"[^>]*>\s*<summary>\s*Using the command line\?\s*</summary>', h)
    assert m, "#backup-cli summary must read 'Using the command line?'"
    for el_id in ("backup-banner", "left-out", "test-values"):
        tag = re.search(r'<[a-z]+\b[^>]*\bid="%s"[^>]*>' % el_id, h).group(0)
        assert re.search(r"\bhidden\b", tag), "#%s must start hidden" % el_id


def test_open_form_never_sends_exclude_and_app_js_sets_it_in_few_places():
    j = js()
    assert re.search(r"\bexclude\b", j), "app.js never sends exclude"
    sites = re.findall(r"\bexclude\s*:|\.exclude\s*=|\[\s*[\"']exclude[\"']\s*\]\s*=", j)
    # at most a request helper plus the two actions (banner, put back); the browser test proves which actions send it
    assert 1 <= len(sites) <= 3, "exclude is set in %d places; only the banner and put-back actions may send it" % len(sites)
    form = re.search(r'<form\b[^>]*\bid="scan-form".*?</form>', html(), re.S).group(0)
    assert "exclude" not in form.lower(), "the Open form must not offer an exclude"


def test_token_sets_equal_040_in_both_themes():
    css = (UI / "app.css").read_text(encoding="utf-8")
    found = {}
    for m in BLOCK.finditer(css):
        found["light" if m.group(1) else "dark"] = dict(
            (k, v.strip()) for k, v in re.findall(r"(--[\w-]+|color-scheme)\s*:\s*([^;]+);", m.group(2)))
    assert found == TOKENS_040, "the :root token sets changed"


def test_contrast_ok():
    r = subprocess.run([sys.executable, str(ROOT / "tools" / "contrast_check.py"), str(UI / "app.css")],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stdout + r.stderr
    assert re.search(r"^ok: \d+ pairs in 2 palettes", r.stdout, re.M), r.stdout


def test_old_acceptance_files_untouched():
    for name, digest in sorted(OLD_ACCEPTANCE.items()):
        data = (HERE / name).read_bytes().replace(b"\r\n", b"\n")
        assert hashlib.sha256(data).hexdigest() == digest, "%s was edited" % name


def _png_size(path):
    with open(path, "rb") as fh:
        head = fh.read(24)
    assert head[:8] == b"\x89PNG\r\n\x1a\n", path
    return struct.unpack(">II", head[16:24])


def test_four_screenshots_and_the_p78_set_unchanged():
    for name in P88_SHOTS:
        p = SHOTS_DIR / name
        assert p.is_file(), "missing screenshot %s" % p.relative_to(ROOT)
        assert p.stat().st_size > 10 * 1024, name
        w = int(re.search(r"_(\d+)x(\d+)\.png$", name).group(1))
        pw, _ = _png_size(p)
        assert pw / w in (1, 2, 3), (name, pw)
    assert {p.name for p in SHOTS.glob("*.png")} == SHOTS_040, "docs/screenshots/*.png must stay the P78 set"


# ---- the round trip through the real server (container only) ---------------------------------------------------------

def _real_shaped_key():
    """A key built at test time: mixed letters and digits, no placeholder word, no run, many distinct characters."""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789"
    seed, body = 88, ""
    while len(body) < 24:
        seed = (seed * 1103515245 + 12345) % 2 ** 31
        c = alphabet[(seed >> 16) % len(alphabet)]
        if body and c == body[-1]:
            continue
        body += c
    low = body.lower()
    for w in ("mock", "fake", "dummy", "example", "placeholder", "sample", "redacted", "test", "testing", "notreal",
              "changeit", "xxx"):
        assert w not in low
    assert len(set(body)) >= 12
    return "s" + "k-" + body


def build_backup_folder(dest):
    """A small app plus an `_archive/` copy (offered) and an `old/` folder the app imports (held)."""
    dest = Path(dest)
    key = _real_shaped_key()
    (dest / "app").mkdir(parents=True)
    (dest / "app" / "__init__.py").write_text("", encoding="utf-8")
    (dest / "app" / "main.py").write_text(
        "import old.helper\n\n\ndef run():\n    return old.helper.answer()\n", encoding="utf-8")
    (dest / "old").mkdir()
    (dest / "old" / "__init__.py").write_text("", encoding="utf-8")
    (dest / "old" / "helper.py").write_text(
        'API_KEY_VALUE = "%s"\n\n\ndef answer():\n    return len(API_KEY_VALUE)\n' % key, encoding="utf-8")
    (dest / "_archive" / "app").mkdir(parents=True)
    (dest / "_archive" / "app" / "settings.py").write_text('API_KEY_VALUE = "%s"\n' % key, encoding="utf-8")
    (dest / "_archive" / "app" / "settings_v2.py").write_text('SERVICE_KEY_VALUE = "%s"\n' % key, encoding="utf-8")
    return dest


class Server:
    def __init__(self):
        from code_guardian import ui
        self.s = ui.make_server(port=0)
        self.t = threading.Thread(target=self.s.serve_forever)
        self.t.start()
        self.port = self.s.server_address[1]

    def call(self, method, path, body=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=120)
        headers = {"Host": "127.0.0.1:%d" % self.port, "Content-Type": "application/json", "X-CG-Token": self.s.token}
        c.request(method, path, None if body is None else json.dumps(body), headers)
        r = c.getresponse()
        raw = r.read()
        c.close()
        return r.status, json.loads(raw.decode("utf-8"))

    def close(self):
        self.s.shutdown()
        self.s.server_close()
        self.t.join(10)


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


@pytest.fixture
def page_and_server(browser):
    srv = Server()
    ctx = browser.new_context(viewport={"width": 1280, "height": 800})
    page = ctx.new_page()
    posts = []   # (request body, response body) of every POST /api/scan the page sends

    def on_response(resp):
        if resp.request.method == "POST" and resp.url.endswith("/api/scan"):
            posts.append((json.loads(resp.request.post_data or "{}"), resp.json()))
    page.on("response", on_response)
    page.goto("http://127.0.0.1:%d/#t=%s" % (srv.port, srv.s.token))
    page.wait_for_selector("#screen-open:not([hidden])", timeout=30000)
    yield page, srv, posts
    ctx.close()
    srv.close()


def _shown(page, sel):
    return page.evaluate("""(sel) => {
        let e = document.querySelector(sel);
        if (!e) return false;
        for (; e; e = e.parentElement) {
            if (e.hidden || getComputedStyle(e).display === "none") return false;
        }
        return true; }""", sel)


def _settle(page):
    page.wait_for_load_state("networkidle")
    page.wait_for_selector("#check-again:not([disabled])", timeout=120000)


def test_round_trip_banner_held_left_out_put_back(page_and_server, tmp_path):
    from code_guardian import plain
    page, srv, posts = page_and_server
    folder = build_backup_folder(tmp_path / "proj")

    # 1. a plain check from the Open form: no exclude is sent; the banner offers _archive/* and holds old/*
    page.fill("#path", str(folder))
    page.click("#scan-button")
    page.wait_for_selector("#screen-result:not([hidden])", timeout=120000)
    _settle(page)
    assert len(posts) == 1 and "exclude" not in posts[0][0], posts[0][0]
    first = posts[0][1]
    offer = first["backup_offer"]
    assert [g["glob"] for g in offer["offered"]] == ["_archive/*"], offer
    assert [g["glob"] for g in offer["held"]] == ["old/*"], offer
    assert _shown(page, "#backup-banner")
    total = len(first["report"]["findings"])
    assert page.inner_text("#backup-offer-text").strip() == plain.backup_offer_line(offer["offered"], total)
    held_text = page.inner_text("#backup-held")
    for line in plain.held_line(offer["held"]):
        assert line in held_text, (line, held_text)
    assert "app/main.py" in held_text
    cli = page.evaluate("document.querySelector('#backup-cli').textContent")
    assert "--exclude" in cli and "_archive/*" in cli, cli
    assert not _shown(page, "#left-out")

    # 2. Keep them in: the banner goes, nothing is sent
    page.click("#backup-keep")
    assert not _shown(page, "#backup-banner")
    page.wait_for_load_state("networkidle")
    assert len(posts) == 1

    # 3. a plain Check again: no exclude, and the banner is back (no state kept)
    page.click("#check-again")
    _settle(page)
    assert len(posts) == 2 and "exclude" not in posts[1][0], posts[1][0]
    assert _shown(page, "#backup-banner")

    # 4. Check again without them: exclude = the offered globs; the left-out line carries by-code counts
    page.click("#backup-exclude")
    _settle(page)
    assert len(posts) == 3 and posts[2][0].get("exclude") == ["_archive/*"], posts[2][0]
    rep = posts[2][1]["report"]
    groups = rep["excluded_by_request"]
    assert [g["glob"] for g in groups] == ["_archive/*"], groups
    assert groups[0]["findings"] >= 1 and groups[0]["by_code"], groups
    assert all("_archive/" not in (f.get("node") or "") for f in rep["findings"]), "_archive findings still reported"
    assert _shown(page, "#left-out")
    line = page.inner_text("#left-out-text").strip()
    assert line == plain.left_out_line(groups), line
    assert "secret.key" in line and "findings left out" in line
    assert not _shown(page, "#backup-banner")
    assert page.get_attribute("#check-again", "title").endswith("(without _archive/*)")

    # 5. Check again on the excluded result: the server keeps the exclude; the page does not resend it
    page.click("#check-again")
    _settle(page)
    assert len(posts) == 4 and "exclude" not in posts[3][0], posts[3][0]
    assert [g["glob"] for g in posts[3][1]["report"]["excluded_by_request"]] == ["_archive/*"]
    assert _shown(page, "#left-out") and page.inner_text("#left-out-text").strip() == line

    # 6. Put them back: exclude = [], the line goes, the banner returns
    page.click("#left-out-put-back")
    _settle(page)
    assert len(posts) == 5 and posts[4][0].get("exclude") == [], posts[4][0]
    assert "excluded_by_request" not in posts[4][1]["report"]
    assert not _shown(page, "#left-out")
    assert _shown(page, "#backup-banner")


def test_a_saved_check_reopens_with_the_left_out_line(page_and_server, tmp_path):
    from code_guardian import plain
    page, srv, posts = page_and_server
    folder = build_backup_folder(tmp_path / "proj")
    # Amended 2026-10-24 ~22:15 (overseer): the real order -- a check without excludes makes the offer, then the
    # banner's re-check leaves the copy out; the saved result keeps the offer's counts, files included (a pruned
    # folder is ONE path to the walk, so the file count must come from the offer, which counts the files in it).
    status, first = srv.call("POST", "/api/scan", {"path": str(folder), "goal_file": None})
    assert status == 200, first
    offered = {g["glob"]: g for g in first["backup_offer"]["offered"]}
    assert "_archive/*" in offered, first["backup_offer"]
    status, got = srv.call("POST", "/api/scan", {"path": str(folder), "goal_file": None, "exclude": ["_archive/*"]})
    assert status == 200, got
    groups = got["report"]["excluded_by_request"]
    assert groups and "findings" in groups[0] and "by_code" in groups[0], groups
    assert groups[0]["files"] == offered["_archive/*"]["files"], (groups[0], offered["_archive/*"])
    saved = tmp_path / "saved.json"
    saved.write_text(json.dumps(got["report"]), encoding="utf-8")
    page.set_input_files("#open-saved", str(saved))
    page.wait_for_selector("#screen-result:not([hidden])", timeout=30000)
    page.wait_for_load_state("networkidle")
    assert _shown(page, "#left-out")
    assert page.inner_text("#left-out-text").strip() == plain.left_out_line(groups)


def _stub_report_with_test_values():
    """A real report of clean_repo with three key findings graded as test values and one other finding added."""
    from code_guardian import report
    rep = json.loads(json.dumps(report.scan(str(FIXTURES / "clean_repo"))))
    for i, reason in enumerate(("spells out FAKE", "is mostly one character", "counts up")):
        rep["findings"].append({
            "code": "secret.key", "level": "INFO", "node": "app/conf_%d.py:%d" % (i, i + 3),
            "summary": "API key in the source (looks like a test value; value redacted)",
            "evidence": ["matched: API key", "length: 27", "looks like a test value: %s" % reason],
            "fix": ["keep test values out of the source too, or make them obviously fake"],
            "confidence": "high", "fingerprint": "p88s2tv%d" % i})
    rep["findings"].append({
        "code": "secret.key", "level": "FAIL", "node": "app/live.py:2",
        "summary": "API key in the source (value redacted)", "evidence": ["matched: API key", "length: 27"],
        "fix": ["move it to an environment variable"], "confidence": "high", "fingerprint": "p88s2real"})
    rep["test_values_graded"] = 3
    return rep


def test_test_value_line_renders_and_filters(page_and_server, tmp_path):
    from code_guardian import plain
    page, srv, posts = page_and_server
    saved = tmp_path / "tv.json"
    saved.write_text(json.dumps(_stub_report_with_test_values()), encoding="utf-8")
    page.set_input_files("#open-saved", str(saved))
    page.wait_for_selector("#screen-result:not([hidden])", timeout=30000)
    page.wait_for_load_state("networkidle")
    assert _shown(page, "#test-values")
    assert plain.test_values_line(3) in page.inner_text("#test-values")
    page.click("#test-values-show")
    page.wait_for_selector("#screen-findings:not([hidden])", timeout=30000)
    prints = page.evaluate("""() => Array.from(document.querySelectorAll('#groups article.card')).filter(c => {
        for (let e = c; e; e = e.parentElement) { if (e.hidden || getComputedStyle(e).display === 'none') return false; }
        return true; }).map(c => c.textContent)""")
    assert len(prints) == 3, prints
    for i in range(3):
        assert any("p88s2tv%d" % i in t for t in prints), i
    assert not any("p88s2real" in t for t in prints)


def test_no_test_value_line_without_the_key(page_and_server, tmp_path):
    from code_guardian import report
    page, srv, posts = page_and_server
    saved = tmp_path / "clean.json"
    saved.write_text(json.dumps(report.scan(str(FIXTURES / "clean_repo"))), encoding="utf-8")
    page.set_input_files("#open-saved", str(saved))
    page.wait_for_selector("#screen-result:not([hidden])", timeout=30000)
    page.wait_for_load_state("networkidle")
    assert not _shown(page, "#test-values")
    assert not _shown(page, "#left-out")
    assert not _shown(page, "#backup-banner")
