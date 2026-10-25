"""The page's backup banner, left-out line and test-value line beyond tests/test_p88_s2_acceptance.py: the sentences the
page builds against plain.py on inputs the acceptance file does not use, the banner's button when the check already left
something out, and the filter on the findings list. The browser tests need Playwright and Chromium and skip without them."""
import json
import re
import threading
from pathlib import Path

import pytest

from code_guardian import plain, report, ui

HERE = Path(__file__).resolve().parent
CLEAN = HERE / "fixtures" / "clean_repo"
UI = HERE.parent / "code_guardian" / "ui"


def test_the_page_sends_no_exclude_but_from_the_two_actions():
    js = (UI / "app.js").read_text(encoding="utf-8")
    sent = re.findall(r"checkAgain\(\{[^}]*\}\)", js)
    assert len(sent) == 2 and sum("exclude" in s for s in sent) == 2, sent


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
def page(browser):
    srv = ui.make_server(port=0)
    thread = threading.Thread(target=srv.serve_forever)
    thread.start()
    ctx = browser.new_context(viewport={"width": 1280, "height": 800})
    pg = ctx.new_page()
    pg.goto("http://127.0.0.1:%d/#t=%s" % (srv.server_address[1], srv.token))
    pg.wait_for_selector("#screen-open:not([hidden])", timeout=30000)
    yield pg, srv
    ctx.close()
    srv.shutdown()
    srv.server_close()
    thread.join(10)


def shown(pg, sel):
    return pg.evaluate("""(sel) => { let e = document.querySelector(sel);
        for (; e; e = e.parentElement) { if (e.hidden || getComputedStyle(e).display === "none") return false; }
        return !!document.querySelector(sel); }""", sel)


def saved_report(tmp_path, **extra):
    rep = json.loads(json.dumps(report.scan(str(CLEAN))))
    rep.update(extra)
    path = tmp_path / "saved.json"
    path.write_text(json.dumps(rep), encoding="utf-8")
    return path, rep


def open_saved(pg, path):
    pg.set_input_files("#open-saved", str(path))
    pg.wait_for_selector("#screen-result:not([hidden])", timeout=30000)
    pg.wait_for_load_state("networkidle")


LEFT_OUT = [
    [{"glob": "_archive/*", "files": 1, "findings": 1, "by_code": {"secret.key FAIL": 1}}],
    [{"glob": "_archive/*", "files": 2, "findings": 4, "by_code": {"secret.key INFO": 1, "exec.shell WARN": 3}},
     {"glob": "old/*", "files": 5, "findings": 0, "by_code": {}}],
    [{"glob": "_archive/*", "files": 151}, {"glob": "old/*", "files": 4}],
    [{"glob": "_archive/*", "files": 3, "findings": 2, "by_code": {"secret.key FAIL": 2}}, {"glob": "old/*", "files": 4}],
]


@pytest.mark.parametrize("groups", LEFT_OUT)
def test_left_out_line_matches_plain(page, tmp_path, groups):
    pg, _ = page
    path, _ = saved_report(tmp_path, excluded_by_request=groups)
    open_saved(pg, path)
    assert shown(pg, "#left-out")
    assert pg.inner_text("#left-out-text").strip() == plain.left_out_line(groups)
    assert pg.get_attribute("#check-again", "title").endswith("(without %s)" % ", ".join(g["glob"] for g in groups))
    # still there on another tab of the same check
    pg.click('#tabs [data-screen="findings"]')
    assert shown(pg, "#left-out")


@pytest.mark.parametrize("n", [1, 3])
def test_test_value_line_matches_plain(page, tmp_path, n):
    pg, _ = page
    path, _ = saved_report(tmp_path, test_values_graded=n)
    open_saved(pg, path)
    assert pg.inner_text("#test-values-text").strip() == plain.test_values_line(n)


def stub_result(srv, offer, excluded=None, exclude=()):
    """What POST /api/scan answers for the clean fixture, with the given backup_offer and left-out groups."""
    import http.client
    c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=60)
    c.request("POST", "/api/scan", json.dumps({"path": str(CLEAN), "goal_file": None}),
              {"Host": "127.0.0.1:%d" % srv.server_address[1], "Content-Type": "application/json",
               "X-CG-Token": srv.token})
    got = json.loads(c.getresponse().read().decode("utf-8"))
    c.close()
    got["backup_offer"] = offer
    got["exclude"] = list(exclude)
    if excluded:
        got["report"]["excluded_by_request"] = excluded
    return got


OFFER = {"offered": [{"glob": "_archive/*", "files": 9, "findings": 5, "by_code": {"secret.key FAIL": 5}, "fail": 5,
                      "named_by": ["a.py", "b.py", "c.py", "d.py"]},
                     {"glob": "*.backup-*", "files": 1, "findings": 1, "by_code": {"secret.key FAIL": 1}, "fail": 1,
                      "named_by": []}],
         "held": [{"glob": "old/*", "why": "app/main.py imports it"}]}


def serve(pg, stub, seen):
    """Answer every POST /api/scan with stub, recording the request bodies in seen."""
    def handler(route):
        seen.append(json.loads(route.request.post_data or "{}"))
        route.fulfill(status=200, content_type="application/json", body=json.dumps(stub))
    pg.route("**/api/scan", handler)


def test_banner_lines_match_plain_and_the_button_adds_to_what_was_left_out(page):
    pg, srv = page
    left = [{"glob": "docs/*", "files": 2}]
    stub = stub_result(srv, OFFER, excluded=left, exclude=["docs/*"])
    seen = []
    serve(pg, stub, seen)
    pg.fill("#path", str(CLEAN))
    pg.click("#scan-button")
    pg.wait_for_selector("#screen-result:not([hidden])", timeout=60000)
    pg.wait_for_selector("#check-again-summary:not([disabled])", timeout=60000)
    total = len(stub["report"]["findings"])
    assert pg.inner_text("#backup-offer-text").strip() == plain.backup_offer_line(OFFER["offered"], total)
    assert "1 folder and 1 set of files that look like backup copies" in pg.inner_text("#backup-offer-text")
    lines = [t.strip() for t in pg.locator("#backup-named li").all_inner_texts()]
    assert lines == [plain.named_line(OFFER["offered"][0])], lines
    assert [t.strip() for t in pg.locator("#backup-held li").all_inner_texts()] == plain.held_line(OFFER["held"])
    cli = pg.evaluate("document.querySelector('#backup-cli').textContent")
    assert "--exclude 'docs/*' --exclude '_archive/*' --exclude '*.backup-*'" in cli, cli
    pg.click("#backup-exclude")
    pg.wait_for_selector("#check-again-summary:not([disabled])", timeout=60000)
    assert seen[-1]["exclude"] == ["docs/*", "_archive/*", "*.backup-*"], seen[-1]
    assert seen[-1]["path"] == str(CLEAN)
    # a plain Check again repeats the check by its id and carries no paths of its own
    pg.click("#check-again-summary")
    pg.wait_for_selector("#check-again-summary:not([disabled])", timeout=60000)
    assert "exclude" not in seen[-1] and seen[-1]["again"] == stub["id"], seen[-1]


def test_findings_filter_can_be_cleared(page, tmp_path):
    pg, _ = page
    path, rep = saved_report(tmp_path, test_values_graded=1)
    rep["findings"].append({"code": "secret.key", "level": "INFO", "node": "app/conf.py:3",
                            "summary": "API key in the source (looks like a test value; value redacted)",
                            "evidence": ["matched: API key", "looks like a test value: counts up"],
                            "fix": ["make it obviously fake"], "confidence": "high", "fingerprint": "ubtv1"})
    path.write_text(json.dumps(rep), encoding="utf-8")
    open_saved(pg, path)
    pg.click("#test-values-show")
    pg.wait_for_selector("#screen-findings:not([hidden])")
    assert shown(pg, "#findings-filter")
    assert pg.locator("#groups article.card").count() == 1
    pg.click("#findings-filter-clear")
    assert not shown(pg, "#findings-filter")
    assert pg.locator("#groups article.card").count() == len(rep["findings"])
    # a later visit to Findings by the tab is not filtered: the filter ends with the check on screen being replaced
    pg.click('#tabs [data-screen="result"]')
    pg.click("#test-values-show")
    assert pg.locator("#groups article.card").count() == 1
    open_saved(pg, path)
    pg.click('#tabs [data-screen="findings"]')
    assert not shown(pg, "#findings-filter")
