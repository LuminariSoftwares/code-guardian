"""P76 S3b acceptance -- the owner's first design reaction (decisions_log 2026-10-22 ~16:12) plus the overseer's three
review findings on PR #28, as one small follow-up before S4.

Written by the overseer BEFORE the build session. The build session must add this file to the PR byte-for-byte and
must not edit it; a PR that changes it fails the section. What the screenshots must show is reviewed by eye.

Names this file fixes (the S3b prompt quotes them): the `/api/scan` key `plain.fix_first_notes`; the `:root` token
`--none`; the CSS class `harm-none` for the "No known risks found" label; the element ids `summary-rail` and
`check-again`; the note toggle class `note-toggle` in app.js.
"""
import copy
import http.client
import json
import re
import threading
from pathlib import Path

import pytest

from code_guardian import plain, report, verify

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
FIXTURES = HERE / "fixtures"
UI = ROOT / "code_guardian" / "ui"
DIMENSIONS = ("safe", "works", "complete", "overall")


def _js_only(tmp_path):
    d = tmp_path / "js_only"
    d.mkdir()
    (d / "index.js").write_text("console.log('hi')\n", encoding="utf-8")
    (d / "package.json").write_text(json.dumps({"name": "x", "version": "1.0.0"}), encoding="utf-8")
    return d


def _reports(tmp_path):
    reps = {n: report.scan(str(FIXTURES / n)) for n in ("risky_repo", "clean_repo", "works_broken", "supply_repo")}
    reps["js_only"] = report.scan(str(_js_only(tmp_path)))
    return reps


def _sentences(rep):
    out = [plain.harm(rep)["why"]]
    out += [plain.score_sentence(d, rep) for d in DIMENSIONS]
    out += [e["text"] for e in plain.checked_lines(rep)]
    return out


def _rgb(v):
    h = v.strip().lstrip("#").lower()
    if len(h) == 3:
        h = "".join(c * 2 for c in h)
    assert re.fullmatch(r"[0-9a-f]{6}", h), v
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


def _ratio(a, b):
    def lum(c):
        f = [x / 255.0 for x in c]
        f = [x / 12.92 if x <= 0.04045 else ((x + 0.055) / 1.055) ** 2.4 for x in f]
        return 0.2126 * f[0] + 0.7152 * f[1] + 0.0722 * f[2]
    la, lb = sorted((lum(a), lum(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def _css_tokens():
    css = (UI / "app.css").read_text(encoding="utf-8")
    body = re.search(r":root\s*\{(.*?)\}", css, re.S).group(1)
    return css, dict(re.findall(r"(--[\w-]+)\s*:\s*([^;]+);", body))


# ---- copy (plain.py) ---------------------------------------------------------------------------------------------

def test_no_ascii_double_dash_in_any_plain_sentence(tmp_path):
    hits = [(n, s) for n, rep in _reports(tmp_path).items() for s in _sentences(rep) if " -- " in s]
    assert not hits, hits[:5]


def test_partial_clause_is_not_repeated_in_every_score_sentence(tmp_path):
    rep = report.scan(str(_js_only(tmp_path)))
    assert rep["status"] == "PARTIAL"
    clause = "did not cover the whole project"
    in_scores = [d for d in DIMENSIONS if clause in plain.score_sentence(d, rep)]
    assert len(in_scores) <= 1, in_scores


def test_zero_python_files_line_claims_nothing_ran(tmp_path):
    rep = report.scan(str(_js_only(tmp_path)))
    py = [e for e in plain.checked_lines(rep) if e["label"] == "Python"]
    assert py and py[0]["files"] == 0
    assert "ran on these" not in py[0]["text"] and "every" not in py[0]["text"]


def test_plain_still_never_mutates_the_report(tmp_path):
    for rep in _reports(tmp_path).values():
        before = copy.deepcopy(rep)
        _sentences(rep)
        plain.fix_first_notes(rep)
        assert rep == before


# ---- fix-first notes reach the page ------------------------------------------------------------------------------

def test_api_scan_carries_fix_first_notes():
    from code_guardian import ui
    s = ui.make_server(port=0)
    t = threading.Thread(target=s.serve_forever)
    t.start()
    try:
        port = s.server_address[1]
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
        body = json.dumps({"path": str(FIXTURES / "risky_repo"), "goal_file": None})
        c.request("POST", "/api/scan", body, {"X-CG-Token": s.token, "Content-Type": "application/json",
                                             "Host": "127.0.0.1:%d" % port})
        r = c.getresponse()
        js = json.loads(r.read().decode("utf-8"))
        c.close()
    finally:
        s.shutdown()
        s.server_close()
        t.join(10)
    assert r.status == 200
    notes = js["plain"]["fix_first_notes"]
    assert notes == verify.plan(js["report"], top=10)["notes"]
    assert any("caps the grade" in n for n in notes), notes


def test_page_renders_the_notes():
    js = (UI / "app.js").read_text(encoding="utf-8")
    assert "fix_first_notes" in js


# ---- "No known risks found" is neutral, never green --------------------------------------------------------------

def test_no_known_risks_label_is_a_neutral_token():
    css, tok = _css_tokens()
    assert "--none" in tok, "no --none token in :root"
    rules = re.findall(r"([^{}]*\bharm-none\b[^{}]*)\{([^}]*)\}", css)
    assert rules, "no CSS rule for .harm-none"
    for _, decl in rules:
        assert "var(--ok)" not in decl, decl
    assert any("var(--none)" in decl for _, decl in rules), rules
    assert "harm-none" in (UI / "app.js").read_text(encoding="utf-8")
    assert _ratio(_rgb(tok["--none"]), _rgb(tok["--bg"])) >= 3.0
    assert _ratio(_rgb(tok["--none"]), _rgb(tok["--surface"])) >= 3.0
    ok, none = _rgb(tok["--ok"]), _rgb(tok["--none"])
    assert max(none) - min(none) <= 24, "--none is meant to be a grey, got %s" % tok["--none"]
    assert none != ok


# ---- summary rail, check again, inline notes ---------------------------------------------------------------------

def test_summary_rail_and_check_again_exist():
    html = (UI / "index.html").read_text(encoding="utf-8")
    js = (UI / "app.js").read_text(encoding="utf-8")
    assert 'id="summary-rail"' in html
    assert 'id="check-again"' in html
    assert "check-again" in js and "summary-rail" in js
    assert not re.search(r"setInterval\([^)]*/api/scan\b", js), "no automatic re-scan of the user's files"


def test_inline_notes_expand_to_why_and_fix():
    js = (UI / "app.js").read_text(encoding="utf-8")
    assert "note-toggle" in js
    assert re.search(r"\.why\b", js) and re.search(r"\.how\b", js), "an expanded note shows the card's why and how"


@pytest.mark.parametrize("name", ["test_p76_s1_acceptance.py", "test_p76_s2_acceptance.py",
                                  "test_p76_s3_acceptance.py"])
def test_earlier_acceptance_files_still_present(name):
    assert (HERE / name).is_file()
