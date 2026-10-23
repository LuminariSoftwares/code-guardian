"""P76 S5 acceptance -- before / after: POST /api/diff (C7), plain.diff_sentence, the Compare screen, and its two
screenshots.

Written by the overseer BEFORE the build session. The build session must add this file to the PR byte-for-byte and
must not edit it; a PR that changes it fails the section. This file is pure ASCII on purpose: characters outside ASCII
are built with chr() so no escape sequence has to survive being retyped.
"""
import copy
import http.client
import json
import re
import struct
import subprocess
import sys
import threading
from pathlib import Path

from code_guardian import plain, report, verify

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
UI = ROOT / "code_guardian" / "ui"
SHOTS = ROOT / "docs" / "screenshots"
AWS_ID = "AKIA" + "Q7XZ" * 4  # built at runtime: the package's self-scan reads literals
ARROW = "(->|" + chr(0x2192) + ")"
VERDICT = re.compile(
    r"is safe|safe to run|\bsecure\b|\bclean\b|no risks|risk-free|\bharmless\b|\bguaranteed\b", re.IGNORECASE)
BEFORE_SRC = 'import os\n\nKEY = "%s"\n\n\ndef run(cmd):\n    os.system(cmd)\n' % AWS_ID
AFTER_SRC = 'import os\n\n\ndef run(cmd):\n    os.system(cmd)\n'


class Server:
    def __init__(self):
        from code_guardian import ui
        self.s = ui.make_server(port=0)
        self.t = threading.Thread(target=self.s.serve_forever)
        self.t.start()
        self.port = self.s.server_address[1]

    def call(self, method, path, body=None, token=True):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=90)
        headers = {"Host": "127.0.0.1:%d" % self.port, "Content-Type": "application/json"}
        if token:
            headers["X-CG-Token"] = self.s.token
        c.request(method, path, None if body is None else json.dumps(body), headers)
        r = c.getresponse()
        raw = r.read()
        c.close()
        try:
            return r.status, json.loads(raw.decode("utf-8"))
        except ValueError:
            return r.status, None

    def scan(self, path):
        status, js = self.call("POST", "/api/scan", {"path": str(path), "goal_file": None})
        assert status == 200, js
        return js["id"]

    def close(self):
        self.s.shutdown()
        self.s.server_close()
        self.t.join(10)


def _project(tmp_path):
    d = tmp_path / "proj"
    d.mkdir()
    (d / "app.py").write_text(BEFORE_SRC, encoding="utf-8")
    return d


def _expected(tmp_path):
    d = tmp_path / "direct"
    d.mkdir()
    (d / "app.py").write_text(BEFORE_SRC, encoding="utf-8")
    before = report.scan(str(d))
    (d / "app.py").write_text(AFTER_SRC, encoding="utf-8")
    after = report.scan(str(d))
    return before, after, verify.diff(before, after)


# ---- plain.diff_sentence -----------------------------------------------------------------------------------------

def test_diff_sentence_counts_and_grade(tmp_path):
    before, after, d = _expected(tmp_path)
    assert d["counts"]["fixed"] == 1 and d["counts"]["new"] == 0, d["counts"]
    s = plain.diff_sentence(d)
    assert s.startswith("1 fixed, 0 new"), s
    assert re.search(r"grade %s %s %s" % (d["grade"]["before"], ARROW, d["grade"]["after"]), s), s
    same = plain.diff_sentence(verify.diff(before, copy.deepcopy(before)))
    assert same.startswith("0 fixed, 0 new"), same
    for text in (s, same, plain.diff_sentence(verify.diff(after, before))):
        assert not VERDICT.search(text) and " -- " not in text, text


def test_diff_sentence_never_mutates(tmp_path):
    _, _, d = _expected(tmp_path)
    kept = copy.deepcopy(d)
    plain.diff_sentence(d)
    assert d == kept


# ---- POST /api/diff ------------------------------------------------------------------------------------------------

def test_api_diff_two_scans_of_one_folder(tmp_path):
    proj = _project(tmp_path)
    _, _, want = _expected(tmp_path)
    srv = Server()
    try:
        first = srv.scan(proj)
        (proj / "app.py").write_text(AFTER_SRC, encoding="utf-8")
        second = srv.scan(proj)
        status, js = srv.call("POST", "/api/diff", {"before": first, "after": second})
    finally:
        srv.close()
    assert status == 200, js
    assert [f["code"] for f in js["fixed"]] == ["secret.key"]
    assert js["new"] == []
    assert js["counts"] == want["counts"] and js["grade"] == want["grade"] and js["verdict"] == want["verdict"]
    assert sorted(f["fingerprint"] for f in js["unchanged"]) == sorted(f["fingerprint"] for f in want["unchanged"])
    assert js["sentence"] == plain.diff_sentence(want)


def test_api_diff_accepts_saved_scan_json(tmp_path):
    proj = _project(tmp_path)
    env = {"PYTHONPATH": str(ROOT)}
    import os
    env = dict(os.environ, **env)
    runs = []
    for src in (BEFORE_SRC, AFTER_SRC):
        (proj / "app.py").write_text(src, encoding="utf-8")
        r = subprocess.run([sys.executable, "-m", "code_guardian", "scan", str(proj), "--json"], cwd=str(ROOT),
                           capture_output=True, text=True, timeout=180, env=env)
        assert r.stdout.strip().startswith("{"), r.stderr[-500:]
        runs.append(r.stdout)
    srv = Server()
    try:
        status, js = srv.call("POST", "/api/diff", {"before_json": runs[0], "after_json": runs[1]})
        bad = srv.call("POST", "/api/diff", {"before_json": "not json", "after_json": runs[1]})
        missing = srv.call("POST", "/api/diff", {"before": "no-such-scan", "after": "no-such-scan-either"})
        empty = srv.call("POST", "/api/diff", {})
        no_token = srv.call("POST", "/api/diff", {"before_json": runs[0], "after_json": runs[1]}, token=False)
    finally:
        srv.close()
    assert status == 200, js
    assert [f["code"] for f in js["fixed"]] == ["secret.key"] and js["new"] == []
    assert js["sentence"].startswith("1 fixed, 0 new")
    assert bad[0] == 400
    assert missing[0] == 404
    assert empty[0] == 400
    assert no_token == (403, {"error": "token"})


# ---- the Compare screen and its screenshots ------------------------------------------------------------------------

def test_compare_screen_calls_diff_and_loads_files():
    html = (UI / "index.html").read_text(encoding="utf-8")
    js = (UI / "app.js").read_text(encoding="utf-8")
    assert "/api/diff" in js
    assert re.search(r'<input\b[^>]*\btype="file"[^>]*>', html), "a way to load a saved scan --json file"
    assert "before_json" in js and "after_json" in js


def _png_size(path):
    with open(path, "rb") as fh:
        head = fh.read(24)
    assert head[:8] == b"\x89PNG\r\n\x1a\n", path
    return struct.unpack(">II", head[16:24])


def test_two_compare_screenshots():
    for w, h in ((390, 844), (1280, 800)):
        p = SHOTS / ("diff_%dx%d.png" % (w, h))
        assert p.is_file(), p
        assert p.stat().st_size > 10 * 1024, p
        pw, ph = _png_size(p)
        assert pw / w in (1, 2, 3) and ph >= h * (pw / w), (p.name, pw, ph)
    assert len(list(SHOTS.glob("*.png"))) >= 12  # P78 S0: P78 adds more screenshots
