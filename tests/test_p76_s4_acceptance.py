"""P76 S4 acceptance -- select-to-explain: explain.excerpt (C8), POST /api/explain (C7), the Code screen panel, and
the start/end line fields the owner asked for (decisions_log 2026-10-22 ~16:12).

Written by the overseer BEFORE the build session. The build session must add this file to the PR byte-for-byte and
must not edit it; a PR that changes it fails the section.

The env the server uses is set BEFORE make_server() in every test, so a server that reads the model settings once at
start-up and one that reads them per request both pass.
"""
import hashlib
import http.client
import json
import re
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from code_guardian import explain, report

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
FIXTURES = HERE / "fixtures"
UI = ROOT / "code_guardian" / "ui"
# sha256 of json.dumps(explain.payload(report.scan(risky_repo)), sort_keys=True) on main 2b92059/9b1d2e8
PAYLOAD_SHA = "47138193a635f2fa18ce526a2df3646b9b352359bc6e2ce31a99e045eae037c1"
SETUP_NOTE = "set CODE_GUARDIAN_LLM_URL and CODE_GUARDIAN_LLM_MODEL, then restart code-guardian ui"
REPLY = {"message": {"role": "assistant", "content": "These lines read a value and print it."}}
LINES = ["line %d of the file" % i for i in range(1, 11)]


def _project(tmp_path):
    d = tmp_path / "proj"
    d.mkdir()
    (d / "a.py").write_text("\n".join(LINES) + "\n", encoding="utf-8")
    (d / "b.py").write_text("SIBLING_FILE_MARKER = 1\n", encoding="utf-8")
    return d


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


@pytest.fixture
def no_model(monkeypatch):
    for k in ("CODE_GUARDIAN_LLM_URL", "CODE_GUARDIAN_LLM_MODEL", "CODE_GUARDIAN_LLM_KEY", "CODE_GUARDIAN_LLM_TIMEOUT"):
        monkeypatch.delenv(k, raising=False)


# ---- the scan's --explain path is unchanged ----------------------------------------------------------------------

def test_scan_explain_payload_is_byte_for_byte_unchanged():
    p = explain.payload(report.scan(str(FIXTURES / "risky_repo")))
    assert hashlib.sha256(json.dumps(p, sort_keys=True).encode("utf-8")).hexdigest() == PAYLOAD_SHA


def test_explain_selftest_did_not_shrink():
    r = subprocess.run([sys.executable, "-m", "code_guardian.explain", "--selftest"], cwd=str(ROOT),
                       capture_output=True, text=True, timeout=180)
    assert r.returncode == 0, r.stdout + r.stderr
    m = re.search(r"(\d+) checks, (\d+) passed, 0 failed", r.stdout)
    assert m and int(m.group(1)) == int(m.group(2)) >= 7, r.stdout[-400:]


# ---- C8 explain.excerpt -------------------------------------------------------------------------------------------

def test_excerpt_prompt_and_unset_model():
    assert "not write code" in explain.SYSTEM_EXCERPT and "grade" in explain.SYSTEM_EXCERPT
    text, note = explain.excerpt("a.py", LINES, 3, 5, {})
    assert text is None and note.startswith("explain skipped")


def test_excerpt_sends_exactly_the_selected_lines(stub):
    model = stub({("POST", "/api/chat"): (200, REPLY, 0)})
    text, _ = explain.excerpt("a.py", LINES, 3, 5, {"CODE_GUARDIAN_LLM_URL": model.url + "/api/chat",
                                                     "CODE_GUARDIAN_LLM_MODEL": "m"})
    assert text == REPLY["message"]["content"]
    body = model.requests[0][2]
    assert body["messages"][0]["content"] == explain.SYSTEM_EXCERPT
    assert json.loads(body["messages"][1]["content"]) == {"file": "a.py", "start": 3, "end": 5,
                                                          "code": "\n".join(LINES[2:5])}


# ---- POST /api/explain ---------------------------------------------------------------------------------------------

def test_api_explain_sends_only_the_selection(stub, tmp_path, monkeypatch, no_model):
    model = stub({("POST", "/api/chat"): (200, REPLY, 0)})
    monkeypatch.setenv("CODE_GUARDIAN_LLM_URL", model.url + "/api/chat")
    monkeypatch.setenv("CODE_GUARDIAN_LLM_MODEL", "m")
    srv = Server()
    try:
        sid = srv.scan(_project(tmp_path))
        status, js = srv.call("POST", "/api/explain", {"id": sid, "rel": "a.py", "start": 3, "end": 5})
    finally:
        srv.close()
    assert status == 200, js
    assert js["text"] == REPLY["message"]["content"]
    assert js["sent"]["model"] == "m" and js["sent"]["lines"] == 3 and "127.0.0.1" in js["sent"]["host"]
    assert len(model.requests) == 1
    raw = json.dumps(model.requests[0][2])
    sent = json.loads(model.requests[0][2]["messages"][1]["content"])
    assert sent == {"file": "a.py", "start": 3, "end": 5, "code": "\n".join(LINES[2:5])}
    for other in LINES[:2] + LINES[5:] + ["SIBLING_FILE_MARKER", str(tmp_path)]:
        assert other not in raw, other


def test_api_explain_without_a_model_is_200_with_the_setup_note(tmp_path, no_model):
    srv = Server()
    try:
        sid = srv.scan(_project(tmp_path))
        status, js = srv.call("POST", "/api/explain", {"id": sid, "rel": "a.py", "start": 1, "end": 2})
    finally:
        srv.close()
    assert status == 200
    assert js["text"] is None and js["note"] == SETUP_NOTE


def test_api_explain_with_the_model_down_names_the_host(tmp_path, monkeypatch, no_model):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    dead_port = sock.getsockname()[1]
    sock.close()
    monkeypatch.setenv("CODE_GUARDIAN_LLM_URL", "http://127.0.0.1:%d/api/chat" % dead_port)
    monkeypatch.setenv("CODE_GUARDIAN_LLM_MODEL", "m")
    monkeypatch.setenv("CODE_GUARDIAN_LLM_TIMEOUT", "3")
    srv = Server()
    try:
        sid = srv.scan(_project(tmp_path))
        status, js = srv.call("POST", "/api/explain", {"id": sid, "rel": "a.py", "start": 1, "end": 2})
    finally:
        srv.close()
    assert status == 200 and js["text"] is None
    assert "127.0.0.1:%d" % dead_port in js["note"], js["note"]


def test_api_explain_refusals(tmp_path, no_model):
    big = tmp_path / "big"
    big.mkdir()
    (big / "a.py").write_text("\n".join("x = %d" % i for i in range(300)) + "\n", encoding="utf-8")
    srv = Server()
    try:
        sid = srv.scan(big)
        assert srv.call("POST", "/api/explain", {"id": sid, "rel": "a.py", "start": 1, "end": 201})[0] == 400
        assert srv.call("POST", "/api/explain", {"id": sid, "rel": "a.py", "start": 1, "end": 200})[0] == 200
        assert srv.call("POST", "/api/explain", {"id": sid, "rel": "a.py", "start": 5, "end": 4})[0] == 400
        assert srv.call("POST", "/api/explain", {"id": sid, "rel": "a.py", "start": 0, "end": 3})[0] == 400
        assert srv.call("POST", "/api/explain", {"id": sid, "rel": "../x.py", "start": 1, "end": 2}) == \
            (403, {"error": "outside"})
        assert srv.call("POST", "/api/explain", {"id": sid, "rel": "a.py", "start": 1, "end": 2},
                        token=False) == (403, {"error": "token"})
    finally:
        srv.close()


# ---- the Code screen ------------------------------------------------------------------------------------------------

def test_page_has_line_fields_and_calls_explain():
    html = (UI / "index.html").read_text(encoding="utf-8")
    js = (UI / "app.js").read_text(encoding="utf-8")
    assert re.search(r"AI explanation (--|—) may be wrong; does not change any score", html)
    for field in ("line-start", "line-end"):
        assert re.search(r'<input\b[^>]*\bid="%s"' % field, html), field
        assert field in js, field
    assert "/api/explain" in js
