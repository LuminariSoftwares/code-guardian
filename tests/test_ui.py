"""code_guardian/ui.py beyond the acceptance file: malformed requests, unknown scan ids, and the token staying private."""
import http.client
import json
import threading

import pytest

from code_guardian import ui

from conftest import ROOT

CLEAN = ROOT / "tests" / "fixtures" / "clean_repo"


@pytest.fixture
def server():
    srv = ui.make_server(port=0)
    thread = threading.Thread(target=srv.serve_forever)
    thread.start()
    yield srv
    srv.shutdown()
    srv.server_close()
    thread.join(10)


def call(srv, method, path, raw=None, headers=None, token=True):
    """One request with exactly the headers given (http.client adds none of its own); returns (status, body bytes)."""
    port = srv.server_address[1]
    head = {"Host": "127.0.0.1:%d" % port}
    if token:
        head["X-CG-Token"] = srv.token
    head.update(headers or {})
    head["Content-Length"] = str(len(raw or b""))
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
    conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
    for k, v in head.items():
        conn.putheader(k, v)
    conn.endheaders(raw or b"")
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    return resp.status, body


def test_post_with_invalid_json_is_400(server):
    status, body = call(server, "POST", "/api/scan", raw=b"{not json")
    assert (status, json.loads(body)) == (400, {"error": "json"})
    status, body = call(server, "POST", "/api/scan", raw=b"[1, 2]")
    assert (status, json.loads(body)) == (400, {"error": "json"})


def test_post_without_a_path_is_400_path(server):
    status, body = call(server, "POST", "/api/scan", raw=b'{"goal_file": null}')
    assert status == 400 and json.loads(body)["error"] == "path"


def test_bad_goal_file_is_400_not_a_crash(server):
    raw = json.dumps({"path": str(CLEAN), "goal_file": str(CLEAN / "no-such-goal.toml")}).encode("utf-8")
    status, body = call(server, "POST", "/api/scan", raw=raw)
    assert status == 400 and json.loads(body)["error"] == "goal"
    assert json.loads(call(server, "GET", "/api/scans")[1]) == []


def test_unknown_scan_id_is_404(server):
    status, body = call(server, "GET", "/api/file?id=nope&rel=a.py")
    assert (status, json.loads(body)) == (404, {"error": "scan"})


def test_token_never_appears_in_a_response_body(server):
    raw = json.dumps({"path": str(CLEAN), "goal_file": None}).encode("utf-8")
    sid = json.loads(call(server, "POST", "/api/scan", raw=raw)[1])["id"]
    bodies = [call(server, "POST", "/api/scan", raw=raw)[1],
              call(server, "GET", "/api/scans")[1],
              call(server, "GET", "/api/scans", token=False)[1],
              call(server, "GET", "/api/file?id=%s&rel=../x" % sid)[1],
              call(server, "GET", "/api/file?id=nope&rel=a")[1],
              call(server, "POST", "/api/scan", raw=b"{")[1],
              call(server, "GET", "/api/nope")[1],
              call(server, "GET", "/")[1], call(server, "GET", "/app.css")[1], call(server, "GET", "/app.js")[1],
              call(server, "GET", "/", headers={"Host": "evil.example"})[1]]
    assert all(server.token.encode("utf-8") not in b for b in bodies)


def test_host_without_a_port_is_refused(server):
    for host in ("127.0.0.1", "localhost", ""):
        status, body = call(server, "GET", "/api/scans", headers={"Host": host})
        assert (status, json.loads(body)) == (403, {"error": "origin"}), host


def test_an_empty_origin_header_is_refused(server):
    status, body = call(server, "GET", "/api/scans", headers={"Origin": ""})
    assert (status, json.loads(body)) == (403, {"error": "origin"})
    status, body = call(server, "GET", "/api/scans", headers={"Origin": "null"})
    assert (status, json.loads(body)) == (403, {"error": "origin"})


def test_the_guard_runs_before_the_token(server):
    status, body = call(server, "GET", "/api/scans", headers={"Host": "evil.example"}, token=False)
    assert (status, json.loads(body)) == (403, {"error": "origin"})


def test_a_failed_scan_leaves_no_scanning_entry(server, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("boom")

    monkeypatch.setattr(ui.report, "scan", boom)
    raw = json.dumps({"path": str(CLEAN), "goal_file": None}).encode("utf-8")
    status, body = call(server, "POST", "/api/scan", raw=raw)
    assert (status, json.loads(body)["error"]) == (500, "scan") and b"boom" not in body
    assert json.loads(call(server, "GET", "/api/scans")[1]) == []
