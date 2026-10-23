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


# ---- POST /api/explain (P76 S4): the refusals and the dry run; the sending is in test_p76_s4_acceptance.py -----------

EXPLAIN_ENV = ("CODE_GUARDIAN_LLM_URL", "CODE_GUARDIAN_LLM_MODEL", "CODE_GUARDIAN_LLM_KEY", "CODE_GUARDIAN_LLM_TIMEOUT")


@pytest.fixture
def scanned(server, tmp_path, monkeypatch):
    for k in EXPLAIN_ENV:
        monkeypatch.delenv(k, raising=False)
    (tmp_path / "a.py").write_text("one = 1\ntwo = 2\nthree = 3\n", encoding="utf-8")
    (tmp_path / "blob.bin").write_bytes(b"\0\1\2")
    status, raw = call(server, "POST", "/api/scan", json.dumps({"path": str(tmp_path), "goal_file": None}).encode())
    assert status == 200
    return json.loads(raw)["id"]


def explain_call(server, **body):
    status, raw = call(server, "POST", "/api/explain", json.dumps(body).encode())
    return status, json.loads(raw)


def test_explain_rejects_bad_bodies(server, scanned):
    assert call(server, "POST", "/api/explain", b"{nope")[0] == 400
    assert call(server, "POST", "/api/explain", b"[]")[0] == 400
    good = {"id": scanned, "rel": "a.py", "start": 1, "end": 2}
    for bad in ({"rel": "a.py"}, dict(good, id=1), dict(good, rel=None), dict(good, start="1"), dict(good, end=2.5),
                dict(good, start=True), dict(good, end=None)):
        assert explain_call(server, **bad)[0] == 400, bad
    assert explain_call(server, **good)[0] == 200


def test_explain_end_past_the_file_is_400(server, scanned):
    status, js = explain_call(server, id=scanned, rel="a.py", start=3, end=4)
    assert status == 400 and js["error"] == "range" and "3 lines" in js["detail"]


def test_explain_unknown_scan_missing_and_binary_file(server, scanned):
    assert explain_call(server, id="nope", rel="a.py", start=1, end=1) == (404, {"error": "scan"})
    assert explain_call(server, id=scanned, rel="gone.py", start=1, end=1) == (404, {"error": "file"})
    assert explain_call(server, id=scanned, rel="blob.bin", start=1, end=1) == (415, {"error": "binary"})
    assert explain_call(server, id=scanned, rel="/etc/hosts", start=1, end=1) == (403, {"error": "outside"})


def test_explain_dry_run_says_where_and_sends_nothing(server, scanned, stub, monkeypatch):
    model = stub({("POST", "/api/chat"): (200, {"message": {"content": "x"}}, 0)})
    monkeypatch.setenv("CODE_GUARDIAN_LLM_URL", "http://user:secret@" + model.url.split("//")[1] + "/api/chat")
    monkeypatch.setenv("CODE_GUARDIAN_LLM_MODEL", "tiny")
    status, js = explain_call(server, id=scanned, rel="a.py", start=1, end=2, dry_run=True)
    assert status == 200 and js["text"] is None and js["note"] is None
    assert js["sent"] == {"host": model.url.split("//")[1], "model": "tiny", "lines": 2}
    assert model.requests == []
    assert "secret" not in json.dumps(js)


def test_explain_with_no_model_never_calls_out(server, scanned, monkeypatch):
    note = "set CODE_GUARDIAN_LLM_URL and CODE_GUARDIAN_LLM_MODEL, then restart code-guardian ui"
    for url, model in (("", ""), ("http://127.0.0.1:9", ""), ("", "m")):
        monkeypatch.setenv("CODE_GUARDIAN_LLM_URL", url)
        monkeypatch.setenv("CODE_GUARDIAN_LLM_MODEL", model)
        for dry in (True, False):
            assert explain_call(server, id=scanned, rel="a.py", start=1, end=1, dry_run=dry) == \
                (200, {"text": None, "note": note, "sent": None})


def test_explain_refused_url_is_a_note_not_a_crash(server, scanned, monkeypatch):
    monkeypatch.setenv("CODE_GUARDIAN_LLM_URL", "file:///etc/hosts")
    monkeypatch.setenv("CODE_GUARDIAN_LLM_MODEL", "m")
    status, js = explain_call(server, id=scanned, rel="a.py", start=1, end=1)
    assert status == 200 and js["text"] is None and js["sent"] is None and js["note"].startswith("explain skipped")


def test_explain_reads_the_model_settings_per_request(server, scanned, stub, monkeypatch):
    model = stub({("POST", "/api/chat"): (200, {"message": {"content": "ok"}}, 0)})
    assert explain_call(server, id=scanned, rel="a.py", start=1, end=1)[1]["sent"] is None
    monkeypatch.setenv("CODE_GUARDIAN_LLM_URL", model.url)
    monkeypatch.setenv("CODE_GUARDIAN_LLM_MODEL", "m")
    assert explain_call(server, id=scanned, rel="a.py", start=1, end=1)[1]["text"] == "ok"


# ---- POST /api/diff (P76 S5): the refusals and the memory; the happy paths are in test_p76_s5_acceptance.py ---------

def diff_call(server, body):
    status, raw = call(server, "POST", "/api/diff", json.dumps(body).encode())
    return status, json.loads(raw)


def scan_id(server, path):
    status, raw = call(server, "POST", "/api/scan", json.dumps({"path": str(path), "goal_file": None}).encode())
    assert status == 200
    return json.loads(raw)["id"]


def test_diff_keeps_only_the_last_reports(server, monkeypatch):
    monkeypatch.setattr(ui, "REPORTS_KEPT", 2)
    ids = [scan_id(server, CLEAN) for _ in range(3)]
    assert diff_call(server, {"before": ids[0], "after": ids[2]})[0] == 404
    status, d = diff_call(server, {"before": ids[1], "after": ids[2]})
    assert status == 200 and d["counts"]["fixed"] == d["counts"]["new"] == 0
    assert d["sentence"].startswith("0 fixed, 0 new, grade ")


def test_diff_never_reads_a_path_given_as_saved_text(server, tmp_path):
    saved = tmp_path / "saved.json"
    saved.write_text(json.dumps(ui.report.scan(str(CLEAN))), encoding="utf-8")
    status, d = diff_call(server, {"before_json": str(saved), "after_json": str(saved)})
    assert (status, d["error"], d["side"]) == (400, "report", "before")


def test_diff_refuses_half_pairs_and_non_reports(server):
    good = json.dumps(ui.report.scan(str(CLEAN)))
    assert diff_call(server, {"before": "x"})[0] == 400
    assert diff_call(server, {"before_json": good})[0] == 400
    assert diff_call(server, {"before": 1, "after": 2})[0] == 400
    status, d = diff_call(server, {"before_json": good, "after_json": "[1, 2]"})
    assert (status, d["error"], d["side"]) == (400, "report", "after")
    old = json.loads(good)
    for f in old["findings"]:
        f.pop("fingerprint", None)
    status, d = diff_call(server, {"before_json": json.dumps(old), "after_json": good})
    assert (status, d["error"]) == (400, "report") and "fingerprint" in d["detail"]
    assert call(server, "POST", "/api/diff", b"{nope")[0] == 400


def test_scan_carries_the_fix_first_lead(server):
    status, raw = call(server, "POST", "/api/scan", json.dumps({"path": str(ROOT / "tests" / "fixtures" / "risky_repo"),
                                                                "goal_file": None}).encode())
    plain_layer = json.loads(raw)["plain"]
    assert status == 200 and plain_layer["fix_first_lead"].startswith("Safety problems do not raise the grade")


# ---- GET /api/files (P78 S3): every file the scan saw, taken at scan time ------------------------------------------

def files_call(server, scan, **kw):
    status, raw = call(server, "GET", "/api/files?id=%s" % scan, **kw)
    return status, json.loads(raw)


def test_files_lists_what_the_scan_saw_with_counts_derived_from_the_rows(server, tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "broken.py").write_text("def f(:\n", encoding="utf-8")
    (tmp_path / "app.js").write_text("let a = 1;\n", encoding="utf-8")
    (tmp_path / "blob.bin").write_bytes(b"\0\1")
    (tmp_path / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
    (tmp_path / "ignored.txt").write_text("x\n", encoding="utf-8")
    status, body = files_call(server, scan_id(server, tmp_path))
    assert status == 200
    assert [r["rel"] for r in body["files"]] == [".gitignore", "a.py", "app.js", "blob.bin", "broken.py"]
    assert body["counts"] == ui.plain.file_counts(body["files"])
    assert (body["ignored"], body["excluded"]) == (1, 0)
    assert {r["rel"]: r["risk"] for r in body["files"]} == {
        ".gitignore": "Partly checked", "a.py": "No known risks found", "app.js": "Partly checked",
        "blob.bin": "Not read", "broken.py": "Partly checked"}


def test_files_needs_the_token_and_only_answers_get(server, tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    sid = scan_id(server, tmp_path)
    assert files_call(server, sid, token=False) == (403, {"error": "token"})
    status, raw = call(server, "POST", "/api/files?id=%s" % sid)
    assert (status, json.loads(raw)) == (404, {"error": "route"})
    assert files_call(server, "") == (404, {"error": "scan"})
    assert call(server, "GET", "/api/files")[0] == 404


def test_files_honours_the_goal_files_excludes_the_way_the_scan_does(server, tmp_path):
    (tmp_path / "gen").mkdir()
    (tmp_path / "main.py").write_text("def main():\n    return 1\n", encoding="utf-8")
    (tmp_path / "gen" / "made.py").write_text("X = 1\n", encoding="utf-8")
    (tmp_path / ui.goal.FILENAME).write_text(ui.goal.render("demo", ["main.py"], exclude=["gen/*"]), encoding="utf-8")
    status, body = files_call(server, scan_id(server, tmp_path))
    assert status == 200 and body["excluded"] >= 1
    assert [r["rel"] for r in body["files"] if r["rel"].startswith("gen/")] == []
    assert "main.py" in [r["rel"] for r in body["files"]]


def test_files_uses_the_goal_file_named_in_the_request(server, tmp_path):
    (tmp_path / "keep.py").write_text("X = 1\n", encoding="utf-8")
    (tmp_path / "skip.py").write_text("X = 2\n", encoding="utf-8")
    elsewhere = tmp_path.parent / (tmp_path.name + "-goal.toml")
    elsewhere.write_text(ui.goal.render("demo", ["keep.py"], exclude=["skip.py"]), encoding="utf-8")
    raw = json.dumps({"path": str(tmp_path), "goal_file": str(elsewhere)}).encode()
    status, scanned = call(server, "POST", "/api/scan", raw)
    assert status == 200
    status, body = files_call(server, json.loads(scanned)["id"])
    assert [r["rel"] for r in body["files"]] == ["keep.py"] and body["excluded"] == 1


def test_files_for_one_file_scanned_as_a_copy(server, tmp_path):
    one = tmp_path / "only.py"
    one.write_text("x = 1\n", encoding="utf-8")
    status, body = files_call(server, scan_id(server, one))
    assert status == 200 and [r["rel"] for r in body["files"]] == ["only.py"]


def test_files_are_kept_and_dropped_with_the_reports(server, monkeypatch):
    monkeypatch.setattr(ui, "REPORTS_KEPT", 2)
    ids = [scan_id(server, CLEAN) for _ in range(3)]
    assert files_call(server, ids[0]) == (404, {"error": "scan"})
    assert files_call(server, ids[1])[0] == files_call(server, ids[2])[0] == 200
    assert sorted(server.inventories) == sorted(ids[1:])


def test_a_check_without_an_inventory_is_404_not_a_crash(server):
    sid = scan_id(server, CLEAN)
    server.inventories.clear()
    assert files_call(server, sid) == (404, {"error": "scan"})


def test_a_walk_that_crashes_leaves_the_scan_working_and_the_list_absent(server, monkeypatch):
    real = ui.walk.walk
    calls = []

    def flaky(root, exclude=()):
        calls.append(root)
        if len(calls) == 1:  # the one taken for the file list; the scan's own walk is a later call
            raise OSError("boom")
        return real(root, exclude=exclude)

    monkeypatch.setattr(ui.walk, "walk", flaky)
    sid = scan_id(server, CLEAN)
    assert files_call(server, sid) == (404, {"error": "scan"})
    assert len(calls) >= 1


def test_the_inventory_is_walked_before_the_scan_and_never_changes_the_report(server, monkeypatch):
    order = []
    real_walk, real_scan = ui.walk.walk, ui.report.scan
    monkeypatch.setattr(ui.walk, "walk", lambda *a, **k: order.append("walk") or real_walk(*a, **k))
    monkeypatch.setattr(ui.report, "scan", lambda *a, **k: order.append("scan") or real_scan(*a, **k))
    sid = scan_id(server, CLEAN)
    assert order[:2] == ["walk", "scan"]
    assert server.report_of(sid) == ui.redact_report(real_scan(str(CLEAN)))
