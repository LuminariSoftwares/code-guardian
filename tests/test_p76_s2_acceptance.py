"""P76 S2 acceptance -- the local server (code_guardian/ui.py) and the `ui` subcommand.

Written by the overseer from plan P76 contracts C1, C7 (every route except /api/explain and /api/diff, which belong
to S4 and S5) and C11 BEFORE the build session. The build session must add this file to the PR byte-for-byte and
must not edit it; a PR that changes it fails the section. CI runs it on ubuntu, windows and macos (the `pytest
(<os>, py3.11)` matrix); it must pass on windows-latest.

The in-process seam these tests use (the plan's contracts describe the CLI and the HTTP API; this is the smallest
Python surface needed to test them in a thread):
    ui.make_server(port=0) -> a http.server.ThreadingHTTPServer (or subclass) bound to 127.0.0.1, not yet serving,
        with attribute .token (the per-process token, str); serve_forever()/shutdown() as usual; server_close()
        also removes every per-scan temp directory it created.
    ui.py calls the scanner as `report.scan(...)` through the module (`from . import report`), so a test can
        monkeypatch code_guardian.report.scan.
"""
import http.client
import importlib
import json
import os
import queue
import re
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
from pathlib import Path

import pytest

from code_guardian import report

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
FIXTURES = HERE / "fixtures"
CSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'"
LINE = re.compile(r"^code-guardian ui: open http://127\.0\.0\.1:(\d+)/#t=(\S+)$")
AWS_ID = "AKIA" + "Q7XZ" * 4  # built at runtime: the package's self-scan reads literals


def ui():
    return importlib.import_module("code_guardian.ui")


class Running:
    def __init__(self):
        self.server = ui().make_server(port=0)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()

    @property
    def port(self):
        return self.server.server_address[1]

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(10)


@pytest.fixture
def srv():
    r = Running()
    yield r
    r.close()


def call(r, method, path, body=None, token=True, host=None, origin=None):
    c = http.client.HTTPConnection("127.0.0.1", r.port, timeout=60)
    c.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
    c.putheader("Host", host or "127.0.0.1:%d" % r.port)
    if token:
        c.putheader("X-CG-Token", r.server.token if token is True else token)
    if origin:
        c.putheader("Origin", origin)
    data = b"" if body is None else json.dumps(body).encode("utf-8")
    if body is not None:
        c.putheader("Content-Type", "application/json")
    c.putheader("Content-Length", str(len(data)))
    c.endheaders(data)
    resp = c.getresponse()
    raw = resp.read()
    headers = {k.lower(): v for k, v in resp.getheaders()}
    c.close()
    try:
        js = json.loads(raw.decode("utf-8"))
    except ValueError:
        js = None
    return resp.status, headers, js, raw


def scan(r, path):
    status, _, js, raw = call(r, "POST", "/api/scan", {"path": str(path), "goal_file": None})
    assert status == 200, raw[:500]
    return js


def file_url(scan_id, rel):
    return "/api/file?" + urllib.parse.urlencode({"id": scan_id, "rel": rel})


def _tree(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "a.py").write_text("print(1)\n", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "x").write_text("outside the root\n", encoding="utf-8")
    return root, outside


# ---- C1 / C7 guards ---------------------------------------------------------------------------------------------

def test_binds_loopback_with_a_token(srv):
    assert srv.server.server_address[0] == "127.0.0.1"
    assert isinstance(srv.server.token, str) and len(srv.server.token) >= 16


def test_wrong_host_is_403_origin(srv):
    status, _, js, _ = call(srv, "GET", "/api/scans", host="evil.example:%d" % srv.port)
    assert (status, js) == (403, {"error": "origin"})
    status, _, _, _ = call(srv, "GET", "/api/scans", host="localhost:%d" % srv.port)
    assert status == 200


def test_cross_origin_is_403_origin(srv):
    status, _, js, _ = call(srv, "GET", "/api/scans", origin="http://evil.example")
    assert (status, js) == (403, {"error": "origin"})
    status, _, js, _ = call(srv, "POST", "/api/scan", {"path": str(FIXTURES / "clean_repo"), "goal_file": None},
                            origin="http://evil.example")
    assert (status, js) == (403, {"error": "origin"})
    for ok in ("http://127.0.0.1:%d" % srv.port, "http://localhost:%d" % srv.port):
        status, _, _, _ = call(srv, "GET", "/api/scans", origin=ok)
        assert status == 200, ok


def test_missing_or_wrong_token_is_403_token(srv):
    assert call(srv, "GET", "/api/scans", token=False)[:3:2] == (403, {"error": "token"})
    assert call(srv, "GET", "/api/scans", token="not-the-token")[:3:2] == (403, {"error": "token"})
    status, _, js, _ = call(srv, "POST", "/api/scan", {"path": str(FIXTURES / "clean_repo"), "goal_file": None},
                            token=False)
    assert (status, js) == (403, {"error": "token"})


def test_unknown_route_is_404_route(srv):
    assert call(srv, "GET", "/api/nope")[:3:2] == (404, {"error": "route"})
    assert call(srv, "GET", "/nope")[:3:2] == (404, {"error": "route"})


def test_security_headers_and_no_cors(srv):
    responses = [call(srv, "GET", "/api/scans"), call(srv, "GET", "/api/scans", token=False),
                 call(srv, "OPTIONS", "/api/scan", origin="http://evil.example"), call(srv, "GET", "/")]
    for status, headers, _, _ in responses:
        assert headers.get("content-security-policy") == CSP, (status, headers)
        assert headers.get("x-content-type-options") == "nosniff"
        assert headers.get("referrer-policy") == "no-referrer"
        assert "no-store" in headers.get("cache-control", "")
        assert not [h for h in headers if h.startswith("access-control-")], headers
    status, headers, _, raw = responses[3]
    assert status == 200 and headers.get("content-type", "").startswith("text/html") and raw.strip()
    for asset, kind in (("/app.css", "text/css"), ("/app.js", "javascript")):
        status, headers, _, _ = call(srv, "GET", asset, token=False)
        assert status == 200 and kind in headers.get("content-type", ""), (asset, headers)


# ---- /api/scan ---------------------------------------------------------------------------------------------------

def test_good_scan_returns_report_and_plain(srv):
    js = scan(srv, FIXTURES / "risky_repo")
    assert set(js) >= {"id", "report", "plain"}
    assert set(js["plain"]) >= {"harm", "sentences", "checked", "cards", "fix_first"}
    assert set(js["plain"]["harm"]) >= {"level", "partial", "why", "counts"}
    assert js["plain"]["harm"]["level"] == "High"
    assert set(js["plain"]["sentences"]) >= {"safe", "works", "complete", "overall"}
    assert len(js["plain"]["cards"]) == len(js["report"]["findings"])
    assert js["report"]["scores"]["grade"] == report.scan(str(FIXTURES / "risky_repo"))["scores"]["grade"]


def test_bad_path_is_400_path(srv, tmp_path):
    status, _, js, _ = call(srv, "POST", "/api/scan", {"path": str(tmp_path / "missing"), "goal_file": None})
    assert status == 400 and js["error"] == "path"


def test_quoted_paths_scan_the_same(srv):
    p = str(FIXTURES / "clean_repo")
    reps = [scan(srv, q)["report"] for q in (p, '"%s"' % p, "'%s'" % p)]
    fps = [sorted(f["fingerprint"] for f in r["findings"]) for r in reps]
    assert reps[0]["scores"] == reps[1]["scores"] == reps[2]["scores"]
    assert fps[0] == fps[1] == fps[2]


def test_single_file_scans_a_temp_copy_never_the_parent(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "a.py").write_text("print(1)\n", encoding="utf-8")
    (proj / "b.py").write_text('KEY = "%s"\n' % AWS_ID, encoding="utf-8")
    assert "secret.key" in {f["code"] for f in report.scan(str(proj))["findings"]}, "fixture no longer detected"
    r = Running()
    scanned = None
    try:
        js = scan(r, proj / "a.py")
        codes = {f["code"] for f in js["report"]["findings"]}
        assert "secret.key" not in codes, codes
        scanned = Path(js["report"]["path"])
        assert scanned.resolve() != proj.resolve() and scanned.is_dir()
        assert sorted(os.listdir(scanned)) == ["a.py"]
        status, _, _, raw = call(r, "GET", file_url(js["id"], "b.py"))
        assert status in (403, 404) and AWS_ID.encode() not in raw
        status, _, got, _ = call(r, "GET", file_url(js["id"], "a.py"))
        assert status == 200 and got["lines"] == ["print(1)"]
    finally:
        r.close()
    assert scanned is not None and not scanned.exists(), "per-scan temp dir survived server_close()"


def test_slow_scan_shows_scanning_state(srv, monkeypatch):
    real = report.scan
    gate = threading.Event()

    def slow(*a, **k):
        gate.wait(30)
        return real(*a, **k)

    monkeypatch.setattr(report, "scan", slow)
    results = []
    t = threading.Thread(target=lambda: results.append(
        call(srv, "POST", "/api/scan", {"path": str(FIXTURES / "clean_repo"), "goal_file": None})))
    t.start()
    seen = False
    try:
        deadline = time.time() + 15
        while time.time() < deadline and not seen:
            status, _, js, _ = call(srv, "GET", "/api/scans")
            assert status == 200
            seen = any(e.get("state") == "scanning" for e in js)
            time.sleep(0.1)
    finally:
        gate.set()
        t.join(60)
    assert seen, "no scan reported state 'scanning' while the scanner was blocked"
    assert results and results[0][0] == 200
    status, _, js, _ = call(srv, "GET", "/api/scans")
    assert js and all(e["state"] == "done" for e in js)
    assert set(js[0]) >= {"id", "path", "when", "state", "grade", "overall", "status"}


# ---- /api/file ---------------------------------------------------------------------------------------------------

def test_file_reads_are_contained(srv, tmp_path):
    root, outside = _tree(tmp_path)
    sid = scan(srv, root)["id"]
    status, _, js, _ = call(srv, "GET", file_url(sid, "a.py"))
    assert status == 200 and js["lines"] == ["print(1)"] and js["truncated"] is False
    escapes = ["../outside/x", str(outside / "x")] + (["..\\outside\\x"] if os.name == "nt" else [])
    for rel in escapes:
        status, _, js, raw = call(srv, "GET", file_url(sid, rel))
        assert (status, js) == (403, {"error": "outside"}), (rel, raw[:200])


def test_symlink_out_of_root_is_refused(srv, tmp_path):
    root, outside = _tree(tmp_path)
    try:
        os.symlink(str(outside / "x"), str(root / "link"))
    except (OSError, NotImplementedError) as exc:  # Windows without symlink privilege; CI runners have it
        pytest.skip("cannot create a symlink here: %s" % exc)
    sid = scan(srv, root)["id"]
    status, _, js, _ = call(srv, "GET", file_url(sid, "link"))
    assert (status, js) == (403, {"error": "outside"})


def test_big_file_is_truncated_at_2mb(srv, tmp_path):
    root, _ = _tree(tmp_path)
    (root / "big.txt").write_text(("x" * 99 + "\n") * 30000, encoding="utf-8")  # 3,000,000 bytes
    sid = scan(srv, root)["id"]
    status, _, js, _ = call(srv, "GET", file_url(sid, "big.txt"))
    assert status == 200 and js["truncated"] is True
    assert len("\n".join(js["lines"]).encode("utf-8")) <= 2 * 1024 * 1024


# ---- C1 CLI ------------------------------------------------------------------------------------------------------

def _env():
    env = dict(os.environ)
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    return env


def test_cli_prints_one_line_prescans_a_quoted_path_and_serves():
    p = FIXTURES / "clean_repo"
    proc = subprocess.Popen([sys.executable, "-m", "code_guardian", "ui", "--no-browser", "--port", "0", '"%s"' % p],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=_env(), cwd=str(ROOT))
    lines = queue.Queue()
    reader = threading.Thread(target=lambda: [lines.put(x) for x in proc.stdout])
    reader.start()
    try:
        first = None
        deadline = time.time() + 120
        while first is None and time.time() < deadline:
            try:
                first = lines.get(timeout=1).rstrip("\n")
            except queue.Empty:
                if proc.poll() is not None:
                    break
        assert first is not None, "no line on stdout; exit %s; stderr: %s" % (proc.poll(), proc.stderr.read()[-800:]
                                                                               if proc.poll() is not None else "")
        m = LINE.match(first)
        assert m, first
        port, token = int(m.group(1)), m.group(2)
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
        c.request("GET", "/api/scans", headers={"X-CG-Token": token})
        resp = c.getresponse()
        scans = json.loads(resp.read().decode("utf-8"))
        assert resp.status == 200 and len(scans) == 1, scans
        assert scans[0]["state"] == "done" and scans[0]["grade"] == report.scan(str(p))["scores"]["grade"]
        time.sleep(0.5)
        extra = []
        while not lines.empty():
            extra.append(lines.get().strip())
        assert not [x for x in extra if x], "stdout must carry exactly one line: %r" % extra
    finally:
        proc.kill()
        proc.wait(30)
        reader.join(30)
        proc.stdout.close()
        proc.stderr.close()


def test_ui_help_exits_0_and_opens_nothing(monkeypatch, capsys):
    ui()
    from code_guardian import cli
    binds, opened = [], []
    real_bind = socket.socket.bind
    monkeypatch.setattr(socket.socket, "bind", lambda self, addr: binds.append(addr) or real_bind(self, addr))
    import webbrowser
    monkeypatch.setattr(webbrowser, "open", lambda *a, **k: opened.append(a))
    with pytest.raises(SystemExit) as exc:
        cli.main(["ui", "--help"])
    assert exc.value.code in (0, None)
    assert binds == [] and opened == []
    assert "--no-browser" in capsys.readouterr().out
    r = subprocess.run([sys.executable, "-m", "code_guardian", "--help"], capture_output=True, text=True,
                       env=_env(), cwd=str(ROOT), timeout=60)
    assert r.returncode == 0 and re.search(r"\bui\b", r.stdout), r.stdout


def test_ui_usage_error_exits_2():
    ui()
    r = subprocess.run([sys.executable, "-m", "code_guardian", "ui", "--port", "notaport"], capture_output=True,
                       text=True, env=_env(), cwd=str(ROOT), timeout=60)
    assert r.returncode == 2, r.stdout + r.stderr


def test_ui_selftest_count_line():
    ui()
    r = subprocess.run([sys.executable, "-m", "code_guardian", "ui", "--selftest"], capture_output=True, text=True,
                       env=_env(), cwd=str(ROOT), timeout=180)
    assert r.returncode == 0, r.stdout[-2000:] + r.stderr[-2000:]
    m = re.search(r"(\d+) checks, (\d+) passed", r.stdout)
    assert m and int(m.group(1)) == int(m.group(2)) >= 10, r.stdout[-500:]


def test_mcp_surface_unchanged():
    ui()
    code = "import sys; from code_guardian import mcp_server; sys.exit(mcp_server.main(['--port', '1']))"
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=_env(), cwd=str(ROOT),
                       timeout=60)
    assert r.returncode == 2, r.stdout + r.stderr


# ---- C11 package data --------------------------------------------------------------------------------------------

def test_package_data_lists_the_three_ui_files():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    for pat in ("ui/*.html", "ui/*.css", "ui/*.js"):
        assert pat in text, pat
    assert re.search(r"^dependencies = \[\]$", text, re.M)
    for name in ("index.html", "app.css", "app.js"):
        assert (ROOT / "code_guardian" / "ui" / name).is_file(), name
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "code_guardian/ui/index.html" in ci and "ui --selftest" in ci
