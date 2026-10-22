"""The local server behind `code-guardian ui`: the scanner and the plain-language layer over HTTP, for one person's browser.

Standard library only. The only socket is the loopback listener (127.0.0.1, never all interfaces). Every request
passes the Host / Origin guard first and, for /api/*, the per-process token, so a page on another site cannot reach it.
The server calls report.scan() and builds every sentence with plain.py; it never changes a number.

    make_server(port=0) -> server bound to 127.0.0.1, not yet serving, with .token; server_close() also removes every
                           per-scan temp directory
    run(path, port, open_browser) -> exit code        # the `code-guardian ui` command (C1)

    python -m code_guardian.ui --selftest
"""

import atexit
import codecs
import http.client
import http.server
import json
import os
import secrets
import shutil
import socketserver
import sys
import tempfile
import threading
import time
import webbrowser
from urllib.parse import parse_qsl

from . import goal, plain, report
from .finding import summarize
from .scanners import redact_report

HOST = "127.0.0.1"
SCHEME = "http"
CSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'"
FILE_LIMIT = 2 * 1024 * 1024
BODY_LIMIT = 1024 * 1024
UI_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui")
ASSETS = {"/": ("index.html", "text/html; charset=utf-8"), "/app.css": ("app.css", "text/css; charset=utf-8"),
          "/app.js": ("app.js", "text/javascript; charset=utf-8")}
DIMENSIONS = ("safe", "works", "complete", "overall")

_live = set()
_live_lock = threading.Lock()


class ScanRefused(report.UsageError):
    """The request cannot be scanned: error is the C7 error word ("path", "goal"), detail says why."""

    def __init__(self, error, detail):
        super().__init__(detail)
        self.error = error
        self.detail = detail


def _unquote(text):
    """Windows "Copy as path" wraps the path in double quotes; a shell may leave single quotes."""
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        text = text[1:-1].strip()
    return text


def _cleanup_all():
    with _live_lock:
        servers = list(_live)
    for server in servers:
        server.remove_temp_dirs()


atexit.register(_cleanup_all)


class Server(http.server.ThreadingHTTPServer):
    allow_reuse_address = False  # on Windows SO_REUSEADDR would let another process share a fixed --port
    def __init__(self, port=0):
        self.token = secrets.token_urlsafe(24)
        self.scans = []  # entries, oldest first: id, path, when, state, grade, overall, status
        self.roots = {}  # scan id -> the directory /api/file may read under
        self.temp_dirs = []
        self.lock = threading.Lock()
        super().__init__((HOST, port), Handler)
        with _live_lock:
            _live.add(self)

    def server_bind(self):
        socketserver.TCPServer.server_bind(self)  # not HTTPServer's: it asks DNS for the host's name
        self.server_name = HOST
        self.server_port = self.server_address[1]

    def server_close(self):
        super().server_close()
        self.remove_temp_dirs()
        with _live_lock:
            _live.discard(self)

    def remove_temp_dirs(self):
        with self.lock:
            dirs, self.temp_dirs = self.temp_dirs, []
        for d in dirs:
            shutil.rmtree(d, ignore_errors=True)

    def allowed_hosts(self):
        port = self.server_address[1]
        return {"%s:%d" % (name, port) for name in ("127.0.0.1", "localhost")}

    def allowed_origins(self):
        return {SCHEME + "://" + h for h in self.allowed_hosts()}

    def scan(self, path, goal_file=None):
        """Scan a directory, or a copy of a single file, and return {"id", "report", "plain"}."""
        target = os.path.abspath(os.path.expanduser(_unquote(path)))
        made = None
        if os.path.isfile(target):
            made = tempfile.mkdtemp(prefix="cg-ui-")
            with self.lock:
                self.temp_dirs.append(made)
            shutil.copy2(target, made)
            root = made
        elif os.path.isdir(target):
            root = target
        else:
            raise ScanRefused("path", "not an existing directory or file: %s" % path)
        entry = {"id": secrets.token_hex(6), "path": target, "when": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                 "state": "scanning", "grade": None, "overall": None, "status": None}
        with self.lock:
            self.scans.append(entry)
        try:
            rep = redact_report(report.scan(root, _unquote(goal_file) if goal_file else None))
        except (report.UsageError, goal.GoalError) as exc:
            self._forget(entry, made)
            raise ScanRefused("goal", str(exc)) from None
        except BaseException:
            self._forget(entry, made)
            raise
        with self.lock:
            self.roots[entry["id"]] = os.path.realpath(root)
            entry.update(state="done", grade=rep["scores"]["grade"], overall=rep["scores"]["overall"],
                         status=rep["status"])
        return {"id": entry["id"], "report": rep, "plain": plain_of(rep)}

    def _forget(self, entry, made):
        with self.lock:
            self.scans.remove(entry)
            if made in self.temp_dirs:
                self.temp_dirs.remove(made)
        if made:
            shutil.rmtree(made, ignore_errors=True)

    def listing(self):
        with self.lock:
            return [dict(e) for e in self.scans]

    def read_file(self, scan_id, rel):
        """(status, body) for /api/file: rel under the scan's root, after realpath, or refused."""
        with self.lock:
            root = self.roots.get(scan_id)
        if root is None:
            return 404, {"error": "scan"}
        target = os.path.realpath(os.path.join(root, rel))
        try:
            inside = os.path.commonpath([root, target]) == root
        except ValueError:  # a different drive on Windows
            inside = False
        if not inside:
            return 403, {"error": "outside"}
        if not os.path.isfile(target):
            return 404, {"error": "file"}
        try:
            with open(target, "rb") as fh:
                data = fh.read(FILE_LIMIT + 1)
        except OSError:
            return 404, {"error": "file"}
        if b"\0" in data[:8192]:
            return 415, {"error": "binary"}
        truncated = len(data) > FILE_LIMIT
        text = codecs.getincrementaldecoder("utf-8")("replace").decode(data[:FILE_LIMIT], final=not truncated)
        lines = [line.rstrip("\r") for line in text.split("\n")]
        if lines and lines[-1] == "":
            lines.pop()
        return 200, {"rel": rel, "lines": lines, "truncated": truncated}


def plain_of(rep):
    return {"harm": plain.harm(rep),
            "sentences": {d: plain.score_sentence(d, rep) for d in DIMENSIONS},
            "checked": plain.checked_lines(rep),
            "cards": [plain.finding_card(f, rep) for f in rep["findings"]],
            "fix_first": plain.fix_first(rep),
            "fix_first_notes": plain.fix_first_notes(rep)}


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "code-guardian-ui"
    sys_version = ""

    def log_message(self, format, *args):  # noqa: A002 - the base class's name
        del format, args  # no request log: stdout carries the one URL line and nothing else

    def _send(self, status, body, content_type):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status, obj):
        self._send(status, json.dumps(obj).encode("utf-8"), "application/json; charset=utf-8")

    def _body(self):
        """The request body, always drained so the client never sees a reset; None when it is too large or malformed."""
        raw = self.headers.get("Content-Length")
        if raw is None:
            return b""
        if not raw.isdigit() or int(raw) > BODY_LIMIT:
            return None
        return self.rfile.read(int(raw))

    def _guard(self):
        """The Host / Origin guard, then the token for /api/*: the error word to refuse with, or None."""
        server = self.server
        if self.headers.get("Host") not in server.allowed_hosts():
            return "origin"
        origin = self.headers.get("Origin")
        if origin is not None and origin not in server.allowed_origins():
            return "origin"
        if self.path.partition("?")[0].startswith("/api/"):
            given = (self.headers.get("X-CG-Token") or "").encode("utf-8")
            if not secrets.compare_digest(given, server.token.encode("utf-8")):
                return "token"
        return None

    def _handle(self):
        body = self._body()
        refused = self._guard()
        if refused:
            return self._json(403, {"error": refused})
        if body is None:
            return self._json(413, {"error": "body"})
        path, _, query = self.path.partition("?")
        if self.command in ("GET", "HEAD") and path in ASSETS:
            name, kind = ASSETS[path]
            try:
                with open(os.path.join(UI_DIR, name), "rb") as fh:
                    return self._send(200, fh.read(), kind)
            except OSError:
                return self._json(404, {"error": "route"})
        if self.command == "POST" and path == "/api/scan":
            return self._scan(body)
        if self.command == "GET" and path == "/api/scans":
            return self._json(200, self.server.listing())
        if self.command == "GET" and path == "/api/file":
            params = dict(parse_qsl(query, keep_blank_values=True))
            status, out = self.server.read_file(params.get("id", ""), params.get("rel", ""))
            return self._json(status, out)
        return self._json(404, {"error": "route"})

    def _scan(self, body):
        try:
            req = json.loads(body.decode("utf-8"))
        except ValueError:
            return self._json(400, {"error": "json"})
        if not isinstance(req, dict):
            return self._json(400, {"error": "json"})
        path, goal_file = req.get("path"), req.get("goal_file")
        if not isinstance(path, str) or not path.strip():
            return self._json(400, {"error": "path", "detail": "path must be a non-empty string"})
        if goal_file is not None and not isinstance(goal_file, str):
            return self._json(400, {"error": "goal", "detail": "goal_file must be a string or null"})
        try:
            return self._json(200, self.server.scan(path, goal_file))
        except ScanRefused as exc:
            return self._json(400, {"error": exc.error, "detail": exc.detail})
        except Exception as exc:  # the scanner crashed: say so, never the traceback
            return self._json(500, {"error": "scan", "detail": type(exc).__name__})

    do_GET = do_POST = do_HEAD = do_OPTIONS = do_PUT = do_DELETE = do_PATCH = _handle


def make_server(port=0):
    """The server, bound to 127.0.0.1 and not yet serving."""
    return Server(port)


def run(path=None, port=0, open_browser=True):
    """`code-guardian ui`: print the one URL line, then serve until Ctrl-C. Returns the exit code."""
    server = make_server(port)
    try:
        if path:
            try:
                server.scan(path)
            except ScanRefused as exc:
                sys.stderr.write("code-guardian: %s\n" % exc)
                return 2
        url = "%s://%s:%d/#t=%s" % (SCHEME, HOST, server.server_address[1], server.token)
        print("code-guardian ui: open " + url, flush=True)
        if open_browser:
            try:
                webbrowser.open(url)
            except Exception:  # no browser here: the printed link is enough
                pass
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
    finally:
        server.server_close()
    return 0


# ---------------------------------------------------------------------------------------------------------------
# selftest


def _call(server, method, path, body=None, headers=None):
    conn = http.client.HTTPConnection(HOST, server.server_address[1], timeout=60)
    head = {"Host": "%s:%d" % (HOST, server.server_address[1])}
    head.update(headers or {})
    data = None if body is None else json.dumps(body).encode("utf-8")
    conn.request(method, path, body=data, headers=head)
    resp = conn.getresponse()
    raw = resp.read()
    got = {k.lower(): v for k, v in resp.getheaders()}
    conn.close()
    try:
        js = json.loads(raw.decode("utf-8"))
    except ValueError:
        js = None
    return resp.status, got, js


def selftest():
    tmp = tempfile.mkdtemp(prefix="cg-ui-selftest-")
    server = make_server(0)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        proj = os.path.join(tmp, "proj")
        os.makedirs(proj)
        for name, text in (("a.py", "print(1)\n"), ("b.py", "print(2)\n")):
            with open(os.path.join(proj, name), "w", encoding="utf-8") as fh:
                fh.write(text)
        token = {"X-CG-Token": server.token}
        post = lambda p, **kw: _call(server, "POST", "/api/scan", {"path": p, "goal_file": None}, **kw)  # noqa: E731
        sid_status, _, scanned = post(proj, headers=token)
        sid = (scanned or {}).get("id", "")
        file_status, _, read = _call(server, "GET", "/api/file?id=%s&rel=a.py" % sid, headers=token)
        up_status, _, up = _call(server, "GET", "/api/file?id=%s&rel=../x" % sid, headers=token)
        abs_status, _, absolute = _call(server, "GET", "/api/file?id=%s&rel=%s" % (sid, os.path.join(tmp, "x")),
                                        headers=token)
        quoted_status, _, quoted = post('"%s"' % proj, headers=token)
        one_status, _, one = post(os.path.join(proj, "a.py"), headers=token)
        one_dir = (one or {}).get("report", {}).get("path", "")
        one_names = sorted(os.listdir(one_dir)) if os.path.isdir(one_dir) else None
        bad_status, _, bad = post(os.path.join(tmp, "missing"), headers=token)
        json_status, _, _ = _call(server, "POST", "/api/scan", headers=token)
        host_status, _, host = _call(server, "GET", "/api/scans", headers={**token, "Host": "evil.example"})
        origin_status, _, origin = _call(server, "GET", "/api/scans", headers={**token, "Origin": "http://evil.example"})
        tok_status, tok_headers, tok = _call(server, "GET", "/api/scans")
        route_status, _, route = _call(server, "GET", "/api/nope", headers=token)
        page_status, page_headers, _ = _call(server, "GET", "/")
        list_status, _, listed = _call(server, "GET", "/api/scans", headers=token)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(10)
        shutil.rmtree(tmp, ignore_errors=True)
    checks = [
        ("binds_loopback", server.server_address[0] == HOST),
        ("token_is_long", len(server.token) >= 16),
        ("wrong_host_403", (host_status, host) == (403, {"error": "origin"})),
        ("cross_origin_403", (origin_status, origin) == (403, {"error": "origin"})),
        ("no_token_403", (tok_status, tok) == (403, {"error": "token"})),
        ("security_headers", tok_headers.get("content-security-policy") == CSP
         and tok_headers.get("x-content-type-options") == "nosniff"
         and tok_headers.get("referrer-policy") == "no-referrer" and "no-store" in tok_headers.get("cache-control", "")),
        ("no_cors_headers", not [h for h in tok_headers if h.startswith("access-control-")]),
        ("unknown_route_404", (route_status, route) == (404, {"error": "route"})),
        ("page_served", page_status == 200 and page_headers.get("content-type", "").startswith("text/html")),
        ("scan_dir", sid_status == 200 and bool(sid) and set(scanned["plain"]) >= {"harm", "sentences", "checked",
                                                                                  "cards", "fix_first"}),
        ("scans_listed_done", list_status == 200 and len(listed) >= 3 and all(e["state"] == "done" for e in listed)),
        ("file_read", file_status == 200 and read["lines"] == ["print(1)"] and read["truncated"] is False),
        ("dotdot_refused", (up_status, up) == (403, {"error": "outside"})),
        ("absolute_refused", (abs_status, absolute) == (403, {"error": "outside"})),
        ("quoted_path", quoted_status == 200 and quoted["report"]["scores"] == scanned["report"]["scores"]),
        ("single_file_temp_copy", one_status == 200 and one_names == ["a.py"] and os.path.realpath(one_dir) != os.path.realpath(proj)),
        ("bad_path_400", bad_status == 400 and (bad or {}).get("error") == "path"),
        ("invalid_json_400", json_status == 400),
        ("temp_copy_removed_on_close", bool(one_dir) and not os.path.exists(one_dir)),
    ]
    return summarize("ui", checks)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if "--selftest" in argv:
        return selftest()
    sys.stderr.write("usage: python -m code_guardian.ui --selftest\n")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
