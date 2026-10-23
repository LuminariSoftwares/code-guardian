"""The local server behind `code-guardian ui`: the scanner and the plain-language layer over HTTP, for one person's browser.

Standard library only. The only socket is the loopback listener (127.0.0.1, never all interfaces). Every request
passes the Host / Origin guard first and, for /api/*, the per-process token, so a page on another site cannot reach it.
The server calls report.scan() and builds every sentence with plain.py; it never changes a number.
Only POST /api/scan reads a folder. GET /api/scan?id= hands back a stored result and POST /api/open stores a saved
`scan --json` (P78 C7); neither touches the disk.

    make_server(port=None) -> server bound to 127.0.0.1, not yet serving, with .token; server_close() also removes
                              every per-scan temp directory. None tries DEFAULT_PORTS in order, then any free port;
                              0 is any free port; any other number is that port or an OSError
    run(path, port, open_browser) -> exit code        # the `code-guardian ui` command (C1)

A folder refuse.refused() names (a drive, the home folder, Downloads, ...) is refused before anything reads it, by
POST /api/scan, by `code-guardian ui PATH` and for the folder Browse picks (P78 C5). POST /api/browse opens the
computer's own folder window in a child process (DIALOG_SOURCE, through Server.dialog_runner), one at a time (C6).

    python -m code_guardian.ui --selftest
"""

import atexit
import codecs
import collections
import errno
import http.client
import http.server
import json
import os
import secrets
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import webbrowser
from urllib.parse import parse_qsl

from . import explain, goal, plain, refuse, report, verify, walk
from .finding import summarize
from .scanners import redact_report

HOST = "127.0.0.1"
SCHEME = "http"
DEFAULT_PORTS = tuple(range(8765, 8776))  # a stable address, so the browser keeps its settings across restarts (ADR 0008)
CSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'"
FILE_LIMIT = 2 * 1024 * 1024
BODY_LIMIT = 1024 * 1024
UI_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui")
ASSETS = {"/": ("index.html", "text/html; charset=utf-8"), "/app.css": ("app.css", "text/css; charset=utf-8"),
          "/app.js": ("app.js", "text/javascript; charset=utf-8")}
DIMENSIONS = ("safe", "works", "complete", "overall")
EXPLAIN_MAX_LINES = 200
EXPLAIN_SETUP = "set CODE_GUARDIAN_LLM_URL and CODE_GUARDIAN_LLM_MODEL, then restart code-guardian ui"
REPORTS_KEPT = 20  # finished reports (and their file inventories) held for /api/diff and /api/files; the oldest goes first
DIALOG_TIMEOUT = 600  # seconds a folder window may stay open; no answer by then is a cancel
DIALOG_DETAIL = {3: "this Python has no tkinter", 4: "no display to open a window on"}

# The folder window, run as `python -I -c DIALOG_SOURCE START` (ADR 0009): tkinter wants the main thread of its own
# process, so the server's threads never import it. Exit 0 and the folder on stdout as UTF-8 whatever the console's
# code page is (browse() decodes UTF-8), 1 cancelled, 3 no tkinter, 4 no display.
DIALOG_SOURCE = """\
import sys
try:
    import tkinter
    import tkinter.filedialog
except ImportError:
    sys.exit(3)
try:
    root = tkinter.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    root.update()
except tkinter.TclError:
    sys.exit(4)
root.lift()
root.focus_force()
chosen = tkinter.filedialog.askdirectory(parent=root, initialdir=sys.argv[1], mustexist=True,
                                         title="Pick the folder to check")
chosen = chosen if isinstance(chosen, str) else ""
sys.stdout.reconfigure(encoding="utf-8")
print(chosen)
sys.exit(0 if chosen else 1)
"""

_live = set()
_live_lock = threading.Lock()
_dialog_lock = threading.Lock()  # one folder window at a time, across every server in this process


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
    # POSIX SO_REUSEADDR only lets a restart bind a port whose old connections are in TIME_WAIT; it never lets two
    # listeners share one. On Windows it would let another process take a fixed --port, so it stays off there.
    allow_reuse_address = os.name != "nt"
    dialog_runner = staticmethod(subprocess.run)  # replaced by a fake in the tests and --selftest

    def __init__(self, port=0):
        self.token = secrets.token_urlsafe(24)
        self.scans = []  # entries, oldest first: id, path, when, state, grade, overall, status (+ saved for POST /api/open)
        self.roots = {}  # scan id -> the directory /api/file may read under
        self.reports = collections.OrderedDict()  # scan id -> its (redacted) report, the last REPORTS_KEPT
        self.inventories = collections.OrderedDict()  # scan id -> the walk the scan saw, trimmed with reports
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
        sentence = refuse.refused(target)  # before anything is read or listed; a single file is never refused
        if sentence:
            raise ScanRefused("refused", sentence)
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
        goal_file = _unquote(goal_file) if goal_file else None
        try:
            # The files the scan will see: its own goal-file excludes, walked just before it walks (report.scan).
            contract, _ = report._contract(root, goal_file)
            try:
                inventory = walk.walk(root, exclude=contract["exclude"] if contract else ())
            except Exception:  # the scan reports a crashed walk itself; the file list is simply absent
                inventory = None
            rep = redact_report(report.scan(root, goal_file))
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
            self.reports[entry["id"]] = rep
            if inventory is not None:
                self.inventories[entry["id"]] = inventory
            self._trim()
        return {"id": entry["id"], "report": rep, "plain": plain_of(rep)}

    def _trim(self):
        """Keep the last REPORTS_KEPT reports; a report that goes takes its file inventory with it. Caller holds the lock."""
        while len(self.reports) > REPORTS_KEPT:
            gone, _ = self.reports.popitem(last=False)
            self.inventories.pop(gone, None)

    def stored(self, scan_id):
        """(status, body) for GET /api/scan: the result of a finished check held in memory, exactly what the POST that
        made it returned, plus its file list (None for a saved check, or one without an inventory). Reads no folder."""
        with self.lock:
            rep = self.reports.get(scan_id)
            saved = any(e["id"] == scan_id and e.get("saved") for e in self.scans)
        if rep is None:
            return 404, {"error": "scan"}
        status, files = (404, None) if saved else self.files_of(scan_id)
        return 200, {"id": scan_id, "report": rep, "plain": plain_of(rep), "files": files if status == 200 else None,
                     "saved": saved}

    def open_saved(self, rep):
        """Hold a report read from a saved `scan --json` file (already validated and redacted) as a finished check with
        no folder behind it: no root, no inventory. Returns {"id", "report", "plain", "files", "saved"}."""
        entry = {"id": secrets.token_hex(6), "path": rep["path"], "when": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                 "state": "done", "grade": rep["scores"].get("grade"), "overall": rep["scores"].get("overall"),
                 "status": rep.get("status"), "saved": True}
        out = {"id": entry["id"], "report": rep, "plain": plain_of(rep), "files": None, "saved": True}
        with self.lock:
            self.scans.append(entry)
            self.reports[entry["id"]] = rep
            self._trim()
        return out

    def browse(self, start):
        """(status, body) for /api/browse (C6): open the folder window in a child process and wait for its answer."""
        if not _dialog_lock.acquire(blocking=False):
            return 409, {"error": "busy"}
        try:
            try:
                done = self.dialog_runner([sys.executable, "-I", "-c", DIALOG_SOURCE, start or os.path.expanduser("~")],
                                          capture_output=True, text=True, encoding="utf-8",
                                          timeout=DIALOG_TIMEOUT)
            except subprocess.TimeoutExpired:
                return 200, {"path": None, "cancelled": True}
        finally:
            _dialog_lock.release()
        chosen = (done.stdout or "").rstrip("\r\n")
        if done.returncode == 1 or (done.returncode == 0 and not chosen):
            return 200, {"path": None, "cancelled": True}
        if done.returncode != 0:
            detail = DIALOG_DETAIL.get(done.returncode, "the folder window could not open (exit %s)" % done.returncode)
            return 501, {"error": "no_dialog", "detail": detail}
        path = os.path.abspath(chosen)
        return 200, {"path": path, "refused": refuse.refused(path)}

    def _forget(self, entry, made):
        with self.lock:
            self.scans.remove(entry)
            if made in self.temp_dirs:
                self.temp_dirs.remove(made)
        if made:
            shutil.rmtree(made, ignore_errors=True)

    def report_of(self, scan_id):
        with self.lock:
            return self.reports.get(scan_id)

    def files_of(self, scan_id):
        """(status, body) for /api/files: one row per file the scan saw (plain.file_rows), or 404 for a check this
        server does not hold or one saved without its file list."""
        with self.lock:
            rep, inventory = self.reports.get(scan_id), self.inventories.get(scan_id)
        if rep is None or inventory is None:
            return 404, {"error": "scan"}
        rows = plain.file_rows(rep, inventory)
        return 200, {"files": rows, "counts": plain.file_counts(rows), "ignored": inventory["ignored"],
                     "excluded": inventory["excluded"]}

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
            "fix_first_notes": plain.fix_first_notes(rep),
            "fix_first_lead": plain.fix_first_lead(rep)}


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
        if self.command == "POST" and path == "/api/browse":
            return self._browse(body)
        if self.command == "POST" and path == "/api/open":
            return self._open(body)
        if self.command == "GET" and path == "/api/scan":
            status, out = self.server.stored(dict(parse_qsl(query, keep_blank_values=True)).get("id", ""))
            return self._json(status, out)
        if self.command == "POST" and path == "/api/explain":
            return self._explain(body)
        if self.command == "POST" and path == "/api/diff":
            return self._diff(body)
        if self.command == "GET" and path == "/api/scans":
            return self._json(200, self.server.listing())
        if self.command == "GET" and path == "/api/files":
            status, out = self.server.files_of(dict(parse_qsl(query, keep_blank_values=True)).get("id", ""))
            return self._json(status, out)
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

    def _open(self, body):
        """The text of a saved `scan --json` file, held as a finished check with no folder behind it. Parsed with the
        validator /api/diff uses for before_json; nothing is read from the disk and report.scan is never called."""
        try:
            req = json.loads(body.decode("utf-8"))
        except ValueError:
            return self._json(400, {"error": "json", "detail": "the request is not JSON"})
        text = req.get("json") if isinstance(req, dict) else None
        if not isinstance(text, str):
            return self._json(400, {"error": "json", "detail": "give json: the text of a file saved with scan --json"})
        try:
            data = json.loads(text)
            if not isinstance(data, dict):  # load_report would take a bare string for a file path
                raise ValueError("not a code-guardian scan report (from scan --json)")
            rep = redact_report(verify.load_report(data))
            if not isinstance(rep.get("path"), str):
                raise ValueError("not a code-guardian scan report (from scan --json)")
            return self._json(200, self.server.open_saved(rep))
        except (ValueError, RecursionError) as exc:
            detail = "not JSON" if isinstance(exc, (json.JSONDecodeError, RecursionError)) else str(exc)
        except (KeyError, TypeError, AttributeError, IndexError):  # not the shape scan --json writes
            detail = "not a code-guardian scan report (from scan --json)"
        return self._json(400, {"error": "json", "detail": detail})

    def _browse(self, body):
        try:
            req = json.loads(body.decode("utf-8"))
        except ValueError:
            return self._json(400, {"error": "json"})
        if not isinstance(req, dict):
            return self._json(400, {"error": "json"})
        start = req.get("start")
        if start is not None and not isinstance(start, str):
            return self._json(400, {"error": "start", "detail": "start must be a string or null"})
        try:
            status, out = self.server.browse(start)
        except Exception as exc:  # the window's process could not start: say so, never the traceback
            return self._json(500, {"error": "browse", "detail": type(exc).__name__})
        return self._json(status, out)

    def _diff(self, body):
        """Two checks of this session by id, or the text of two saved `scan --json` files: verify.diff's result as it
        is, plus plain.diff_sentence of it. A saved file is parsed here and never treated as a path."""
        try:
            req = json.loads(body.decode("utf-8"))
        except ValueError:
            return self._json(400, {"error": "json"})
        if not isinstance(req, dict):
            return self._json(400, {"error": "json"})
        if isinstance(req.get("before"), str) and isinstance(req.get("after"), str):
            pair = [self.server.report_of(req["before"]), self.server.report_of(req["after"])]
            if None in pair:
                return self._json(404, {"error": "scan", "detail": "code-guardian does not hold that check; it keeps "
                                        "the last %d" % REPORTS_KEPT})
        elif isinstance(req.get("before_json"), str) and isinstance(req.get("after_json"), str):
            pair = []
            for side in ("before_json", "after_json"):
                try:
                    data = json.loads(req[side])
                    if not isinstance(data, dict):  # load_report would take a bare string for a file path
                        raise ValueError("not a code-guardian scan report (from scan --json)")
                    pair.append(redact_report(verify.load_report(data)))
                except (ValueError, RecursionError) as exc:
                    detail = "not JSON" if isinstance(exc, (json.JSONDecodeError, RecursionError)) else str(exc)
                    return self._json(400, {"error": "report", "side": side[:-5], "detail": detail})
        else:
            return self._json(400, {"error": "diff", "detail": "give before and after (two check ids) or before_json "
                                    "and after_json (two saved scan --json files)"})
        try:
            d = verify.diff(pair[0], pair[1])
        except ValueError as exc:  # a report without fingerprints, from a version older than 0.3
            return self._json(400, {"error": "report", "detail": str(exc)})
        except (KeyError, TypeError, AttributeError):  # a report whose findings are not the shape scan --json writes
            return self._json(400, {"error": "report", "detail": "not a code-guardian scan report (from scan --json)"})
        d["sentence"] = plain.diff_sentence(d)
        return self._json(200, d)

    def _explain(self, body):
        """Ask the person's own model about the lines they chose: those lines and nothing else leave this machine.
        With "dry_run": true it only says where they would go."""
        try:
            req = json.loads(body.decode("utf-8"))
        except ValueError:
            return self._json(400, {"error": "json"})
        if not isinstance(req, dict):
            return self._json(400, {"error": "json"})
        scan_id, rel, start, end = (req.get(k) for k in ("id", "rel", "start", "end"))
        if not isinstance(scan_id, str) or not isinstance(rel, str):
            return self._json(400, {"error": "json"})
        if any(isinstance(n, bool) or not isinstance(n, int) for n in (start, end)):
            return self._json(400, {"error": "range", "detail": "start and end must be whole line numbers"})
        if start < 1 or end < start or end - start + 1 > EXPLAIN_MAX_LINES:
            return self._json(400, {"error": "range", "detail": "pick between 1 and %d lines, starting at line 1 "
                                    "or later" % EXPLAIN_MAX_LINES})
        status, out = self.server.read_file(scan_id, rel)
        if status != 200:
            return self._json(status, out)
        if end > len(out["lines"]):
            return self._json(400, {"error": "range", "detail": "%s has %d lines" % (rel, len(out["lines"]))})
        url = (os.environ.get("CODE_GUARDIAN_LLM_URL") or "").strip()
        model = (os.environ.get("CODE_GUARDIAN_LLM_MODEL") or "").strip()
        if not url or not model:
            return self._json(200, {"text": None, "note": EXPLAIN_SETUP, "sent": None})
        try:
            sent = {"host": explain.hostport(explain.endpoint(url)[1]), "model": model, "lines": end - start + 1}
        except ValueError as exc:  # the URL is refused, so nothing can be sent
            return self._json(200, {"text": None, "note": "explain skipped: %s" % exc, "sent": None})
        if req.get("dry_run") is True:  # the page asks where the lines would go before it sends them
            return self._json(200, {"text": None, "note": None, "sent": sent})
        text, note = explain.excerpt(rel, out["lines"], start, end)
        return self._json(200, {"text": text, "note": note, "sent": sent})

    do_GET = do_POST = do_HEAD = do_OPTIONS = do_PUT = do_DELETE = do_PATCH = _handle


def make_server(port=None):
    """The server, bound to 127.0.0.1 and not yet serving. port=None tries DEFAULT_PORTS in order and falls back to
    any free port; port=0 is any free port; any other number is that port, or an OSError when it is taken."""
    if port is not None:
        return Server(port)
    for candidate in DEFAULT_PORTS:
        try:
            return Server(candidate)
        except OSError:  # taken, or reserved by the OS: try the next
            continue
    return Server(0)


def run(path=None, port=None, open_browser=True):
    """`code-guardian ui`: print the one URL line, then serve until Ctrl-C. Returns the exit code."""
    if path:
        sentence = refuse.refused(os.path.abspath(os.path.expanduser(_unquote(path))))
        if sentence:  # before any socket is opened
            sys.stderr.write("code-guardian: %s\n" % sentence)
            return 2
    try:
        server = make_server(port)
    except OSError as exc:  # a --port that is taken, or one this system will not hand out
        why = "is in use" if exc.errno in (errno.EADDRINUSE, getattr(errno, "WSAEADDRINUSE", None)) else \
            "cannot be used here (%s)" % (exc.strerror or type(exc).__name__)
        sys.stderr.write("code-guardian: port %s %s; pick another or leave out --port\n" % (port, why))
        return 2
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


class _Done:
    """What a fake dialog runner returns: the fields of subprocess.CompletedProcess that browse() reads."""

    def __init__(self, returncode, stdout=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, ""


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
        files_status, _, filed = _call(server, "GET", "/api/files?id=%s" % sid, headers=token)
        nofiles_status, _, nofiles = _call(server, "GET", "/api/files?id=gone", headers=token)
        quoted_status, _, quoted = post('"%s"' % proj, headers=token)
        one_status, _, one = post(os.path.join(proj, "a.py"), headers=token)
        diff_status, _, diffed = _call(server, "POST", "/api/diff", {"before": sid, "after": (quoted or {}).get("id")},
                                       headers=token)
        gone_status, _, _ = _call(server, "POST", "/api/diff", {"before": sid, "after": "gone"}, headers=token)
        text_status, _, _ = _call(server, "POST", "/api/diff", {"before_json": "{", "after_json": "{}"}, headers=token)
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
        home_status, _, home = post(os.path.expanduser("~"), headers=token)
        again_status, _, again = _call(server, "GET", "/api/scan?id=%s" % sid, headers=token)
        open_status, _, opened = _call(server, "POST", "/api/open", {"json": json.dumps((scanned or {}).get("report"))},
                                       headers=token)
        oid = (opened or {}).get("id", "")
        saved_file = _call(server, "GET", "/api/file?id=%s&rel=a.py" % oid, headers=token)[::2]
        saved_files = _call(server, "GET", "/api/files?id=%s" % oid, headers=token)[::2]
        browse = lambda: _call(server, "POST", "/api/browse", {"start": None}, headers=token)  # noqa: E731
        # Fake runners only: the real one would open a window, and --selftest never starts a process.
        server.dialog_runner = lambda args, **kw: _Done(3)
        nodialog_status, _, nodialog = browse()
        entered, release, first = threading.Event(), threading.Event(), {}

        def slow(args, **kw):
            entered.set()
            release.wait(30)
            return _Done(1)
        server.dialog_runner = slow
        holder = threading.Thread(target=lambda: first.setdefault("r", browse()))
        holder.start()
        try:
            busy_status, _, busy = browse() if entered.wait(30) else (None, None, None)
        finally:
            release.set()
            holder.join(30)
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
        ("files_listed", files_status == 200 and [r["rel"] for r in filed["files"]] == ["a.py", "b.py"]
         and filed["counts"] == plain.file_counts(filed["files"]) and filed["counts"]["all"] == 2),
        ("files_unknown_404", (nofiles_status, nofiles) == (404, {"error": "scan"})),
        ("dotdot_refused", (up_status, up) == (403, {"error": "outside"})),
        ("absolute_refused", (abs_status, absolute) == (403, {"error": "outside"})),
        ("quoted_path", quoted_status == 200 and quoted["report"]["scores"] == scanned["report"]["scores"]),
        ("single_file_temp_copy", one_status == 200 and one_names == ["a.py"] and os.path.realpath(one_dir) != os.path.realpath(proj)),
        ("bad_path_400", bad_status == 400 and (bad or {}).get("error") == "path"),
        ("diff_two_scans", diff_status == 200 and (diffed or {}).get("counts", {}).get("fixed") == 0
         and diffed["sentence"] == plain.diff_sentence({k: v for k, v in diffed.items() if k != "sentence"})),
        ("diff_unknown_404_bad_text_400", (gone_status, text_status) == (404, 400)),
        ("invalid_json_400", json_status == 400),
        ("temp_copy_removed_on_close", bool(one_dir) and not os.path.exists(one_dir)),
        ("refused_home_400", (home_status, home) == (400, {"error": "refused",
                                                          "detail": refuse.refused(os.path.expanduser("~"))})),
        ("reopen_get_equal", again_status == 200 and again["report"] == scanned["report"]
         and again["plain"] == scanned["plain"] and again["saved"] is False and again["files"] == filed),
        ("open_saved_no_root", open_status == 200 and opened["saved"] is True and opened["files"] is None
         and opened["report"] == scanned["report"] and saved_file == (404, {"error": "scan"})
         and saved_files == (404, {"error": "scan"})),
        ("browse_no_dialog_501", (nodialog_status, nodialog) == (501, {"error": "no_dialog",
                                                                      "detail": DIALOG_DETAIL[3]})),
        ("browse_busy_409", (busy_status, busy) == (409, {"error": "busy"})
         and first.get("r", (None,))[0] == 200 and first["r"][2] == {"path": None, "cancelled": True}),
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
