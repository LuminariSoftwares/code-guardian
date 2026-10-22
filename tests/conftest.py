"""Shared test helpers: the fixture repos are test input (never collected) and a tiny loopback HTTP stub for the
--explain and --online tests, copied from stack-guardian's conftest."""
import http.server
import json
import sys
import threading
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
FIXTURES = HERE / "fixtures"
sys.path.insert(0, str(HERE))

# The fixture repos contain their own test_*.py files; they are scan input, not tests of this project.
collect_ignore_glob = ["fixtures/*"]

# Like the key shapes, URLs to placeholder addresses are test data: built at runtime so the self-scan (which reads
# literals) inventories this project's own egress, not its test inputs.
HTTP = "http" + "://"


def tailnet(n):
    """The documented placeholder address 100.64.0.n (n in 1..20)."""
    return ".".join(["100", "64", "0", str(n)])


class Stub:
    """routes: {(method, path): (status, body, delay_s)}; body is a dict/list (sent as JSON) or a str.

    A test for a client-side timeout (supply's PyPI timeout, explain's model timeout) hands a route a delay longer
    than the client's timeout, so the client gives up and closes the socket while a handler thread is still in that
    delay. Two things follow, and both have to be handled here or the whole pytest process can die at exit with
    `Fatal Python error: _enter_buffered_busy ... at interpreter shutdown, possibly due to daemon threads`:

    * the handler eventually writes to a socket nobody is reading, which socketserver reports by printing a
      traceback to stderr from that thread -- so handle_error() records a connection error instead of printing it,
      and anything else is kept for the stub fixture to fail the test with;
    * the thread must not outlive the test. The delay waits on an Event that close() sets, and the handler threads
      are not daemons and are joined by server_close(), so no thread of this stub's is alive afterwards.
    """

    def __init__(self, routes):
        self.routes = dict(routes)
        self.requests = []  # (method, path, parsed JSON body or None)
        self.errors = []  # handler exceptions that are not a client hanging up; the fixture asserts this is empty
        self._closing = threading.Event()
        self._closed = False
        stub = self

        class Handler(http.server.BaseHTTPRequestHandler):
            timeout = 10  # a client that connects and says nothing cannot wedge a handler thread

            def _serve(self, method):
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                stub.requests.append((method, self.path, json.loads(raw) if raw else None))
                status, body, delay = stub.routes.get((method, self.path), (404, {"error": "not found"}, 0))
                data = (body if isinstance(body, str) else json.dumps(body)).encode("utf-8")
                if delay and not stub._closing.wait(delay):  # interruptible: close() ends the wait at once
                    return
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):  # noqa: N802
                self._serve("GET")

            def do_POST(self):  # noqa: N802
                self._serve("POST")

            def log_message(self, *args):
                pass

        class Server(http.server.ThreadingHTTPServer):
            daemon_threads = False  # with block_on_close, server_close() joins every handler thread
            block_on_close = True

            def handle_error(self, request, client_address):
                exc = sys.exc_info()[1]
                if isinstance(exc, (ConnectionError, TimeoutError)):
                    return  # the client gave up on a slow reply: that is what its test is checking
                stub.errors.append(exc)  # never printed: a thread writing to stderr at exit aborts the process

        self.server = Server(("127.0.0.1", 0), Handler)
        self.url = "http://127.0.0.1:%d" % self.server.server_port
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()

    def paths(self, method=None):
        return [p for m, p, _ in self.requests if method is None or m == method]

    def close(self):
        """Idempotent, and leaves no thread of this stub's running."""
        if self._closed:
            return
        self._closed = True
        self._closing.set()
        self.server.shutdown()
        self.server.server_close()  # joins the handler threads
        self._thread.join(timeout=10)

    def live_threads(self):
        return [t for t in (self._thread,) if t.is_alive()]


@pytest.fixture
def stub():
    made = []

    def make(routes):
        s = Stub(routes)
        made.append(s)
        return s
    yield make
    for s in made:
        s.close()
    unexpected = [(type(e).__name__, str(e)) for s in made for e in s.errors]
    assert unexpected == [], unexpected
