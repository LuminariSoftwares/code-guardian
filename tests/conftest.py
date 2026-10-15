"""Shared test helpers: the fixture repos are test input (never collected) and a tiny loopback HTTP stub for the
--explain tests, copied from stack-guardian's conftest."""
import http.server
import json
import sys
import threading
import time
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
    """routes: {(method, path): (status, body, delay_s)}; body is a dict/list (sent as JSON) or a str."""

    def __init__(self, routes):
        self.routes = dict(routes)
        self.requests = []  # (method, path, parsed JSON body or None)
        stub = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def _serve(self, method):
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                stub.requests.append((method, self.path, json.loads(raw) if raw else None))
                status, body, delay = stub.routes.get((method, self.path), (404, {"error": "not found"}, 0))
                data = (body if isinstance(body, str) else json.dumps(body)).encode("utf-8")
                if delay:
                    time.sleep(delay)
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

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = "http://127.0.0.1:%d" % self.server.server_port
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def paths(self, method=None):
        return [p for m, p, _ in self.requests if method is None or m == method]

    def close(self):
        self.server.shutdown()
        self.server.server_close()


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
