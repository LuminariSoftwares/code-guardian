"""The test harness' loopback stub must not leave a thread running after a test.

Several tests check that a client-side timeout is reported and not fatal, by giving a route a delay longer than the
client's timeout. The client then gives up and closes the socket while the handler is still in that delay. If that
handler thread is a daemon and nobody joins it, it is still alive when pytest exits, and it writes a traceback to
stderr for the socket nobody is reading any more -- which is how a run whose own output ends in `402 passed` dies
with `Fatal Python error: _enter_buffered_busy: could not acquire lock for <_io.BufferedWriter name='<stderr>'> at
interpreter shutdown, possibly due to daemon threads` and exit code 134.

Nothing here tests code-guardian; it tests conftest.Stub, because that abort takes the whole suite down with it.
"""
import threading
import urllib.error
import urllib.request

import pytest


def test_a_client_that_gives_up_leaves_no_live_thread_and_no_traceback(stub, capsys):
    before = set(threading.enumerate())
    slow = stub({("GET", "/slow"): (200, {"ok": True}, 30)})

    with pytest.raises((urllib.error.URLError, TimeoutError)):
        urllib.request.urlopen(slow.url + "/slow", timeout=0.3)

    slow.close()  # the fixture would do this too; close() is idempotent

    new_threads = [t for t in threading.enumerate() if t not in before and t.is_alive()]
    assert new_threads == [], new_threads
    captured = capsys.readouterr()
    assert "Exception occurred during processing of request" not in captured.err + captured.out
    assert slow.errors == [], slow.errors


def test_close_is_idempotent_and_the_stub_still_serves_before_it(stub):
    quick = stub({("GET", "/ping"): (200, {"ok": True}, 0)})
    with urllib.request.urlopen(quick.url + "/ping", timeout=10) as resp:
        assert resp.status == 200
    quick.close()
    quick.close()
    assert quick.live_threads() == []
    assert quick.paths() == ["/ping"]
