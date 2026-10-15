"""--explain: ask a local model to put the findings into plain English. It never adds, removes or rescores one.

Only the findings travel: code, level, file:line and the summary (at most 120 characters each), plus the score,
grade and hygiene counts. No source code, no evidence lines. The request goes to the one URL the user configured,
directly (no proxy), and nowhere else. Any failure leaves the report as it was and adds one note line.

Environment:
    CODE_GUARDIAN_LLM_URL     Ollama .../api/chat or OpenAI-compatible .../v1/chat/completions (a bare host or a
                              .../v1 base is completed by path); http or https only
    CODE_GUARDIAN_LLM_MODEL   model name
    CODE_GUARDIAN_LLM_KEY     optional bearer token for an OpenAI-compatible server
    CODE_GUARDIAN_LLM_TIMEOUT seconds (default 60)

Public contract:
    LABEL
    payload(report) -> dict                       # exactly what is sent
    endpoint(url) -> (api, url)                   # api is "ollama" or "openai"; raises ValueError
    explain(report, env=None) -> (text or None, note or None)
"""

import http.server
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from .finding import summarize

LABEL = "model explanation (not part of the score)"
SYSTEM = ("You explain the results of a static code scan to someone who does not write code. It scores three "
          "things out of 100, higher is better: Safe (is it safe to run?), Works (will it work?) and Complete (does "
          "it have what it needs?), plus an Overall score and grade. Use only the JSON you are given. Do not add, "
          "remove, merge or re-grade findings, and do not invent file names. In at most 150 words: say what the "
          "scores mean, then the two or three most important things to do first, in plain words.")
FIELDS = ("code", "level", "node", "summary")


def payload(report):
    s = report.get("scores") or {}
    hygiene = report.get("hygiene") or {}
    return {"scores": {k: s.get(k) for k in ("safe", "works", "complete", "overall", "grade")},
            "findings": [{k: f.get(k) for k in FIELDS} for f in report.get("findings") or []],
            "hygiene": {"source": hygiene.get("source"), "counts": hygiene.get("counts") or {},
                        "findings": [{k: f.get(k) for k in FIELDS} for f in hygiene.get("findings") or []]}}


def endpoint(url):
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ValueError("CODE_GUARDIAN_LLM_URL must be an http(s) URL")
    path = parts.path.rstrip("/")
    if path.endswith("/chat/completions"):
        api = "openai"
    elif path.endswith("/api/chat"):
        api = "ollama"
    elif path.endswith("/v1"):
        api, path = "openai", path + "/chat/completions"
    elif not path:
        api, path = "ollama", "/api/chat"
    else:
        raise ValueError("CODE_GUARDIAN_LLM_URL path must end in /api/chat or /v1/chat/completions")
    return api, urllib.parse.urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def _request(api, model, report):
    messages = [{"role": "system", "content": SYSTEM},
                {"role": "user", "content": json.dumps(payload(report), sort_keys=True)}]
    if api == "ollama":
        return {"model": model, "messages": messages, "stream": False, "options": {"temperature": 0}}
    return {"model": model, "messages": messages, "temperature": 0, "stream": False}


def _text(api, body):
    if api == "ollama":
        return ((body.get("message") or {}).get("content") or "").strip()
    choices = body.get("choices") or [{}]
    return (((choices[0] or {}).get("message") or {}).get("content") or "").strip()


def explain(report, env=None):
    env = os.environ if env is None else env
    url = (env.get("CODE_GUARDIAN_LLM_URL") or "").strip()
    model = (env.get("CODE_GUARDIAN_LLM_MODEL") or "").strip()
    if not url:
        return None, "explain skipped: CODE_GUARDIAN_LLM_URL is not set"
    if not model:
        return None, "explain skipped: CODE_GUARDIAN_LLM_MODEL is not set"
    try:
        api, full = endpoint(url)
        timeout = float(env.get("CODE_GUARDIAN_LLM_TIMEOUT") or 60)
    except ValueError as exc:
        return None, "explain skipped: %s" % exc
    headers = {"Content-Type": "application/json"}
    if api == "openai" and env.get("CODE_GUARDIAN_LLM_KEY"):
        headers["Authorization"] = "Bearer " + env["CODE_GUARDIAN_LLM_KEY"]
    req = urllib.request.Request(full, data=json.dumps(_request(api, model, report)).encode("utf-8"),
                                 headers=headers, method="POST")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    started = time.perf_counter()
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return None, "explain skipped: the model at %s did not answer (%s)" % (urllib.parse.urlsplit(full).netloc,
                                                                            type(exc).__name__)
    text = _text(api, body) if isinstance(body, dict) else ""
    if not text:
        return None, "explain skipped: the model returned no text"
    return text, "explain: %s answered in %.1f s" % (api, time.perf_counter() - started)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if "--selftest" in argv:
        return selftest()
    sys.stderr.write("usage: python -m code_guardian.explain --selftest\n")
    return 2


def selftest():
    seen = []

    class Stub(http.server.BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            seen.append((self.path, body))
            reply = ({"message": {"content": "All clear."}} if self.path == "/api/chat"
                     else {"choices": [{"message": {"content": "Fix the key."}}]})
            data = json.dumps(reply).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Stub)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % server.server_port
    report = {"scores": {"safe": 60, "overall": 80, "grade": "D"}, "findings": [
        {"code": "secret.key", "level": "FAIL", "node": "a.py:1", "summary": "s", "evidence": ["SOURCE"], "try": []}],
        "hygiene": {"source": "inferred", "counts": {"orphan.dead": 0}, "findings": []}}
    try:
        ollama = explain(report, {"CODE_GUARDIAN_LLM_URL": base, "CODE_GUARDIAN_LLM_MODEL": "m"})
        openai = explain(report, {"CODE_GUARDIAN_LLM_URL": base + "/v1", "CODE_GUARDIAN_LLM_MODEL": "m"})
    finally:
        server.shutdown()
        server.server_close()
    dead = explain(report, {"CODE_GUARDIAN_LLM_URL": base, "CODE_GUARDIAN_LLM_MODEL": "m", "CODE_GUARDIAN_LLM_TIMEOUT": "2"})
    checks = [
        ("ollama", ollama[0] == "All clear." and seen[0][0] == "/api/chat"),
        ("openai", openai[0] == "Fix the key." and seen[1][0] == "/v1/chat/completions"),
        ("findings_only", "SOURCE" not in json.dumps([b for _, b in seen]) and '"evidence"' not in json.dumps(seen)),
        ("unset", explain(report, {}) == (None, "explain skipped: CODE_GUARDIAN_LLM_URL is not set")),
        ("unreachable_soft", dead[0] is None and dead[1].startswith("explain skipped: the model at")),
        ("scheme", explain(report, {"CODE_GUARDIAN_LLM_URL": "file:///x", "CODE_GUARDIAN_LLM_MODEL": "m"})[0] is None),
        ("endpoint", endpoint(base + "/v1/chat/completions")[0] == "openai" and endpoint(base + "/api/chat")[0] == "ollama"),
    ]
    return summarize("explain", checks)


if __name__ == "__main__":
    sys.exit(main())
