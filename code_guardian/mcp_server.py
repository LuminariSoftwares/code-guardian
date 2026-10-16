"""Read-only MCP stdio server for code-guardian (mirrors stack-guardian's mcp_server.py).

Speaks JSON-RPC 2.0, one JSON object per line on stdin/stdout, and exposes three read-only tools: scan, orphans and
explain. Everything above default_tools() is pure and package-free; default_tools() is the only place that imports the
rest of code_guardian. A path argument is resolved and must exist.
"""

import json
import os
import sys

PROTOCOL = "2024-11-05"
SERVER_NAME = "code-guardian"
VERSION = "0.2.0"  # keep equal to code_guardian.__version__ and pyproject.toml (this module stays package-free)
_PATH = {"type": "string", "description": "the project directory to read"}
_GOAL = {"type": "string", "description": "goal contract file; default PATH/code-guardian.goal.toml if present"}


def _annotations(title, open_world):
    """MCP tool annotations. Every tool only reads files and reports: it never writes or deletes, and asking twice
    changes nothing. open_world is True only for explain, which calls the configured model URL."""
    return {"title": title, "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True,
            "openWorldHint": open_world}


TOOL_SPECS = [
    {"name": "scan", "title": "Scan a codebase",
     "description": "Is it safe to run, will it work, does it have what it needs? Safe, Works and Complete scores "
                    "(0-100, higher is better), Overall and an A-F grade, every finding with file:line, the egress "
                    "inventory and orphan-code hygiene, and the scan status (COMPLETE, PARTIAL or INVALID: can the "
                    "scan be trusted). Deterministic; parses only, never runs the code.",
     "inputSchema": {"type": "object", "properties": {"path": _PATH, "goal": _GOAL,
                                                      "fail_on": {"type": "string", "enum": ["INFO", "WARN", "FAIL"]}},
                     "required": ["path"]},
     "annotations": _annotations("Scan a codebase", False)},
    {"name": "orphans", "title": "Find orphan code",
     "description": "Functions, classes and modules nothing reachable from the project's entry points uses: dead, "
                    "test-only or uncertain (dynamic dispatch). Judged against the goal contract when there is one.",
     "inputSchema": {"type": "object", "properties": {"path": _PATH, "goal": _GOAL}, "required": ["path"]},
     "annotations": _annotations("Find orphan code", False)},
    {"name": "explain", "title": "Explain the scan in plain English",
     "description": "Runs scan, then asks the local model at CODE_GUARDIAN_LLM_URL for a plain-English summary. Sends "
                    "the findings only (no source). The score never changes; without a model it returns a note.",
     "inputSchema": {"type": "object", "properties": {"path": _PATH, "goal": _GOAL}, "required": ["path"]},
     "annotations": _annotations("Explain the scan in plain English", True)},
]


def resolve_path(value, field="path"):
    """An existing absolute path, or ValueError."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("%s is required" % field)
    path = os.path.realpath(os.path.expanduser(value))
    if not os.path.exists(path):
        raise ValueError("%s does not exist: %s" % (field, value))
    return path


def _text_result(text, is_error):
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


def handle(msg, tools):
    """Answer one JSON-RPC message; return None when there is nothing to say."""
    if not isinstance(msg, dict) or "method" not in msg:
        if isinstance(msg, dict) and "id" in msg:
            return {"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32600, "message": "invalid request"}}
        return None
    if "id" not in msg:
        return None
    method = msg["method"]
    rid = msg["id"]
    if method == "initialize":
        result = {"protocolVersion": PROTOCOL, "capabilities": {"tools": {}},
                  "serverInfo": {"name": SERVER_NAME, "version": VERSION}}
    elif method == "tools/list":
        result = {"tools": TOOL_SPECS}
    elif method == "ping":
        result = {}
    elif method == "tools/call":
        params = msg.get("params") or {}
        args = (params.get("arguments") or {}) if isinstance(params, dict) else None
        if not isinstance(args, dict):
            return {"jsonrpc": "2.0", "id": rid,
                    "error": {"code": -32602, "message": "invalid params: params and arguments must be objects"}}
        name = params.get("name")
        if name not in tools:
            result = _text_result("unknown tool: %s" % name, True)
        else:
            try:
                out = tools[name](args)
            except Exception as exc:  # noqa: BLE001 -- reported to the caller as a tool error
                result = _text_result("%s: %s" % (type(exc).__name__, exc), True)
            else:
                result = _text_result(json.dumps(out, indent=1, default=str), False)
    else:
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "method not found: %s" % method}}
    return {"jsonrpc": "2.0", "id": rid, "result": result}


def serve(lines, write, tools):
    """Read lines, write one JSON reply per answerable line; return the reply count."""
    count = 0
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            reply = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
        else:
            reply = handle(msg, tools)
        if reply is not None:
            write(json.dumps(reply))
            count += 1
    return count


def make_tools(scan_fn, orphans_fn, exit_fn):
    """Bind the protocol to scan_fn(path, goal, explain) -> report, orphans_fn(path, goal) -> hygiene and
    exit_fn(findings, fail_on, status) -> 0, 1 or 3 (3: the scan is PARTIAL or INVALID)."""
    def goal_of(a):
        return resolve_path(a["goal"], "goal") if a.get("goal") else None

    def scan(a):
        rep = scan_fn(resolve_path(a.get("path")), goal_of(a), False)
        fail_on = str(a.get("fail_on") or "FAIL").upper()
        if fail_on not in ("INFO", "WARN", "FAIL"):
            raise ValueError("fail_on must be INFO, WARN or FAIL")
        rep["exit_code"] = exit_fn(rep["findings"], fail_on, rep.get("status"))
        return rep

    def orphans(a):
        return orphans_fn(resolve_path(a.get("path")), goal_of(a))

    def explain(a):
        rep = scan_fn(resolve_path(a.get("path")), goal_of(a), True)
        return {"scores": rep["scores"], "explanation": rep.get("explanation"), "notes": rep["notes"]}

    return {"scan": scan, "orphans": orphans, "explain": explain}


def default_tools():
    """The real tools; every reply goes through scanners.redact_report, the redaction every output path uses."""
    from . import report
    from .scanners import redact_report

    tools = make_tools(lambda p, g, e: report.scan(p, g, explain=e), report.orphans, report.exit_code)
    return {name: (lambda a, fn=fn: redact_report(fn(a))) for name, fn in tools.items()}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv[:1] == ["mcp"]:  # `uvx code-guardian-mcp mcp` (the MCP Registry's packageArguments) lands here
        argv = argv[1:]
    if "--selftest" in argv:
        return _selftest()
    if argv:
        print("code-guardian-mcp: takes no options (it serves MCP on stdio)", file=sys.stderr)
        return 2

    def write(line):
        sys.stdout.write(line + "\n")
        sys.stdout.flush()

    serve(sys.stdin, write, default_tools())
    return 0


def _selftest():
    here = os.path.dirname(os.path.abspath(__file__))
    calls = []

    def fake_scan(path, goal, explain):
        calls.append((path, goal, explain))
        return {"scores": {"overall": 100, "grade": "A"}, "findings": [{"level": "WARN"}], "notes": ["n"]}

    tools = make_tools(fake_scan, lambda p, g: {"path": p}, lambda f, lv, st: 3 if st else 1 if lv != "FAIL" else 0)

    def req(i, method, params=None):
        m = {"jsonrpc": "2.0", "id": i, "method": method}
        if params is not None:
            m["params"] = params
        return m

    def call(name, args):
        r = handle(req(9, "tools/call", {"name": name, "arguments": args}), tools)
        return r["result"]["isError"], r["result"]["content"][0]["text"]

    def body(name, args):
        return json.loads(call(name, args)[1])

    checks = [
        ("initialize", handle(req(1, "initialize", {}), tools)["result"]["serverInfo"] == {"name": SERVER_NAME, "version": VERSION}),
        ("tools_list", [t["name"] for t in handle(req(2, "tools/list"), tools)["result"]["tools"]] == ["scan", "orphans", "explain"]),
        ("notification_silent", handle({"jsonrpc": "2.0", "method": "notifications/initialized"}, tools) is None),
        ("unknown_method", handle(req(3, "resources/list"), tools)["error"]["code"] == -32601),
        ("scan_exit_code", body("scan", {"path": here})["exit_code"] == 0 and body("scan", {"path": here, "fail_on": "warn"})["exit_code"] == 1),
        ("path_resolved", calls[0][0] == os.path.realpath(here)),
        ("missing_path_is_error", call("scan", {"path": os.path.join(here, "no-such-dir")})[0] is True),
        ("path_required", call("orphans", {})[0] is True),
        ("explain_sets_flag", body("explain", {"path": here})["scores"]["grade"] == "A" and calls[-1][2] is True),
        ("unknown_tool", call("delete_everything", {}) == (True, "unknown tool: delete_everything")),
        ("serve_lines", serve(['{"jsonrpc":"2.0","id":1,"method":"ping"}', "", "nope"], [].append, tools) == 2),
        ("annotations", all(t["annotations"]["readOnlyHint"] and not t["annotations"]["destructiveHint"] for t in TOOL_SPECS)
         and [t["annotations"]["openWorldHint"] for t in TOOL_SPECS] == [False, False, True]),
    ]
    passed = sum(1 for _, ok in checks if ok)
    for name, ok in checks:
        if not ok:
            print("FAIL %s" % name)
    print("mcp_server selftest: %d checks, %d passed, %d failed" % (len(checks), passed, len(checks) - passed))
    return 0 if passed == len(checks) else 1


if __name__ == "__main__":
    sys.exit(main())
