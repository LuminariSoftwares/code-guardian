"""Read-only MCP stdio server for code-guardian (mirrors stack-guardian's mcp_server.py).

Speaks JSON-RPC 2.0, one JSON object per line on stdin/stdout, and exposes five read-only tools: scan, diff, plan,
orphans and explain. Everything above default_tools() is pure and package-free; default_tools() is the only place that imports the
rest of code_guardian. A path argument is resolved and must exist.
"""

import json
import os
import sys

PROTOCOL = "2024-11-05"
SERVER_NAME = "code-guardian"
VERSION = "0.3.2"  # keep equal to code_guardian.__version__ and pyproject.toml (this module stays package-free)
_PATH = {"type": "string", "minLength": 1,
         "description": "The project directory to read (absolute, or relative to the server's working directory; "
                        "~ is expanded). It must exist. The code in it is parsed, never imported or run.",
         "examples": ["/home/user/project", "."]}
_GOAL = {"type": "string", "minLength": 1,
         "description": "Optional goal contract (TOML: goal, entry_points, keep, exclude) that says what the project "
                        "is for and where it starts. Must exist when given. Default: PATH/code-guardian.goal.toml if "
                        "present, else entry points are inferred.",
         "examples": ["/home/user/project/code-guardian.goal.toml"]}


def _annotations(title, open_world):
    """MCP tool annotations. Every tool only reads files and reports: it never writes or deletes, and asking twice
    changes nothing. open_world is True only for explain, which calls the configured model URL."""
    return {"title": title, "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True,
            "openWorldHint": open_world}


# Each description answers, in order: what it does, when to use it and which sibling to use instead, what each
# parameter means (Glama scores parameter help in the description, not only in the schema), side effects, output shape
# and errors. tests/test_tool_docs.py fails if a tool or parameter loses any of that.
TOOL_SPECS = [
    {"name": "scan", "title": "Scan a codebase",
     "description": ("Grade a project without running it: Safe, Works and Complete scores (0-100, higher is better), Overall "
                    "and an A-F grade, and every finding with file:line. Use it first and after every edit. Use plan "
                    "instead to rank fixes, diff to compare two scans, orphans when you only want dead code (scan "
                    "already includes it as hygiene), explain for a narrative for a person. "
                    "Parameters: path is the project root; goal overrides PATH/code-guardian.goal.toml; fail_on "
                    "(default FAIL) and baseline only change exit_code, never the scores. "
                    "Behaviour: read-only, deterministic, offline; parses with ast, never imports or runs the code. "
                    "Returns JSON: status (COMPLETE, PARTIAL or INVALID: can the scan be trusted), scores, findings[] "
                    "(code, level, node, summary, fix, fingerprint), egress, hygiene, coverage, notes, exit_code "
                    "(0 pass, 1 findings at or above fail_on, 3 incomplete scan). "
                    "Errors: path, goal or baseline missing, or fail_on not INFO/WARN/FAIL."),
     "inputSchema": {"type": "object", "additionalProperties": False, "properties": {
         "path": _PATH, "goal": _GOAL,
         "fail_on": {"type": "string", "enum": ["INFO", "WARN", "FAIL"], "default": "FAIL",
                     "description": "Lowest finding level that makes exit_code 1 (case-insensitive). Only sets "
                                    "exit_code; the scores and findings are the same either way. Default FAIL.",
                     "examples": ["FAIL", "WARN"]},
         "baseline": {"type": "string", "minLength": 1,
                      "description": "Optional baseline file written by `code-guardian baseline PATH`. Each finding "
                                     "is marked new or known and exit_code counts new findings only; the scores "
                                     "still count every finding. Must exist when given.",
                      "examples": ["/home/user/project/code-guardian.baseline.json"]}},
                     "required": ["path"]},
     "annotations": _annotations("Scan a codebase", False)},
    {"name": "diff", "title": "Compare two scans",
     "description": ("Compare two scan reports and say what a change fixed and what it broke. Use it after an edit, with the "
                    "scan output from before and after; use scan to produce them and plan to choose the next fix. "
                    "Parameters: before and after are each the JSON text a scan call returned or the path of a "
                    "`code-guardian scan --json` file; the forms can be mixed. Findings match by fingerprint (code, "
                    "level, file, evidence line), never line number, so moved code is not a change. "
                    "Behaviour: read-only, offline; reads only the two reports, never the project. "
                    "Returns JSON: verdict (improved, regressed, mixed or unchanged), counts, per-dimension score "
                    "before/after/delta, grade, status, fixed[], new[], unchanged[], exit_code (1 when anything "
                    "regressed). "
                    "Errors: a file that does not exist, or text that is not a scan report."),
     "inputSchema": {"type": "object", "additionalProperties": False, "properties": {
         "before": {"type": "string", "minLength": 1,
                    "description": "The report before the change: the JSON text a scan call returned (starts with "
                                   "{), or the path of an existing `code-guardian scan --json` file.",
                    "examples": ["/home/user/project/before.json"]},
         "after": {"type": "string", "minLength": 1,
                   "description": "The report after the change, in the same form as before: scan JSON text or "
                                  "the path of an existing scan --json file.",
                   "examples": ["/home/user/project/after.json"]}},
                     "required": ["before", "after"]},
     "annotations": _annotations("Compare two scans", False)},
    {"name": "plan", "title": "Plan the next fixes",
     "description": ("Rank what to fix next: scans path, then re-scores it without each check row in turn and lists the rows "
                    "by the Overall points each would gain if fixed, best first. Use it after scan when the grade is "
                    "too low and you need one fix to make; then edit, scan again and diff. Use scan instead for every "
                    "finding, orphans for dead code only. "
                    "Parameters: path is the project root; goal overrides PATH/code-guardian.goal.toml; top (default "
                    "10, at least 1) caps the rows returned. "
                    "Behaviour: read-only, deterministic, offline; the gain is an estimate and the code is never "
                    "edited or run. "
                    "Returns JSON: status, overall, grade, items[] (rank, code, level, dimension, title, gain, "
                    "overall_after, grade_after, count, locations, fix, false_positives), notes. "
                    "Errors: path or goal missing, or top below 1."),
     "inputSchema": {"type": "object", "additionalProperties": False, "properties": {
         "path": _PATH, "goal": _GOAL,
         "top": {"type": "integer", "minimum": 1, "default": 10,
                 "description": "How many rows to return, best first. A whole number of at least 1; default 10.",
                 "examples": [5, 10]}},
                     "required": ["path"]},
     "annotations": _annotations("Plan the next fixes", False)},
    {"name": "orphans", "title": "Find orphan code",
     "description": ("List code nothing uses: functions, classes and modules no entry point reaches, each labelled dead, "
                    "test-only or uncertain (reachable only by dynamic dispatch). Use it before deleting code or to "
                    "clean up a repo; it is lighter than scan because it skips the Safe, Works and Complete checks. "
                    "Use scan instead when you also need the grade (its hygiene section holds this same result). "
                    "Parameters: path is the project root; goal names the contract whose entry_points and keep lists "
                    "decide what is reachable (default PATH/code-guardian.goal.toml; without one, entry points are "
                    "inferred from scripts, __main__ blocks and a library's public API). "
                    "Behaviour: read-only, deterministic, offline; builds a call graph with ast, runs nothing. "
                    "Returns JSON: source (contract or inferred), entry_points, keep, findings[] (code, node "
                    "file:line, summary, try), counts, notes. "
                    "Errors: path or goal missing."),
     "inputSchema": {"type": "object", "additionalProperties": False,
                     "properties": {"path": _PATH, "goal": _GOAL}, "required": ["path"]},
     "annotations": _annotations("Find orphan code", False)},
    {"name": "explain", "title": "Explain the scan in plain English",
     "description": ("Summarise a scan in plain English for a person, written by a local model. Use it when someone needs the "
                    "result explained; use scan instead for the findings themselves (explain returns only scores and "
                    "the summary). "
                    "Parameters: path and goal mean the same as in scan. The model comes from the server's "
                    "environment (CODE_GUARDIAN_LLM_URL, an Ollama or OpenAI-compatible URL, and "
                    "CODE_GUARDIAN_LLM_MODEL), not from arguments. "
                    "Behaviour: runs scan, then POSTs the findings only (code, level, file:line, summary, scores; no "
                    "source, secrets redacted) to that one URL; the only tool that uses the network; writes nothing; "
                    "the score never changes. "
                    "Returns JSON: scores, explanation (text; the model is asked for at most 150 words) and notes. "
                    "Without a configured or reachable model it still succeeds: explanation is null and a note says "
                    "why. "
                    "Errors: path or goal missing."),
     "inputSchema": {"type": "object", "additionalProperties": False,
                     "properties": {"path": _PATH, "goal": _GOAL}, "required": ["path"]},
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


def _report_arg(value, field):
    """A report argument: JSON text is passed through, anything else must be an existing file."""
    if isinstance(value, str) and value.lstrip().startswith("{"):
        return value
    return resolve_path(value, field)


def make_tools(scan_fn, orphans_fn, exit_fn, diff_fn=None, plan_fn=None, gate_fn=None):
    """Bind the protocol to scan_fn(path, goal, explain, baseline) -> report, orphans_fn(path, goal) -> hygiene and
    exit_fn(findings, fail_on, status, baseline) -> 0, 1 or 3 (3: the scan is PARTIAL or INVALID). gate_fn(report)
    -> the status exit_fn gates on (default: the report's status)."""
    gate_fn = gate_fn or (lambda rep: rep.get("status"))
    def goal_of(a):
        return resolve_path(a["goal"], "goal") if a.get("goal") else None

    def scan(a):
        fail_on = str(a.get("fail_on") or "FAIL").upper()
        if fail_on not in ("INFO", "WARN", "FAIL"):
            raise ValueError("fail_on must be INFO, WARN or FAIL")
        base = resolve_path(a["baseline"], "baseline") if a.get("baseline") else None
        rep = scan_fn(resolve_path(a.get("path")), goal_of(a), False, base)
        rep["exit_code"] = exit_fn(rep["findings"], fail_on, gate_fn(rep), rep.get("baseline"))
        return rep

    def orphans(a):
        return orphans_fn(resolve_path(a.get("path")), goal_of(a))

    def explain(a):
        rep = scan_fn(resolve_path(a.get("path")), goal_of(a), True, None)
        return {"scores": rep["scores"], "explanation": rep.get("explanation"), "notes": rep["notes"]}

    def diff(a):
        return diff_fn(_report_arg(a.get("before"), "before"), _report_arg(a.get("after"), "after"))

    def plan(a):
        top = a.get("top", 10)
        if not isinstance(top, int) or isinstance(top, bool) or top < 1:
            raise ValueError("top must be a whole number of at least 1")
        return plan_fn(resolve_path(a.get("path")), goal_of(a), top)

    tools = {"scan": scan, "orphans": orphans, "explain": explain}
    if diff_fn:
        tools["diff"] = diff
    if plan_fn:
        tools["plan"] = plan
    return tools


def default_tools():
    """The real tools; every reply goes through scanners.redact_report, the redaction every output path uses."""
    from . import report, verify
    from .scanners import redact_report

    def diff(before, after):
        d = verify.diff(verify.load_report(before), verify.load_report(after))
        d["exit_code"] = verify.diff_exit(d)
        return d

    tools = make_tools(lambda p, g, e, b: report.scan(p, g, explain=e, baseline=b), report.orphans, report.exit_code,
                       diff, lambda p, g, top: verify.plan(report.scan(p, g), top), report.gate_status)
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

    def fake_scan(path, goal, explain, baseline):
        calls.append((path, goal, explain, baseline))
        return {"scores": {"overall": 100, "grade": "A"}, "findings": [{"level": "WARN"}], "notes": ["n"]}

    tools = make_tools(fake_scan, lambda p, g: {"path": p}, lambda f, lv, st, b: 3 if st else 1 if lv != "FAIL" else 0,
                       lambda b, a: {"before": b, "after": a}, lambda p, g, top: {"top": top})

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
        ("tools_list", [t["name"] for t in handle(req(2, "tools/list"), tools)["result"]["tools"]]
         == ["scan", "diff", "plan", "orphans", "explain"]),
        ("diff_args", body("diff", {"before": "{}", "after": __file__})["after"] == os.path.realpath(__file__)
         and call("diff", {"before": "{}", "after": "nope.json"})[0] is True),
        ("plan_top", body("plan", {"path": here})["top"] == 10 and call("plan", {"path": here, "top": 0})[0] is True),
        ("notification_silent", handle({"jsonrpc": "2.0", "method": "notifications/initialized"}, tools) is None),
        ("unknown_method", handle(req(3, "resources/list"), tools)["error"]["code"] == -32601),
        ("scan_exit_code", body("scan", {"path": here})["exit_code"] == 0 and body("scan", {"path": here, "fail_on": "warn"})["exit_code"] == 1),
        ("path_resolved", calls[0][0] == os.path.realpath(here)),
        ("baseline_resolved", body("scan", {"path": here, "baseline": __file__}) and calls[-1][3] == os.path.realpath(__file__)
         and call("scan", {"path": here, "baseline": os.path.join(here, "nope.json")})[0] is True),
        ("missing_path_is_error", call("scan", {"path": os.path.join(here, "no-such-dir")})[0] is True),
        ("path_required", call("orphans", {})[0] is True),
        ("explain_sets_flag", body("explain", {"path": here})["scores"]["grade"] == "A" and calls[-1][2] is True),
        ("unknown_tool", call("delete_everything", {}) == (True, "unknown tool: delete_everything")),
        ("serve_lines", serve(['{"jsonrpc":"2.0","id":1,"method":"ping"}', "", "nope"], [].append, tools) == 2),
        ("annotations", all(t["annotations"]["readOnlyHint"] and not t["annotations"]["destructiveHint"] for t in TOOL_SPECS)
         and [t["annotations"]["openWorldHint"] for t in TOOL_SPECS] == [False, False, False, False, True]),
    ]
    passed = sum(1 for _, ok in checks if ok)
    for name, ok in checks:
        if not ok:
            print("FAIL %s" % name)
    print("mcp_server selftest: %d checks, %d passed, %d failed" % (len(checks), passed, len(checks) - passed))
    return 0 if passed == len(checks) else 1


if __name__ == "__main__":
    sys.exit(main())
