"""Every MCP tool declares the spec's tool annotations and a title; the values are checked over the real stdio protocol."""
import json
import subprocess
import sys

HINTS = ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")


def _tools_over_stdio():
    msgs = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}]
    r = subprocess.run([sys.executable, "-m", "code_guardian.mcp_server"],
                       input="\n".join(json.dumps(m) for m in msgs) + "\n", capture_output=True, text=True, timeout=60)
    replies = {o["id"]: o for o in (json.loads(x) for x in r.stdout.splitlines() if x.strip())}
    return replies[2]["result"]["tools"]


def test_every_tool_declares_all_hints_and_a_title():
    tools = _tools_over_stdio()
    assert tools, "no tools listed"
    for tool in tools:
        ann = tool.get("annotations")
        assert isinstance(ann, dict), tool["name"]
        for hint in HINTS:
            assert isinstance(ann.get(hint), bool), (tool["name"], hint)
        assert isinstance(tool.get("title"), str) and tool["title"].strip(), tool["name"]
        assert ann.get("title") == tool["title"], tool["name"]


def test_hint_values_are_truthful():
    by_name = {t["name"]: t["annotations"] for t in _tools_over_stdio()}
    assert sorted(by_name) == ["explain", "orphans", "scan"]
    # nothing this server exposes writes or deletes, and asking twice gives the same answer
    for name, ann in by_name.items():
        assert ann["readOnlyHint"] is True and ann["destructiveHint"] is False and ann["idempotentHint"] is True, name
    # scan and orphans only read local files; explain calls the configured model URL
    assert by_name["scan"]["openWorldHint"] is False
    assert by_name["orphans"]["openWorldHint"] is False
    assert by_name["explain"]["openWorldHint"] is True
