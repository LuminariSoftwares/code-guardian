"""The MCP tool definitions have a size budget.

`tools/list` is sent to the model on every request, so the five tool definitions are a standing cost in every
conversation that has this server attached. This measures them the way the project's own audit does -- start the
real server entry point over stdio, ask it for its tools, and count `json.dumps(result["tools"])` at the rule of
thumb of 3.5 characters per token -- and fails when they grow past BUDGET. Released 0.3.1 measured 1147 tokens.

If a change needs more room, trim another definition rather than raising BUDGET: the number is a contract.
"""
import json
import subprocess
import sys

BUDGET = 1300
CHARS_PER_TOKEN = 3.5
INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "budget", "version": "0"}}}
MESSAGES = [INIT, {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}]


def tools_list_tokens():
    """(tokens, tools) from the real `code-guardian-mcp` entry point over stdio."""
    run = subprocess.run([sys.executable, "-m", "code_guardian.mcp_server", "mcp"],
                         input="\n".join(json.dumps(m) for m in MESSAGES) + "\n",
                         capture_output=True, text=True, timeout=120)
    replies = {o["id"]: o for o in (json.loads(x) for x in run.stdout.splitlines() if x.strip())}
    assert 2 in replies, run.stdout + run.stderr
    tools = replies[2]["result"]["tools"]
    return round(len(json.dumps(tools)) / CHARS_PER_TOKEN), tools


def test_tools_list_fits_the_token_budget():
    tokens, tools = tools_list_tokens()
    assert tokens <= BUDGET, (
        "tools/list is %d tokens, over the budget of %d: %s. Trim a tool definition; do not raise the budget."
        % (tokens, BUDGET, ", ".join("%s %d chars" % (t["name"], len(json.dumps(t))) for t in tools)))
