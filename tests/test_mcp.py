"""The MCP server over real stdio: `code-guardian-mcp`, `code-guardian mcp`, and `code-guardian-mcp mcp` (what
`uvx code-guardian-mcp mcp` runs for the MCP Registry) all speak the same protocol."""
import json
import re
import subprocess
import sys

from conftest import FIXTURES, ROOT

import code_guardian
from code_guardian import mcp_server

INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}}


def talk(cmd, msgs):
    r = subprocess.run([sys.executable, *cmd], input="\n".join(json.dumps(m) for m in msgs) + "\n",
                       capture_output=True, text=True, timeout=120)
    return {o["id"]: o for o in (json.loads(x) for x in r.stdout.splitlines() if x.strip())}, r


def call(i, name, args):
    return {"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": name, "arguments": args}}


def test_stdio_end_to_end():
    out, r = talk(["-m", "code_guardian.mcp_server"], [
        INIT, {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        call(3, "scan", {"path": str(FIXTURES / "clean_repo")}),
        call(4, "orphans", {"path": str(FIXTURES / "orphan_repo")}),
        call(5, "scan", {"path": str(FIXTURES / "no_such_repo")}),
        call(6, "explain", {"path": str(FIXTURES / "clean_repo")}),
    ])
    assert sorted(out) == [1, 2, 3, 4, 5, 6], r.stdout + r.stderr
    assert out[1]["result"]["serverInfo"] == {"name": "code-guardian", "version": code_guardian.__version__}
    assert [t["name"] for t in out[2]["result"]["tools"]] == ["scan", "diff", "plan", "orphans", "explain"]
    scan = json.loads(out[3]["result"]["content"][0]["text"])
    assert scan["scores"]["grade"] == "A" and scan["exit_code"] == 0
    orphans = json.loads(out[4]["result"]["content"][0]["text"])
    assert orphans["counts"] == {"orphan.dead": 1, "orphan.test_only": 1, "orphan.uncertain": 1}
    assert out[5]["result"]["isError"] is True and "does not exist" in out[5]["result"]["content"][0]["text"]
    explained = json.loads(out[6]["result"]["content"][0]["text"])
    assert explained["scores"]["grade"] == "A" and explained["explanation"] is None


def test_mcp_subcommand_and_positional():
    for cmd in (["-m", "code_guardian", "mcp"], ["-m", "code_guardian.mcp_server", "mcp"]):
        out, r = talk(cmd, [INIT])
        assert out[1]["result"]["serverInfo"]["name"] == "code-guardian", r.stderr


def test_unknown_option_is_usage_error():
    r = subprocess.run([sys.executable, "-m", "code_guardian.mcp_server", "--nodes", "x"], capture_output=True,
                       text=True, timeout=60)
    assert r.returncode == 2


def test_versions_agree():
    py = re.search(r'^version = "([^"]+)"', (ROOT / "pyproject.toml").read_text(encoding="utf-8"), re.M).group(1)
    server = json.loads((ROOT / "server.json").read_text(encoding="utf-8"))
    assert mcp_server.VERSION == code_guardian.__version__ == py == server["version"] == server["packages"][0]["version"]
