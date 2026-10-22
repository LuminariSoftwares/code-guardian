# 0003. A hand-written MCP stdio server, not the MCP SDK

Status: accepted (0.1.0, commit fbe1aa3; shape shared with stack-guardian). Recorded 2026-10-21.

## Context

code-guardian is offered to AI clients as an MCP server (`uvx code-guardian-mcp mcp`, listed on Glama; the wheel
carries the `mcp-name:` marker an MCP Registry entry needs, but it is not listed there yet). The server
needs `initialize`, `tools/list`, `tools/call` and `ping` over stdio for five read-only tools.
The official Python SDK would bring a dependency tree into a package that otherwise has none ([0001](0001-static-analysis-stdlib-only.md)).

## Decision

`code_guardian/mcp_server.py` implements JSON-RPC 2.0 over stdio by hand, one JSON object per line, in about 100
lines of protocol code. Everything above `default_tools()` is pure and package-free: `handle()` answers one message, `serve()` loops
over lines, and `make_tools()` binds the protocol to injected functions, so the protocol is tested without scanning
anything. Tool errors are returned as results with `isError: true`, never as crashes. The tool schemas
(`TOOL_SPECS`) are plain data that a test checks for complete documentation and that generates the README's tool
reference.

## Alternatives

- **The official `mcp` SDK:** tracks the spec for you (newer protocol versions, structured output, other
  transports), at the cost of a dependency tree and of the zero-dependency install.
- **A generic CLI-to-MCP wrapper:** no protocol code here, but no control over schemas, annotations or error shape.

## Consequences

- `pip install code-guardian-mcp` still installs nothing else, and the server imports nothing outside the package.
- Protocol changes are this project's job. The server speaks protocol `2024-11-05`, stdio only, and returns tool
  output as JSON text rather than `structuredContent`.
- The protocol is tested over real stdio (`tests/test_mcp.py`, `tests/test_tool_annotations.py`) and by the module's
  own `--selftest`, and the built wheel's server is exercised in CI.
