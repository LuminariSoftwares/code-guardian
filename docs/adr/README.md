# Architecture decision records

Short records of the architectural choices already in the code, written down after the fact (2026-10-21) from the
code, its docstrings and the commit history. Each one says what was decided, what else was possible and what it
costs. Format: context, decision, alternatives, consequences.

| # | decision | since |
|---|---|---|
| [0001](0001-static-analysis-stdlib-only.md) | Static analysis only, standard library only | 0.1.0 |
| [0002](0002-deterministic-fixed-weight-scoring.md) | Deterministic fixed-weight scores; a model never scores | 0.1.0 / 0.2 |
| [0003](0003-hand-written-mcp-stdio-server.md) | A hand-written MCP stdio server, not the MCP SDK | 0.1.0 |
| [0004](0004-scan-status-and-exit-code-3.md) | Every scan reports whether it can be trusted (COMPLETE, PARTIAL, INVALID; exit 3) | 0.3.0 |
| [0005](0005-line-free-finding-fingerprints.md) | Finding fingerprints without line numbers | 0.3.0 |
| [0006](0006-offline-known-packages-list.md) | An offline, hand-built package list; PyPI only on request | 0.2 |
| [0007](0007-plain-language-layer-never-scores.md) | A plain-language layer that never scores | unreleased |
| [0008](0008-settings-live-in-the-browser.md) | Settings live in the browser; dark is the default; the address is stable | unreleased |
| [0009](0009-folder-dialog-refusals-reopen-loopback.md) | The folder window runs in a child process; some folders are refused; re-open never reads; loopback only | unreleased |
| [0010](0010-test-values-are-graded-by-value-and-use.md) | Key-shaped values are graded by their value and their use, never by where the file sits | 0.4.1 |

A new record is added when a change alters one of these, or makes a choice of the same weight.
