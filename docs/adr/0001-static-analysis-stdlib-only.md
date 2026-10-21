# 0001. Static analysis only, standard library only

Status: accepted (0.1.0, commit fbe1aa3). Recorded 2026-10-21.

## Context

The question code-guardian answers is "is this safe to run?", usually about code the user did not write: a cloned
repo, a dependency, or a change an AI assistant just made. Any approach that imports, installs or executes that code
to judge it can be attacked by the code under judgement (an install hook, an import-time side effect). The tool is
also meant to run anywhere a developer or a coding agent is: a CI job, a pre-commit hook, an MCP client launched with
`uvx`.

## Decision

- Read, never run: Python is parsed with `ast`; manifests with `json`, `tomllib` and `configparser`; secrets with
  regular expressions. Nothing in the scanned tree is imported, executed or installed (`report.py` docstring).
- No network during a scan. The only network paths are opt-in: `--explain` (one configured URL) and `--online`
  (PyPI).
- Standard library only: `dependencies = []` in `pyproject.toml`; Python 3.11+ (for `tomllib`).

## Alternatives

- **Dynamic analysis or sandboxed execution** (run the tests, trace imports): sees real behaviour, but needs a
  sandbox, the project's dependencies and its runtime, and still runs untrusted code.
- **Wrap existing analysers** (Bandit, vulture, detect-secrets, a type checker): broader coverage, but several
  dependency trees to install and audit, several output formats to reconcile, and no single deterministic score.
- **A multi-language parser** (tree-sitter): deep analysis beyond Python, at the cost of a native dependency.

## Consequences

- Install is one wheel with no dependencies; a scan of a small repo takes well under a second.
- Only Python is analysed in depth. Other languages get the secret scan and repo-hygiene checks, and since 0.3.2 the
  report says so (`coverage:` line, PARTIAL status; see [0004](0004-scan-status-and-exit-code-3.md)).
- Runtime-built behaviour is invisible where the parse cannot see it. The README says a grade A means "nothing the
  scanners recognise", not "proven safe".
- Files are parsed by the interpreter running code-guardian, so a project needing a newer Python gets
  `works.syntax` INFO rather than FAIL.
