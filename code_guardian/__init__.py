"""code-guardian: is this codebase safe to run, and is all of it actually used?

A deterministic threat score from static scanners, orphan code judged against a goal contract, and an optional
plain-English explanation from a local model that never changes the score. Standard library only; the scanned code
is parsed, never executed, imported or installed.
"""

__version__ = "0.2.0"  # keep equal to pyproject.toml version and mcp_server.VERSION
