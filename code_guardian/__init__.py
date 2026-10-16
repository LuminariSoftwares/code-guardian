"""code-guardian: is this codebase safe to run, will it work, and is it complete?

Deterministic Safe, Works and Complete scores (0-100) with an Overall A-F grade, from static scanners, a static call
graph and project-file checks, plus an optional plain-English explanation from a local model that never changes the
score. Standard library only; the scanned code is parsed, never executed, imported or installed.
"""

__version__ = "0.3.0"  # keep equal to pyproject.toml version and mcp_server.VERSION
