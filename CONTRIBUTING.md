# Contributing

Issues and pull requests are welcome. This is a single-maintainer project worked on in evenings and at weekends, so
reviews are best effort — if something has been sitting for a while, a nudge on the thread is fine.

## Run the tests

```
git clone https://github.com/LuminariSoftwares/code-guardian.git
cd code-guardian
python -m venv .venv
.venv\Scripts\activate          # Windows;  macOS/Linux: source .venv/bin/activate
pip install -e ".[test]"
python -m pytest -q
```

`[test]` adds `pytest`, `build` (one test builds a wheel and reads its METADATA) and `jsonschema` (SARIF and the
MCP tool schemas are validated against their schemas). The package's own `dependencies` are empty and must stay
that way: the tool is standard library only, Python 3.11+. A test-only extra is fine; a runtime dependency is not.

Every module also carries a self-test that runs without pytest:

```
python -m code_guardian.mcp_server --selftest
python -m code_guardian.scanners --selftest
```

Each prints a counted summary line (`mcp_server selftest: 16 checks, 16 passed, 0 failed`);
`tests/test_selftests.py` runs all of them and fails if a module loses its self-test or prints a different line.

CI runs the suite on Linux, Windows and macOS (3.11) and on Linux (3.12, 3.13), builds a wheel and installs it
clean, validates the SARIF against the official 2.1.0 schema, and runs the GitHub Action and the pre-commit hook
against this checkout.

## What a change needs

- **A test you watched fail first.** Say so in the pull request: the test name, red before, green after.
- **Public surface is a contract.** Tool names, CLI flags, config keys, environment variables, JSON fields and exit
  codes keep working. If one has to change, keep a deprecated alias and add a `CHANGELOG.md` line marked
  **Breaking** with the one-line migration.
- **The MCP tool definitions have a size budget.** They are sent on every request;
  `tests/test_tools_list_budget.py` caps `tools/list`. Trim another definition rather than raising the cap, and put
  the before → after number in the pull request.
- **README numbers come from a script or a test in the repo.** "Tested with X" only for what was actually run.
- **New scanner, new weight?** The weight tables in `code_guardian/score.py` and the README's check tables are
  checked against each other by `tests/test_readme_sync.py`; change them together. The README's MCP tool reference
  is generated — run `python tools/tool_reference.py --write`.
- Style follows the code already there: standard library only, small pure functions, no new abstractions for one
  caller, comments where the *why* is not obvious.

## Privacy and identity in commits

This repository is public, and so are its pull requests and CI logs.

- **Nothing personal in a commit, a fixture or a comment.** No real hostnames, private IP addresses, local
  filesystem paths, personal email addresses or anything from a private network. Fixtures use
  `C:\path\to\project`, `/home/user/project` and `example.com`. The `privacy` workflow scans every tracked text
  file on every push and fails the build on a hit; it prints `file:line` and a pattern number only, never the
  matched text, because the log is public.
- **No real secrets, anywhere, including in test data.** The scanners' own key-shape patterns and the fixtures'
  fake keys are built so that they do not look like live credentials. If you need a new one, build the string at
  runtime the way `tests/conftest.py` does, so the project's self-scan does not inventory your test input as its
  own.
- **Sign commits with an address you are happy to publish.** GitHub's `@users.noreply.github.com` address is the
  easy option; a `git commit --amend --reset-author` is easier before the push than after.
