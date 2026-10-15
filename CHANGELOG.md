# Changelog

## code-guardian 0.2.0 — unreleased

One command now answers three questions about any repo without running it: is it **safe** to run, will it
**work**, does it have what it **needs**.

- **Three health scores, higher is better:** Safe (is it safe to run?), Works (will it work?) and Complete (does it
  have what it needs?), each 0–100, plus Overall = 0.5·Safe + 0.3·Works + 0.2·Complete and an A–F grade
  (A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40). Safe = 100 − the v0.1 threat score, with the v0.1 weights.
- **Per-check deductions:** a check deducts its weight once, plus a quarter of it per extra occurrence, at most 2×.
- **FAIL cap:** any Safe finding at FAIL caps the grade at D.
- **New report shape** (`scores`, `dimensions`, `top`, `weights`, `weights_rule`; `threat` is gone). Every report
  prints the weight table it used. The report no longer carries `elapsed_ms`: same repo, same output.
- `--fail-on` gates on every scored finding (Safe, Works, Complete).
- **Works checks** (`works.py`): `works.syntax`, `works.import_unresolved` (stdlib, repo tree and declared
  dependencies, with an import-name → distribution table), `works.relative_missing`, `works.tests_missing`,
  `works.test_no_assert`, `works.entry_missing`; `orphan.dead` folds into Works at weight 3. `parse.skipped` is
  replaced by `works.syntax`. `requirements/*.txt` and `Pipfile` are read as manifests.
- **Complete checks** (`complete.py`): licence file and declared licence, README (present, 200+ bytes, install and
  usage headings), CI config, `[project]` metadata, lockfile (applications only), `.env.example` (only when the code
  reads environment variables), and `deps.declared_unused` (INFO).
- **Invented and lookalike packages** (`supply.py`): `supply.unknown_package` (offline INFO against a bundled,
  hand-built list of ~960 known PyPI projects; with `--online`, FAIL when PyPI has no such project and WARN for new or
  single-release projects) and `supply.lookalike` (one or two edits from a known package). `--online` is the only
  network use besides `--explain`.
- **Outputs:** `--sarif` (SARIF 2.1.0, one rule per check code, validated in CI against the official schema) and
  `--markdown`. A composite **GitHub Action** (`action.yml`: scan, job summary, SARIF upload, gate) and a
  **pre-commit hook** (`.pre-commit-hooks.yaml`). A check catalogue (`catalogue.py`) holds each code's meaning, fix
  and false-positive notes.
- **Calibrated** against requests, click, rich, httpx, flask and the four guardian repos (`calibration.md`): no FAIL
  on any of them. Fixes from calibration: Safe findings in test code and documentation are INFO (API-key shapes and
  exec of decoded data excepted); `tls.off` is WARN when only a caller's opt-out reaches it; alphabets are not
  high-entropy secrets; import flags set by guarded imports guard too; scripts resolve next to their own manifest;
  `works.import_unresolved` checks product code only; `.env.example` is asked of applications only; pytest fixtures
  are not tests; XML namespace URIs are not egress; a library's public API and re-exports count as entry points; star
  re-exports, double bindings, property setters, module `__getattr__` and decorator-registered handlers are followed.

## code-guardian 0.1.0 — unreleased

First version. Distribution `code-guardian-mcp`; commands `code-guardian` and `code-guardian-mcp`.

- **`code-guardian scan PATH`**: a deterministic threat score (0–100, grade A–F) from eleven static scanners
  (`secret.key`, `exec.dynamic`, `exec.shell`, `deser.unsafe`, `net.egress`, `net.bind_all`, `tls.off`,
  `install.hook`, `obfuscation`, `fs.outside`, `deps.unpinned`), the top five contributors, and a network egress
  inventory. Python is parsed with `ast`; manifests with `json`/`tomllib`/`configparser`; other languages get the
  secret scan. Nothing scanned is executed, imported or installed, and a scan makes no network calls.
- **Orphan code** (`code-guardian orphans PATH`, and the hygiene section of `scan`): a static call graph reports
  `orphan.dead`, `orphan.test_only` and `orphan.uncertain`, judged against `code-guardian.goal.toml` or inferred entry
  points. `code-guardian init` writes a starter goal file.
- **`--explain`**: an optional plain-English summary from a local model (Ollama or OpenAI-compatible). Sends findings
  only, never changes the score, fails soft.
- **MCP server** (`code-guardian-mcp`, `code-guardian mcp`): read-only tools `scan`, `orphans`, `explain` with tool
  annotations; `server.json` for the MCP Registry (`io.github.LuminariSoftwares/code-guardian`).
- Exit codes: 0 nothing at or above `--fail-on` (default FAIL), 1 findings at or above it, 2 usage or parse error.
