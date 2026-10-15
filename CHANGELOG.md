# Changelog

## code-guardian 0.2.0 — unreleased

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
