# Changelog

## code-guardian 0.3.1 — unreleased

- **`plan`: the floored-dimension note no longer contradicts the plan.** When Safe (or any dimension) is at 0 with
  more than 100 points deducted, 0.3.0 always printed "no single Safe fix moves Overall yet (each shows +0)", even
  when one row deducted more than the excess and its fix did move Overall (for example Safe 130 deducted, a
  `secret.key` row of 50 shown at +10). The note now prints only when it is true: when no single row's deduction is
  larger than the excess (deducted − 100), and it names that excess.
- 0.3.0 was never tagged; 0.3.1 is the first release of the verify loop described below.

## code-guardian 0.3.0 — unreleased

The verify loop: code-guardian becomes the tool an AI-assisted developer runs before and after every change. It
answers four questions: what did the change fix, what did it break, what should be fixed next, and can I trust this
scan. Report and MCP shapes are additive only: every 0.2 key keeps its meaning; the JSON now carries
`schema_version: 2`.

- **Scan status** (`status`, `status_reasons`, `outcomes`). Every scanner, check and the file walk reports `ran`,
  `skipped` (with a reason) or `crashed`; `works`, `complete`, `supply`, `orphans`, the manifest and secret scans
  are now guarded like the Python scanners, so one broken check never kills the scan. **COMPLETE**, **PARTIAL** (a
  check crashed or was skipped, a Python file did not parse, a Python file or manifest was too large or unreadable:
  the grade is capped at **B**) or **INVALID** (PATH unreadable, or no Python files and no manifests: no grade,
  `scores.grade` is `null`). Shown in JSON, text, Markdown, SARIF run properties and MCP. **New exit code 3**: the
  scan is incomplete and nothing is at or above `--fail-on`.
- **Every deduction cites its evidence.** Each check row carries `locations` (every distinct `file:line`, sorted, at
  most 20) and `more`; the text report shows up to three per row.
- **Nothing secret is printed.** One `redact()` on every output path (JSON, text, Markdown, SARIF, MCP, and what
  `--explain` sends) masks API-key shapes and email addresses; the evidence of `secret.*` and `privacy.*` findings is
  redacted strictly. 0.2 printed a key or an email inside a URL literal raw in the egress summary.
- **Baseline.** `code-guardian baseline PATH` writes the sorted fingerprints of every finding
  (`sha256(code | level | path | normalised evidence line)`, no line numbers) to `code-guardian.baseline.json`.
  `scan --baseline FILE` marks each finding `new: true|false`, reports `N new, M known`, and `--fail-on` counts new
  findings only; **the scores still count every finding**. Every finding carries its `fingerprint` (SARIF
  `partialFingerprints`). GitHub Action input `baseline`, pre-commit hook `code-guardian-new`, MCP `scan` argument
  `baseline`.
- **`code-guardian diff BEFORE.json AFTER.json`**: fixed, new and unchanged findings by fingerprint, per-dimension
  score deltas, and a verdict (improved, regressed, mixed, unchanged); exit 1 when anything regressed.
- **`code-guardian plan PATH [--top 10]`**: the repair plan. Each check row's exact Overall gain if its findings were
  gone (re-scored, the code never touched), labelled "estimated gain if fixed", best first, with the catalogue fix
  and every location; a floored dimension is called out. Markdown or `--json`.
- **MCP**: new read-only tools `diff(before, after)` and `plan(path, top)`; a coding agent can loop scan → plan →
  edit → scan → diff.
- **`scan --history [--history-depth N]`** (opt-in): one read-only `git log -p` (argument list, no shell, hardened
  against the scanned repo's own git config, byte-capped) checks the lines commits added with the `secret.key`
  shape rules. New **`secret.history`** (Safe, FAIL, 30): a key a commit added that the file no longer has; it names
  the short sha and the path, never the value.
- **AI-leftover checks** (`leftovers.py`): `works.todo_stub` (WARN 3: a `pass` / `...` / `raise
  NotImplementedError` body an entry point reaches), `works.commented_code` (INFO: 5+ comment lines that parse as
  Python), `works.dead_flag` (INFO: an ALL_CAPS boolean nothing reads).
- **Privacy checks**: `privacy.pii_log` and `privacy.pii_prompt` (Safe, WARN 5): personal-data names (email, phone,
  ssn, dob, a person's address, passport, card number, iban, ip address) flowing into a log, `print` or an LLM
  prompt, one function deep.
- **Calibrated** on the nine repositories (`calibration.md`): no new FAIL; one new WARN (requests, a documented
  override hook), justified. Thirteen first-run `works.todo_stub` hits were deliberate no-ops and were fixed in the
  check.
- An empty repository is now INVALID (no grade) instead of grade A.

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
