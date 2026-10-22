# Changelog

## Unreleased

Review fixes (external review triage, 2026-10-21). One behaviour change in the scanner (URL credentials are
redacted); otherwise the scores, findings and CLI behave as in 0.3.2.

- **Secrets inside a URL literal are no longer printed.** A webhook URL, a signed query string or
  `user:password@host` is itself a credential, and `scan` reprinted it verbatim in `egress[].target`, in the
  `net.egress` findings and in the payload `--explain` sends. Userinfo, every query-parameter value, the fragment
  and the path of a known webhook host (`hooks.slack.com/services/…`, `discord.com/api/webhooks/…`) are now masked
  to `<redacted>`; the scheme, host, port, path and parameter names stay, so the egress inventory still says where
  the code talks to. New `scanners.redact_url()`. Finding fingerprints are computed from the source line, not from
  the printed target, so a baseline written before this change still matches (`tests/test_egress_redaction.py`).
- **The MCP tool definitions are less than half the size.** `tools/list` went from 2,753 tokens to 1,295 against a
  budget of 1,300, measured by the new `tests/test_tools_list_budget.py` (it starts the real server over stdio, so
  CI enforces the budget). Tool names, arguments, defaults, annotations and results are unchanged; the
  `Parameters:` prose that restated the schema is gone, and each description now carries what an agent needs to
  choose a tool — what it does, which sibling to use instead, side effects, the return shape, and, for `scan`,
  `plan` and `orphans`, that finding text is repository data and not instructions. `tests/test_tool_docs.py` checks
  that structure instead of requiring length. The display titles of `plan` and `explain` are shorter ("Plan fixes",
  "Explain a scan").
- **MCP replies are compact JSON** (`separators=(",", ":")` instead of `indent=1`): the same fields, about 21%
  fewer characters (23,078 → 18,154 on `tests/fixtures/risky_repo`).
- **A JSON line that is not an object** (an array, a string, a number) is answered with JSON-RPC `-32600` and the
  server keeps reading, instead of being silently dropped. An unknown method was already `-32601`; that is now
  covered by a test, `server/discover` included, so a client of the stateless MCP revision can fall back.
- **CI** also runs the suite on Ubuntu with Python 3.12 and 3.13 (the existing job names are unchanged), and every
  third-party action in the workflows and in `action.yml` is pinned to a full commit SHA with the version in a
  comment.
- **`pip install -e ".[test]"`** installs what the suite needs (`pytest`, `build`, `jsonschema`); the README recipe
  used to leave `tests/test_spdx_license.py` failing on a missing `build`. Runtime `dependencies` stay empty.
- **`SECURITY.md`** (private vulnerability reporting, plus exactly what leaves the machine and what is written) and
  **`CONTRIBUTING.md`** (how to run the tests, and the privacy and identity rules for commits).
- **README:** who the tool is for and the other three guardians; the MCP protocol revision and that the server is
  stdio only (put an authenticating proxy in front to reach it over a network); a troubleshooting table whose
  messages are pinned by tests; a "one maintainer, best effort" line.
- **`docs/adr/0003`** no longer says the server is listed in the MCP Registry: the wheel carries the `mcp-name:`
  marker, but the entry does not exist yet. `pyproject.toml` declares `Development Status :: 4 - Beta`.

- **MCP tool definitions rewritten for agents.** Each of `scan`, `diff`, `plan`, `orphans` and `explain` now says
  what it does, when to use it, which sibling tool to use instead, its side effects (read-only; network only for
  `explain`) and its output shape. Every parameter has a description, one `examples` entry, and where it applies a
  `default` (`fail_on` FAIL, `top` 10) and `minLength`; each `inputSchema` sets `additionalProperties: false`. The
  server still accepts the same arguments and gives the same results. (The first draft of this also restated the
  whole schema in prose; see the token-budget entry above for what that cost and what replaced it.)
- **`tests/test_tool_docs.py`** fails if a tool or parameter loses its description or example, if a documented
  default differs from the one the server uses, or if the README's tool reference drifts from the served schemas.
  The schemas are validated with `jsonschema` (in the `[test]` extra; skipped when absent).
- **`tools/tool_reference.py`** generates the README's MCP tool reference from `TOOL_SPECS` (`--write`).
- **README:** a 60-second quick start, an Architecture section (Mermaid diagram and the key decisions with their
  trade-offs), Claude Desktop / Claude Code / generic MCP client config, the generated tool reference, "How it is
  tested" and Credits. "30-second example" is now "Example: a repo that trips every scanner".
- **`docs/adr/`:** six architecture decision records for choices already in the code.
- Removed an unused import in `report.py` and one in `tests/test_supply.py`.

## code-guardian 0.3.3 (2026-10-22)

Re-release of the 0.3.2 fix. The v0.3.2 tag and GitHub release point at a commit from before the fix (it still
reported 0.3.1 and scored JavaScript-only repos as COMPLETE / Works 100). Use v0.3.3.

## code-guardian 0.3.2 (not published; tag v0.3.2 is the pre-fix commit)

The report no longer claims checks that never ran on repos that are not Python. On 0.3.1 a repo with only
`package.json`, one `.js` file and a short README scored **Works 100/100** and **COMPLETE**, and the only hint that no
code was analysed was a note at the bottom.

- **Coverage is computed and reported.** Source files are counted by language; every report prints a `coverage:`
  line under the status (`coverage: 40 Python analysed; 112 .ts, 9 .go secret-scan only`). JSON: a new `coverage`
  block; SARIF: `coverage` in the run properties (results unchanged). The note "code-guardian analyses Python only:
  ..." is replaced by that line.
- **No Python source:** Works is **not scored** (`n/a (Python only)`; `scores.works` is `null`,
  `dimensions.works.scored` is `false`), Safe is labelled **partial** (`dimensions.safe.partial`: it can only see
  secrets, manifests and install hooks), Overall is the weighted mean of the scored dimensions (5 × Safe + 2 ×
  Complete) / 7 and the Overall line names what was left out, and the status is **PARTIAL**. The Safe FAIL cap (D)
  and the PARTIAL cap (B) apply as before.
- **Mostly-other-language repos** (at least 5 other-language source files and more than twice as many as Python
  files) are **PARTIAL** with the same scores. A Python project with a few stray helpers stays COMPLETE; all nine
  calibration repos are unchanged and COMPLETE.
- **Coverage alone never fails the gate:** a PARTIAL that is only about coverage keeps exit 0 or 1 from the
  findings (never 3), so `--fail-on` means what it meant.
- **GitHub Action:** new output `status` (`COMPLETE`, `PARTIAL` or `INVALID`); the job summary opens with the status
  and the coverage line; `description` now says Python.
- Every dimension in `dimensions` carries `scored` and `partial` (additive; `schema_version` stays 2).

## code-guardian 0.3.1 (2026-10-16)

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
