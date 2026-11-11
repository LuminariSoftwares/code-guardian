# Repo intake build: progress log (2026-11-11, append-only)

## Escalations (top)

1. **[owner] Branch pushed and PR opened for review; do not merge, tag or release from it.** The maintainer releases.
2. **[owner] CHANGELOG.md was deliberately not edited.** Two existing acceptance tests (`test_p81_s6_acceptance`, `test_p93_s1_acceptance`) forbid an `## Unreleased` section. Add the entry at release time; suggested text is in the PR body draft shipped next to this log.
3. Reading taken: intake is a separate `code-guardian intake PATH` command with its own low/medium/high confidence, kept out of the Safe/Works/Complete scores and MCP tools, so every existing report and golden file is unchanged.

## What closed, with evidence

- Quarantine (item 8): scans a read-only temp copy; symlinks, FIFOs and `.git` not copied; clone byte/mtime-identical afterwards (`test_intake_core.py`).
- Known-bad hashes (7): ships empty, format documented, env and `--bad-hashes` merge, bad file is a usage error, match forces `malicious`.
- Hooks (1), hidden code (2), invisible Unicode + agent text (3), executables (4), run-on-import + lures (5), hollow (6): each written as a failing test first (red counts recorded in commit messages), then implemented; synthetic benign fixtures only.
- Bought stars (9): `--stars OWNER/REPO`, token from env only, never printed or stored (tested), no redirects, skipped without a token; tested against a loopback stub only.
- Confidence, JSON, SARIF 2.1.0 (10): SARIF validated against the official schema (`CODE_GUARDIAN_SARIF_SCHEMA`); "no checks fired" verdict says it is not a guarantee.
- Full suite on Python 3.11: 1476 passed, 83 skipped (baseline before work: 1386 passed, 82 skipped). Privacy workflow script: 0 hits. Wheel builds and `code-guardian intake` runs from the installed wheel. No linter is configured in the repo; `ruff --select F,E9,B` is clean on the new files. Python 3.13 note: `test_supply::test_snapshot_is_bundled_sorted_and_reproducible` fails on 3.13 before and after this work (gzip byte difference), not caused here.
- Other steals: (a) the existing agent-config check now also reads `SKILL.md`, `.windsurfrules`, `.clinerules`, `skills/*/SKILL.md`, `.claude/skills/*/SKILL.md` (2 tests red first); (b) advisory-first model: every verdict carries `trust: advisory`, plus a feedback corpus (`tests/intake_cases/*.json`, runner, issue form, docs section); (c) hygiene: running intake on this repo found raw U+FEFF characters in four source files, replaced by `﻿` escapes (same meaning).
- Calibration: running intake on this repo's own tree exposed two false positives (archive-password lure on a table cell, exfil wording on prose); both fixed with red tests and recorded as corpus cases.

## Open items

- [S5] JavaScript/shell/PowerShell run-on-import detection (currently Python only via ast).
- [S5] CMake `file(DOWNLOAD)` / `execute_process` hooks; `.pre-commit-config.yaml` local hooks; lefthook.
- [O5] Decide whether to expose `intake` as an MCP tool (blocked by the tools/list size budget; needs trimming another definition).
- [O5] Calibrate confidence thresholds on a corpus of known-clean popular repos (intentionally not run: no third-party repo was scanned).
- [owner] Review the PR and add the CHANGELOG entry at release.
- [owner] Hash list is empty; supply known-bad SHA-256s from sources you trust.

## Three lines

1. Closed with evidence: all ten spec items plus skill-file coverage, feedback corpus and a U+FEFF cleanup; 1476 tests pass on 3.11, SARIF schema-valid.
2. Decision for the maintainer: review the PR and decide on the CHANGELOG wording at release.
3. Risk: the heuristic rules (hollow, entropy, lures, agent wording) false-positive on security tools and docs, which is why confidence exists and the verdict is advisory only.
