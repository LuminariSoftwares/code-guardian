# 0006. An offline, hand-built package list; PyPI only on request

Status: accepted (0.2, commit be216fa). Recorded 2026-10-21.

## Context

AI assistants sometimes suggest packages that do not exist, and attackers register those names. Checking every
dependency name against PyPI would catch invented names, but a scan that calls the network is neither offline nor
reproducible ([0001](0001-static-analysis-stdlib-only.md), [0002](0002-deterministic-fixed-weight-scoring.md)), and
PyPI's answer changes with the date.

## Decision

- Offline is the default. Names are compared with a bundled list of about 960 widely used PyPI projects
  (`code_guardian/data/known_packages.txt.gz`, built from `tools/known_packages.txt` by
  `tools/build_known_packages.py`, gzip mtime 0 so the bytes are reproducible). A name not on the list is INFO
  (weight 0); a name one or two edits from a listed one is `supply.lookalike` WARN.
- `--online` (CLI only) asks the PyPI JSON API once per name per run: no such project is FAIL, a new or
  single-release project is WARN. Timeouts become notes and never fail the scan.
- The list is hand-built rather than taken from a download-ranking dataset whose licence could not be confirmed.

## Alternatives

- **Always query PyPI:** catches every invented name, but needs the network and gives different answers on
  different days.
- **Ship a top-15,000-by-downloads list:** fewer INFO misses offline, but the usual source carries no licence the
  project could confirm.
- **No supply check:** leaves the most AI-specific risk unexamined.

## Consequences

- Offline, an unknown name is only a hint (INFO), never a deduction; the strong signal needs `--online`.
- `--online` output is not reproducible run to run, and the README says so.
- The list needs occasional manual upkeep; `--verify` drops names PyPI no longer has.
- The MCP tools do not expose `--online`, so an agent's scan stays offline.
