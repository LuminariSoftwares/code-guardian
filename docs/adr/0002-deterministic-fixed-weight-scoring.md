# 0002. Deterministic fixed-weight scores; a model never scores

Status: accepted (0.1.0 threat score; Safe/Works/Complete model in commit 8abd642). Recorded 2026-10-21.

## Context

The scores gate CI jobs (`--fail-on`), feed a before/after diff and are read by people who cannot audit the
analysis. A score that changes between two runs on the same commit cannot gate anything, and a score a reader cannot
recompute by hand cannot be argued with. The project is aimed at local-AI developers, so a model is available, and it
is tempting to let it judge.

## Decision

- Every check (code + level) has a fixed weight in `score.TABLES`. A check deducts its weight once, plus a quarter
  of it per extra occurrence, capped at twice the weight, so fifty copies of one minor issue cannot zero a score.
- Dimension score = max(0, 100 − deductions); Overall = 0.5 Safe + 0.3 Works + 0.2 Complete; fixed grade bands; any
  Safe FAIL caps the grade at D. No model, randomness or clock is involved (`score.py` docstring), and the report has
  no elapsed time so its bytes are reproducible.
- The weights are printed in every report and published in the README; `tests/test_readme_sync.py` keeps the two
  equal.
- The optional model (`--explain`, MCP `explain`) only explains. A test asserts that the report with an explanation
  equals the report without one, plus a labelled block.

## Alternatives

- **A model-judged score:** reads context a rule cannot, but is not reproducible, depends on which model is loaded,
  and can be argued into a better grade by the code it judges.
- **Sum of per-finding severities (no per-check cap):** simpler, but one noisy rule dominates the grade.
- **Learned weights:** would need a labelled corpus the project does not have.

## Consequences

- Same repo and version give the same output every time; `plan` can compute the exact Overall gain of fixing a row
  by re-scoring without it.
- The weights are judgement calls. They are calibrated by hand on nine real repositories ([calibration.md](../../calibration.md))
  and any change shows up in the README diff, but they are not proven optimal.
- Score changes are visible API: changing a weight is a CHANGELOG entry and changes the fixtures' asserted scores.
