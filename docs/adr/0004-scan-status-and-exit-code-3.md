# 0004. Every scan reports whether it can be trusted

Status: accepted (0.3.0, commit 9486f73; coverage rule in 0.3.2, commit b019bc6). Recorded 2026-10-21.

## Context

Before 0.3, a scanner that crashed or a file that would not parse simply produced fewer findings, and fewer findings
read as a better grade. A repo with no Python at all scored Works 100/100 on 0.3.1 although no Works check ran. For a
tool whose job is to be trusted by people and agents who do not read the analysis, a silent gap is worse than a
loud one.

## Decision

- Every scanner, check and the file walk is run through a guard that records `ran`, `skipped` (with a reason) or
  `crashed` (with the error) in `outcomes`. One broken check never kills the scan.
- The report carries a `status`: **COMPLETE**; **PARTIAL** (a check crashed or was skipped, a file did not parse or
  was too large; or, since 0.3.2, the source is mostly in languages other than Python) with the grade capped at B; or
  **INVALID** (nothing to judge) with no grade.
- A new exit code, 3, means "the scan is incomplete and nothing is at or above `--fail-on`". A PARTIAL that is only
  about language coverage keeps the exit code from the findings, so `--fail-on` means what it meant.

## Alternatives

- **Fail the whole scan on any error:** honest, but one exotic file blocks every CI run.
- **Skip silently and keep the grade:** close to the 0.2 behaviour; the grade overstated what was checked.
- **A warning note only:** visible to a person reading text, invisible to a CI gate or an agent reading JSON.

## Consequences

- Callers (CI, the GitHub Action, MCP clients) have a fourth exit code and a status field to handle; the Action
  exposes `status` as an output.
- The grade can no longer claim more than was checked: a PARTIAL scan is at most B and says why, and an INVALID scan
  has no grade at all.
