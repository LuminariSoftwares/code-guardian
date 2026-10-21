# 0005. Finding fingerprints without line numbers

Status: accepted (0.3.0, commit e38c7c4). Recorded 2026-10-21.

## Context

The verify loop compares two scans (`diff`) and gates on findings that are new since a committed baseline
(`scan --baseline`). Both need to decide whether a finding in one report is "the same" finding in the other. Most
edits move code: adding an import shifts every line below it.

## Decision

A fingerprint is `sha256(code | level | relpath | normalised evidence line)`, where the evidence line is the source
line the finding points at, stripped, whitespace-collapsed and redacted (`baseline.py`). Line numbers are left out.
Fingerprints are compared as a multiset, so a third copy of a known line is new. Every finding carries its
fingerprint (SARIF `partialFingerprints`).

## Alternatives

- **file + line + code** (what many tools do): exact, but every edit above a finding makes it "new" and its old self
  "fixed".
- **Whole-file hash:** stable only while the file is untouched.
- **AST-path or context-window hashing:** more robust to edits of the line itself, but harder to explain and to
  recompute by hand.

## Consequences

- Moving or re-indenting code is not a change; `diff` and the baseline gate stay quiet through refactors.
- Editing the flagged line itself makes it a new finding (and the old one fixed). That is deliberate: the code that
  was judged changed.
- Repo-level findings (no line) fingerprint on code, level and path only, so they match across any edit.
- Redaction happens before hashing, so a baseline file never contains a secret value.
