# 0007. A plain-language layer that never scores

Status: accepted (unreleased, plan P76 section S1). Recorded 2026-10-22.

## Context

Everything code-guardian prints today is written for someone who reads code: finding codes (`exec.shell`),
levels (`FAIL`, `WARN`, `INFO`), three 0-100 scores and a capped letter grade. The person who most needs the
answer — somebody who asked an assistant for a program and now has a folder they cannot read — cannot act on that.

The obvious shortcut is to have the plain-language layer work out its own verdict: look at the findings, decide how
worried to be, and say so. That would put a second scoring system in the codebase, drifting from the one in
`score.py` that the README documents and `tests/test_scoring.py` pins, and it would let a sentence promise
something the scanner never established. A static scan reads files; it does not run the code. It can say a string
is shaped like an API key. It cannot say your password will leak.

## Decision

`code_guardian/plain.py` is a pure read of the report dict `report.scan()` already produces. It never writes to the
report, and every number in a sentence it emits was already in the report. The same holds for the `code-guardian
ui` app built on top of it.

**Harm vocabulary.** Exactly five labels, and the mapping is mechanical, from the Safe findings only
(`score.dimension_of(code) == "safe"`):

| condition | label |
|---|---|
| the scan status is `INVALID` (`scores.grade` is null) | `Could not check` |
| any Safe finding at `FAIL` | `High` |
| else any Safe finding at `WARN` | `Medium` |
| else any Safe finding at `INFO` | `Low` |
| else | `No known risks found` |

`partial` is true when the status is `PARTIAL` or `coverage.safe_partial` is set, and renders beside the label as
"partial check". The harm level is never null: a scan that could not judge the project says so in words.

**Forbidden words.** No sentence the layer produces — harm label, its `why`, the score sentences, the
what-was-checked lines, the diff sentence — may contain `is safe`, `safe to run`, `secure`, `clean`, `no risks`,
`risk-free`, `harmless` or `guaranteed` (single words matched whole, case-insensitively; `Safe` as the name of the
score dimension is not one of them). The same rule applies to every sentence in `plain.WHY`. A sentence says what
a check saw, and what follows from that is written with *can*, *may* or *if*. `tests/test_plain.py` and
`tests/test_p76_s1_acceptance.py` grep for the list over every fixture.

**Select-to-explain.** When the app asks a model to explain something, it sends the lines the user selected and
nothing else — no other file, no whole report, no path outside the scanned tree.

**Stdlib only, loopback only.** The layer and the app it serves add no dependency (`dependencies = []` stays). The
server binds `127.0.0.1` only, and every request must carry the session token and a `Host`/`Origin` from that
loopback address.

## Alternatives

- **Let the layer compute its own severity** (weigh findings, average them, call it a risk level): a second scoring
  system to keep in step with `score.py`, with no weights table to explain it. Rejected; ADR 0002 already says a
  model never scores, and this says the wording never scores either.
- **Ask a model to write the sentences at scan time:** different words every run, no way to test them, and the
  model is free to promise what the scan did not establish. Rejected. `explain.py` stays the one opt-in model call,
  clearly labelled.
- **Reuse the catalogue `means` text as-is:** honest, but written for a developer ("`ast.parse` rejects the file").
  Rejected as the whole layer, kept as the fallback for any code whose plain sentence cannot be written without
  claiming more than the check knows.
- **A traffic-light colour instead of words:** green reads as a promise to most people, which is the one thing a
  static scan cannot make.

## Consequences

- A reader gets one label, five words at most, and a sentence saying which finding produced it.
- The layer cannot drift from the scanner: the acceptance test pins each fixture's label to what
  `score.dimension_of` says on the same scan, so changing a scanner's dimension fails the test rather than quietly
  changing the wording.
- `No known risks found` is the ceiling. There is no label meaning "fine", because the scan cannot establish one.
- Every catalogue code needs a plain sentence, and a drift test fails when one is added without it.
- The wording is reviewed by hand, sentence by sentence: the forbidden-word grep catches the obvious overclaim, not
  a subtle one.
