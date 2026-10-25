# 0010. Key-shaped values are graded by their value and their use, never by where the file sits

Status: accepted (0.4.1, plan P88 section 2.3). Recorded 2026-10-25.

## Context

`secret.key` fires on a provider key shape (`sk-…`, `AKIA…`, `ghp_…`) at FAIL, weight 30, and a FAIL caps the grade.
Run on a real project folder of scripts written with AI, 206 findings were FAIL; most were in backup copies and in test
code, where a key-shaped string is usually a test value (`"sk-" + "0" * 40`, `FAKE_TOKEN = …`). The real ones were
buried. The old rule already sent safe findings in test code to INFO, but it left key shapes alone on purpose: a
real key is leaked wherever it sits.

The question is how to say "this one is a test value" without teaching the scanner to look away from a real leak.

## Decision

**Grade by the value first, then by how it is used, and never by location or comparison alone.**

1. **The value (C3, `scanners.test_value_reason`).** A body that spells out a placeholder word of four or more letters
   (`fake`, `dummy`, `sample`, `mock`, `test`…), has at most 4 distinct characters, repeats one character 6 or more times
   in a row, or counts up for 8 characters is INFO with `looks like a test value: <reason>`. A generated key is mixed,
   so none of these fire on one by chance. This needs no context, so it works in any file and in the history scan.
2. **The use (C4, `report._test_key_context`, Python files that parsed).** Four signals, named in this order: the value
   is assigned to a fake-named variable (U2); the file is a test file (L1); the innermost function or class around it
   has a placeholder word in its name (L2); the value is compared in an assert or any comparison (U1). **INFO only when
   U2 holds and at least one of U1, L1 and L2 does.** Any other combination stays FAIL: the finding names the signals
   it saw ("test signals seen: in a test file, inside test_x(), compared in an assert") and gains one line in its fix
   list telling the person how to say it is a test value (FAKE or TEST in the value, or one character repeated).

   U2 is the signal that carries intent: a person who named the variable `test_key` said what it is. L1, L2 and U1 say
   where it is and what is done with it, and a real key pasted into `tests/test_live.py` and asserted against is
   exactly the leak that matters, so none of them, alone or together, lowers a grade.
3. **History (`scan --history`).** A key shape a commit added is `secret.history` at the level and with the reason its
   hit has: FAIL, or INFO with the same `looks like a test value` line. It uses the value rule only: the scan sees one
   added line at a time, with no tree to read. `secret.history INFO` weighs 0 (the one new weight row).

The report counts the findings graded this way in `test_values_graded` (absent when none), and the text report says so,
so a person can see how many failures became information.

## Alternatives

- **Location-based** (anything under `tests/`, `fixtures/`, `examples/` is INFO). Simple and what most scanners do, and
  wrong in the way that costs most: a real key committed to `tests/test_live.py` (the usual place for one) would be
  waved through. The old rule kept key shapes out of it for this reason.
- **Value-based only** (C3 alone). Safe, and kept as step 1, but it misses a test key that was made to look real, which
  is common: `test_key = "sk-<a real-looking body>"` in a self-test. Those stayed FAIL and the scripts folder stayed
  buried.
- **Never grade** (every key shape FAIL, and tell people to rotate or rename). Honest, and the fewest rules, but a
  tool that cries wolf 206 times is not read; people switch it off or delete the baseline.

## Consequences

- **The limit, said plainly:** a real key placed in a variable called `test_key` inside a test, or in a self-test, is
  reported at INFO. Nothing in a static scan can tell it from a test value that looks real. The finding says why it is
  INFO and the README says to rotate any key that ever sat in a file; the grade is not a statement that a key is safe.
- The first thing a scan of an old project shows is shorter and more honest: FAILs that remain are values that read as
  real and are not marked as test values.
- A baseline recorded with 0.4.0 holds some of these findings at FAIL. The level is part of the fingerprint (ADR 0005),
  so they count as new until `code-guardian baseline` is run again; the README says so under Upgrading to 0.4.1.
- **A dropped rule:** the history scan used to keep only hits at FAIL, which silently dropped a key-shaped value that
  graded INFO. A value that says it is a test value is probably one, but a deleted key that was real is the case the
  history scan exists for, and a drop cannot be seen or corrected. It now keeps the INFO and its reason: it costs
  nothing in the score and nothing is hidden.
- Nothing about a finding's level can be turned on by a name alone: U2 needs a second signal, and a name is matched on
  whole words (`test_key`, `FAKE_TOKEN`, `TestClient`), so `latest_key` and `contest` do not count.
