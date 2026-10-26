# 0011. JavaScript and TypeScript are analysed at token level, in the standard library

Status: accepted (0.5.0, plan P81 section 4). Recorded 2026-10-26.

## Context

Until 0.4.2 only Python was analysed. Every other language got the secret scan and the repo-hygiene checks, and the
report said so in its `coverage:` line, but the consequence was easy to miss. This repository's own CI had a job that
scanned a small JavaScript-only repo whose one source line was `r.send(eval(q.query.x))`: the scan finished PARTIAL
with exit code 0, because coverage alone never fails the gate and the eval was invisible. A tool whose question is "is
this safe to run?" gave a pass to the most recognisable injection in the language that most AI-written web code is in.

Two constraints from earlier decisions bound the answer. A scan must never run, import or install what it reads
([ADR 0001](0001-static-analysis-stdlib-only.md)), and the package has no dependencies, so a person auditing it audits
one wheel of standard-library Python. And the scores must stay deterministic and fixed-weight
([ADR 0002](0002-deterministic-fixed-weight-scoring.md)).

## Decision

**Read JavaScript and TypeScript with a hand-written lexer (`jsts.py`) and run small checks over the token list
(`scanners_js.py`, `works_js.py`). Report the depth honestly.**

1. **A lexer, not a parser.** `jsts.tokenize` cuts a file into names, keywords, numbers, strings, template literals,
   comments, regular expressions, punctuation and JSX text, well enough that a sink named inside a string, a template, a
   comment or a regex is never mistaken for code. The checks read call sites, imports, assignments and object-literal
   properties off the tokens, one statement deep. Nothing is followed between statements or functions, and there is no
   scope, type or module-resolution analysis beyond `package.json` and `tsconfig.json`.
2. **The depth vocabulary.** Each language in `coverage.languages` carries a depth: `full` (Python: the parse tree),
   `tokens` (JavaScript and TypeScript) and, for every other source language, the secret scan only (they appear in
   `coverage.other_source`, not under `languages`). `tokens` is a claim about the method, not about quality: the report
   also lists the checks that ran and the ones that did not (`checks`, `not_checked`).
3. **Generated files are treated as such.** Declaration files, minified and bundled files and any file with a line over
   2,000 characters in its first 8 KB are counted separately (`files.generated`) and get the secret scan, `obfuscation`
   and `exec.dynamic` only, with an `exec.dynamic` WARN reported at INFO. A lexer reading minified output finds noise,
   not intent, and its Works checks (imports that resolve through a bundler) would be wrong by construction.
4. **Where a case cannot be told apart, mark it, never drop it.** JSX text can hold an apostrophe or a backtick that is
   not the start of a string or a template. A `{...}` between two apostrophes on one line is reported as `code-like text
   inside JSX text was not analysed` (an INFO, no grade change); code after a stray backtick is lexed again and found,
   and its evidence says `after a stray backtick in JSX text`.
5. **Code reuse.** `scanners_js.py` imports the secret-name rule, the blob thresholds, the outside-path rule, the egress
   classifier and the URL redaction from `scanners.py` instead of copying them, so the two languages cannot drift apart.
   `scanners.py` and `works.py` are untouched. `dom.html_sink` is the one Safe code with no Python counterpart (the
   browser sinks are a JavaScript matter); `privacy.pii_prompt`, `works.test_no_assert`, `works.todo_stub`,
   `works.commented_code`, `works.dead_flag` and orphan (dead) code are not ported, and each report says so.
6. **The golden guarantee.** `tests/test_golden.py` re-scans every Python-only fixture on every change and compares the
   whole report with the one recorded from `main` before any JavaScript work (`tests/golden/`). Every key in the golden
   must have the identical value, recursively, and a new key is allowed only if it is on a short list (`files.javascript`,
   `files.generated`, `coverage.languages`). Four top-level keys are left out of the comparison and nothing else:
   `version` (changes every release), `schema_version` (bumped on purpose, to 3), `weights` (in every report and pinned
   by `test_readme_sync` and `test_scoring`) and `path` (the scanned location, different on every machine). `risky_repo`
   holds one `.js` file, so it is compared after a reviewed delta (`tests/golden/risky_repo.delta.json`); `scores`,
   `status` and `hygiene` are asserted unchanged, literally, never through a delta. So "no Python result changed" is a
   test that fails, not a sentence in a changelog.

## Alternatives

- **Leave JavaScript secret-scanned only** and make the PARTIAL status louder. Costs nothing and claims nothing, and
  leaves the CI job above passing on an `eval` of request input. The coverage line already said so and it was not enough:
  a status that is "fine" on exit code 0 is read as fine.
- **A real parser, through a dependency.** Tree-sitter grammars (or `acorn` / `esprima` through `node`) give scope and a
  full syntax tree. They also give up the zero-dependency install (a compiled extension per platform, or a second runtime
  on the scanning machine), and running `node` or `npm` from a scan reads as running the scanned project's ecosystem, which
  ADR 0001 rules out. Rejected for 0.5.0.
- **A real parser, written here.** A JavaScript and TypeScript grammar in the standard library is a project of its own,
  with the churn of two languages and JSX; a bug there silently drops findings. A lexer is small enough to test
  exhaustively and fails in a known direction (it misses a flow, it does not invent one).

## Consequences

- **JavaScript findings can change an exit code.** A repo that passed the Action on 0.4.x can exit 1 on 0.5.0. The README
  and the changelog say so under "Upgrading to 0.5.0" and give the gradual path: `code-guardian baseline`, then
  `scan --baseline`, or `--fail-on` raised while the backlog is worked.
- **A grade is still "nothing the scanners recognise".** A value that reaches a sink through another statement, a call or
  an alias is not seen; the README's Limitations says so for JavaScript and TypeScript the way it does for Python.
- **What is explicitly not claimed.** No data-flow, scope or type analysis; no claim that a finding is exploitable; no
  claim of recall beyond what [calibration.md](../../calibration.md) measures (a small, hand-judged sample on five pinned
  repositories, with the OWASP Juice Shop marker recall and lexer-loss reported separately and never summed); no claim
  that `tokens` is as deep as `full`; nothing about Vue, Svelte or Astro single-file components, which are secret-scanned.
- **Parked: a tree-sitter extra.** If a parser is ever added it is an optional extra (`pip install` of a separate extra),
  off by default, and the lexer stays the default and the fallback, so a plain install keeps its guarantees. The signal to
  revisit is calibration: a lexer-loss on Juice Shop, or a false-negative a reviewer can show, that a grammar would not
  have, or a user report of a missed one-statement-deep flow that the token list cannot express.
