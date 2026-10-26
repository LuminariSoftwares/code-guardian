# Changelog

## code-guardian-mcp 0.5.0 (unreleased)

JavaScript and TypeScript are now analysed, not only secret-scanned. Before, an `eval` of request input in a `.js` file went unseen and a JavaScript-only repo came out PARTIAL with Works not scored; now the Safe and Works checks run on those files at token level, and a JavaScript-only repo is COMPLETE with every score. Python reports are unchanged.

1. **JavaScript and TypeScript Safe checks.** `exec.dynamic`, `exec.shell`, `deser.unsafe`, `net.egress`, `net.bind_all`, `tls.off`, `obfuscation`, `fs.outside`, `privacy.pii_log` and the new `dom.html_sink` (an unsanitised value reaching `innerHTML`, `document.write`, React's `dangerouslySetInnerHTML`, jQuery's `.html()` or an Angular `bypassSecurityTrust` call) run on `.js .mjs .cjs .jsx .ts .tsx`, at the same levels and weights as the Python checks.
2. **JavaScript and TypeScript Works checks.** `works.syntax`, `works.import_unresolved`, `works.relative_missing`, `works.entry_missing` and `works.tests_missing`, read from the tokens and from `package.json` / `tsconfig.json`. `works.tests_missing` is reported once per repository.
3. **A reader, not a parser, and it says so.** Nothing is installed or run (no `npm`, no `node`). Each report's `coverage.languages.javascript` lists the checks that ran and the ones that did not (`privacy.pii_prompt`, `works.test_no_assert`, `works.todo_stub`, `works.commented_code`, `works.dead_flag`, orphan code). Declaration, minified and bundled files and any file with a line over 2,000 characters get the secret scan, `obfuscation` and `exec.dynamic` only. The README's Limitations says what the JSX rules see only partly and how each case is marked.

- **Inventory and status (P81 C4).** `walk.walk` gains `javascript` and `generated` lists (the JavaScript and TypeScript files stay in `other` too, so the other callers see the same inventory). `files.javascript` and `files.generated` are always present; `files.other`, `other_languages` and `coverage.other_source` no longer count `.js .mjs .cjs .jsx .ts .tsx`. `.vue`, `.svelte` and `.astro` are listed as other source. `report.scan` adds the `javascript` and `js_works` outcome rows only when the repo has such files. Status: no Python files, no JavaScript / TypeScript files and no manifests is INVALID; with neither Python nor JavaScript / TypeScript source Works is not scored and Safe is partial (PARTIAL, as before); the mixed-repo rule compares other-language source with the Python and JavaScript / TypeScript files together.
- **`schema_version` 3.** Adds `files.javascript`, `files.generated` and `coverage.languages` (`python`: files and depth `full`; `javascript`: files, generated, depth `tokens`, `checks`, `generated_checks`, `not_checked`); every earlier key keeps its meaning. `analysed` is `python`, `python+javascript` or `javascript`. The text report's coverage line reads `coverage: 40 Python analysed; 112 JavaScript/TypeScript analysed (token level); 9 .go secret-scan only`; the Markdown head and the SARIF run properties carry the same coverage. Exit codes, `gate_status`, `--fail-on`, baselines and fingerprints are unchanged.
- **Golden test (P81 C5).** `tests/test_golden.py` re-scans the eight Python-only fixtures on every change and compares them with the reports recorded before this work (`tests/golden/`), leaving out only `version`, `schema_version`, `weights` and `path`. `risky_repo` holds a `.js` file and is compared through `tests/golden/risky_repo.delta.json`: one `net.egress` INFO at `web/setup.js:1`, the file moved out of `other`, the two new outcome rows and `analysed: python+javascript`; its scores, status and hygiene are asserted unchanged.
- **CI (P81 C10).** The JavaScript-only repo job now expects `COMPLETE`, exit code 1, `exec.dynamic FAIL src/index.js:2`, Works scored and `coverage.languages.javascript.depth == "tokens"`; the wheel job also scans the JavaScript risky fixture from the installed wheel.
- **Plainer "What was checked" (P81 S5b).** The page lists in plain words what was and was not looked at in JavaScript / TypeScript, and the depth label reads "line by line".
- **Advice in the file's language (P81 S5b).** A finding in a JavaScript / TypeScript file gets JavaScript advice (`catalogue.FIX_JS`, `catalogue.fix_for`), on the finding card, the Fix first screen and the MCP fix plan.
- **Docs.** ADR [0011](docs/adr/0011-javascript-typescript-at-token-level.md); the README's "What it analyses", "Scan status", "JSON shape", Safe and Works checks, "Check catalogue" and "Limitations".

### Upgrading to 0.5.0

**What is analysed now that was not.** JavaScript and TypeScript at token level, with the checks listed above. Python-only repos see only the additive `schema_version` 3 keys.

**The exit code can change.** A JavaScript or TypeScript finding at or above `--fail-on` exits 1. A repo that passed the GitHub Action on 0.4.x can exit 1 on 0.5.0 without a line of its code changing: this repository's own CI job for a JavaScript-only repo (an `eval` of request input) went from PARTIAL with exit 0 to COMPLETE with exit 1.

**The gradual path.** Record the current state once, on 0.5.0, and fail only on what is new:

```
code-guardian baseline .
code-guardian scan . --baseline code-guardian.baseline.json
```

A baseline written by 0.4.x lacks the JavaScript and TypeScript findings, so every one counts as new until it is written again on 0.5.0. Or raise the bar while the backlog is worked: `code-guardian scan . --fail-on FAIL` (the default), then `--fail-on WARN` once the FAILs are fixed. In the GitHub Action these are the `baseline:` and `fail-on:` inputs. Scores and grade always count every finding; a baseline changes only the exit code.

## code-guardian-mcp 0.4.2 (2026-10-25)

The backup offer now counts exactly what leaving it out would skip, and releases are now published from GitHub with a signed record of where they came from.

1. **The offer's numbers are exact.** On a real folder the page offered `*.backup-*` as 48 files while leaving it out skipped 177, and a glob such as `*.pre-*` also dropped dot files like `.pre-commit-config.yaml` whose findings were never counted or checked. Each file and finding is now counted once, under the first offered glob that drops it, so leaving out everything on offer skips exactly the files and findings the offer says.
2. **Releases are published by GitHub, with provenance.** Publishing a GitHub Release runs `.github/workflows/release.yml`, which builds the package, checks it, and uploads it to PyPI by trusted publishing: no PyPI token is stored anywhere, and the upload carries an attestation pointing at the commit. Steps for the owner: [docs/RELEASING.md](docs/RELEASING.md).

- **Exact attribution (P93 C1).** `backups.offer` orders its candidate globs folder globs first, then by findings dropped, then by glob; every inventory path (python, manifests, other, skipped) and every finding is counted under the first candidate whose glob drops it (`walk._excluded`, the rule `--exclude` applies). `files`, `findings`, `by_code` and `fail` count what is counted under a glob, and the held check (imports, `install.hook` at any level, `obfuscation` / `exec.dynamic` / `exec.shell` at FAIL) looks at those findings, so a risky dot file that a mark glob would drop holds that glob back. The offered list is sorted by findings, then glob. The return shape is unchanged: `ui.py`, `plain.py` and the page needed no change.
- **Trusted publishing (P93 C2).** `release.yml` runs on `release: published`, on `workflow_dispatch` with a `dry_run` input (default on) and on pull requests that change it or `pyproject.toml`. Its build job checks the tag equals `v` plus `pyproject.toml`'s version, then runs `python -m build` and `twine check --strict`; the one publishing job runs in the `pypi` environment with `id-token: write` and `attestations: true`. Every action is pinned to a full commit SHA.

## code-guardian-mcp 0.4.1 (2026-10-25)

Two changes, both about findings that are real but not the ones that matter.

1. **Backup folders can be left out of a check, but only when you say so.** Projects written with AI collect copies (`_archive/`, `old/`, `main.py.backup-20260824`), and their findings can bury the ones in the code you run. You can now leave a folder out with `--exclude`, and the report says exactly what it left out. code-guardian never does it by itself: the page offers it with one button (**Check again without them**) and says afterwards what was left out, with **Put them back**. It holds back, with the reason, any copy the rest of the project imports or that carries a risk that runs code.
2. **A key-shaped value that says it is a test value is information, not a failure.** A value whose body spells out `fake`, `dummy` or `sample`, or is one character repeated, is INFO. So is a value assigned to a fake-named variable (`test_key`, `FAKE_TOKEN`) that also sits in a test file, inside a test function, or in an assert. A real-looking key in a test file with no such sign is still a FAIL, now with the signs it showed and one line on how to mark a test value as one. Where a file sits never grades a key on its own.

- **Leave-out plumbing (P88 S1).** `code_guardian/backups.py` names backup copies (`_archive/`, `old/`, `pkg/_backups/`, `*.backup-*`, `*.bak`, `tmp`, `scratch`, `to_delete*`, `*.pre-*` and similar) and decides which may be offered: a copy needs at least one finding, must not be imported by kept code, and must hold no `install.hook` finding and no `obfuscation` / `exec.dynamic` / `exec.shell` FAIL. A kept file that only names the folder in a string is shown as a caution and does not hold it. `scan`, `baseline`, `plan` and `orphans` take a repeatable `--exclude GLOB`; `report.scan(..., exclude=())` and `report.orphans(..., exclude=())` leave the globs out after the goal file's and add `excluded_by_request` and a note (the text report's files line reads "N left out at your request"); `POST /api/scan` takes `exclude` and answers with the `backup_offer` beside the report. With no `--exclude`, nothing changes. The CLI now writes UTF-8 to a pipe on Windows.
- **The page (P88 S2).** After a check, a banner says how many findings sit in backup-looking folders and offers **Check again without them**; copies that cannot be offered are listed with the reason, copies that kept files only name get a caution line naming those files, the result says **Left out at your request** with **Put them back**, and the summary says how many key-shaped values were graded as test values, with a link to them.
- **Test values graded by the value (P88 S3).** `scanners.test_value_reason` (V1: the body spells out a placeholder word of four or more letters; V2: at most 4 distinct characters, a run of 6 or more of one, or 8 characters counting up). A key-shaped hit with a reason is INFO with `looks like a test value: <reason>`; a real-shaped one stays FAIL. `secret.history` takes the level and reason of the hit instead of dropping it, so a test value in history is INFO (it weighs 0, like every INFO finding).
- **Test values graded by their use (P88 S4).** `report._test_key_context` reads a key-shaped FAIL in a parsed Python file by four signals, always named in this order: assigned to a fake-named variable (U2), in a test file (L1), inside a test or fake function (L2), compared in an assert (U1). INFO only when U2 and at least one other hold; any signals without U2, or U2 alone, stay FAIL with `test signals seen: ...` in the evidence and the hint *if this is a test value, make it say so (FAKE or TEST in the value, or one character repeated, like 000000) and it is reported as information* in the fix list. The report gains `test_values_graded` (the number of `secret.key` INFO findings that look like test values; absent when none) and the text report says the same in a sentence. Docs: [ADR 0010](docs/adr/0010-test-values-are-graded-by-value-and-use.md), the README's "Backup copies" and key-shaped-values sections, `--exclude` in the options table, and a calibration section.
- **Upgrading.** A baseline recorded with 0.4.0 may hold `secret.key` findings that 0.4.1 reports at INFO (the level is part of the fingerprint): re-record it with `code-guardian baseline`.
- **Known limit.** A real key placed in a variable called `test_key` inside a test is reported at INFO. Rotate any key that ever sat in a file.

## code-guardian-mcp 0.4.0 (2026-10-23)

You can now check a project folder in your browser (`code-guardian ui`): every file is listed with an honest label, you can save a check and compare two, and it works in light or dark on any screen size, phone included.
Nothing leaves your computer: the page talks only to the program running on your own machine, and the one thing that can go further is the lines you pick for an AI explanation, sent only to a model you set up yourself.

- **Save this check (P76 S6b).** A button on the Summary screen saves the current check as a file through the browser (nothing is written by the server), so **Open a saved check** and the two-file **Compare** no longer need the command line; their command-line wording is folded into a "Using the command line?" detail.
- **The app, v1.1 (P78).** Six changes to `code-guardian ui`, each said in plain words first and then in detail. The
  README's [The app](README.md#the-app) section describes them for someone who uses AI to write code but does not
  read code well.
  - **Settings** (S1): you can choose a dark or light look, a larger text size and whether the Luminari name shows,
    and the browser remembers the choice. A gear at the top of every screen opens a panel with three choices,
    **Theme** (Dark or Light), **Text size** (Normal, Larger, Largest) and whether the Luminari name shows at the
    top. They are kept by the browser itself (`localStorage`, one key), not in a file on the machine and not by the
    server; the page never follows the system's light/dark setting, so dark stays the default and light is a choice.
    Both palettes pass the contrast gate: `python tools/contrast_check.py code_guardian/ui/app.css` now checks every
    palette and prints `ok: 88 pairs in 2 palettes`. The Luminari name is a plain link in the header with an empty
    slot for its mark. So that the browser keeps the settings across restarts, the page now listens on a stable
    address: with no `--port` it takes the first free port from 8765 to 8775, then any free port (`--port N` and
    `--port 0` are unchanged). On Linux and macOS the listener sets `SO_REUSEADDR`, so a restart within a minute gets
    the same port back instead of the next one; on Windows it stays off, where it would let another process take the
    port. `ui.make_server()` takes `port=None` for the walk (`port=0` is still any free port). See
    [ADR 0008](docs/adr/0008-settings-live-in-the-browser.md).
  - **Sizes** (S2): every screen fits a phone, a narrow side window and a full or wide screen, at every text size,
    with nothing cut off. Four width tiers (phone under 600 px, side window 600-899, full 900 and up, wide 1280 and
    up); the summary rail is a one-line strip under 900 px (tap it for the harm label, Safe, Fix first and Check
    again) and a column from 900 px that **Hide summary** shrinks to a slim icon rail (the choice is kept in
    `localStorage["cg.rail"]`); the tabs are one row that scrolls sideways inside itself on a phone; on Code the file
    list is a drawer under 900 px and, from 1280 px, the explain panel gets its own right-hand column; the Compare
    pickers sit side by side from 900 px. Widths that hold text are `rem` or `clamp()` so they grow with the text
    size. `tools/ui_screenshots.py` now also writes the 520 px shots and `rail_mini_1280x800.png`.
  - **Every file** (S3): the Code screen lists every file the check saw, each with one honest word, and a file that
    was not really read is never shown as having no known risks. A filter (**All files**, **Files with findings**,
    **No known risks found**, **Partly checked**, **Not read**, each with its count) and a find box. Each file gets
    one word: High, Medium or Low from its Safe findings; **No known risks found** only for a Python file that fully
    parsed or a manifest; **Partly checked** for a source file in a language this tool does not analyse yet or a
    Python file that did not parse (the row says which); **Not read** for a binary, a symlink, an unreadable or a
    too-large file. New `GET /api/files?id=` and `plain.file_rows()`; the server walks the folder with the scan's own
    goal-file excludes just before it scans, so the list is the files the scan saw. At most 2,000 rows are drawn at
    once. Also: a quiet edge fade on the tab row when it scrolls, the picked file's name drawn once on a phone, the
    two line fields on one line, and a code viewer of at least 34rem at 1280 px with the summary open.
  - **Browse and the refusals** (S4): a **Browse…** button picks the folder with the computer's own folder window,
    and folders too big to be one project (a whole drive, your home folder, Downloads and the like) are refused
    before anything is read. The folder window is tkinter, in a child process, one at a time (new
    `POST /api/browse`). A folder nobody should check as a whole (a drive, the home folder or a folder above it,
    Downloads, Desktop, Documents, the OneDrive root, system folders) is refused with one plain sentence under the
    field: for the folder Browse picks, a typed path (`POST /api/scan` answers `400 refused`) and
    `code-guardian ui PATH` (exit 2). `code-guardian scan` is unchanged. A Python with no folder window hides Browse
    for the session and says to paste the path. `code-guardian ui --port N` on a taken port now exits 2 with one
    line instead of a traceback. See [ADR 0009](docs/adr/0009-folder-dialog-refusals-reopen-loopback.md).
  - **Re-open vs Check again** (S5): opening the page again or picking an earlier check shows it from memory without
    reading the folder again. Only **Check again**, the Open form, Browse and
    `code-guardian ui PATH` read files (the button says so: "Reads the files again now"). New `GET /api/scan?id=`
    (the stored result, with its file list) and `POST /api/open` with an **Open a saved check** button for a
    `scan --json` file; a saved check has no folder behind it, so the Code screen says so and its file controls are
    off, and Check again reads the folder it names only if it is still on this computer. The summary rail now reads
    "Checked at" and the time in the browser's own format, such as "Checked at 02:05 PM" ("Saved check from PATH"
    for a saved one). A report that leaves the last 20 now also drops its file list.
  - **From a phone, and the README** (S6): the README's The app section now describes the five changes above, with
    four screenshots, and how to look at the page from a phone. The phone section documents one way that works: an
    SSH tunnel with the same port number on both ends (the port in the printed link, usually 8765), because the page
    still listens only on 127.0.0.1 and answers only to `127.0.0.1` or `localhost` at its own port. Tailscale Serve,
    and any other proxy that passes on its own address, is not supported yet: the page refuses it. Documentation
    only; nothing in the code changed.
- `code-guardian ui`, before / after (P76 S5): the Compare tab. Fix something, press **Check again**, open Compare: it shows one sentence first ("1 fixed, 0 new, grade D → B"), the score change per dimension, and three lists, **Fixed**, **New** and **Still there**, each item with its level word, title and where it is; a new High finding is marked "New High" in words as well as colour. You can pick any two checks of the session or load two files saved with `scan --json`; the files are read in the browser and compared by the local server, never uploaded. New `POST /api/diff` (two check ids, or the text of two saved reports; it returns `verify.diff` unchanged plus `sentence`) and `plain.diff_sentence()`; the server keeps the last 20 finished reports for comparing.
- `plain.py` copy: on a PARTIAL scan the Overall sentence says "PARTIAL" once (the cap reason already says it, so the "did not cover the whole project" clause is left out); the Fix first notes get one plain sentence above them when Safe is at its floor ("Safety problems do not raise the grade until most of them are fixed, so they can show +0 here. Fix them first anyway."), and the scanner's note stays word for word under it (`/api/scan` carries it as `plain.fix_first_lead`).
- `code-guardian ui`, select-to-explain (P76 S4): on the Code screen, drag some lines or type a start and an end line (at most 200; the two fields fill each other) and ask your own model what they do. Before anything is sent the panel says "These N lines go to your model at HOST:PORT (MODEL). Nothing else is sent." and waits for a confirmation; with no model configured it shows the one setup step instead and sends nothing. The answer sits under "AI explanation — may be wrong; does not change any score" and never changes a grade, a label or a finding. New `explain.excerpt()` and `POST /api/explain` (the model settings are read from the environment on each request); `scan --explain` and the MCP `explain` tool are unchanged and still send findings only. The note for a model that does not answer now leaves out any user:password in the URL.
- `code-guardian ui`, the owner's first design reaction (P76 S3b): a summary rail on every tab (grade, how worried to be, Safe, how many fixes, finding counts) beside the screen on a wide window and as a strip under the tabs on a phone; a **Check again** button that re-scans the same folder on demand (never on a timer) and redraws every tab; the scan's own notes on its ranking above the Fix first list (such as "a Safe FAIL caps the grade at D"; `/api/scan` now carries `plain.fix_first_notes`); notes under flagged lines in the Code viewer open to the finding's why and what to do; "Go to line" sits on the file name's row. "No known risks found" is now a neutral grey (`--none`) with an outlined circle, never green: it is not an all clear.
- `plain.py` copy: an em dash instead of ` -- `; the "from a scan that did not cover the whole project" clause is said once, on the Overall sentence, not on all four; a Python line with no files says there was no Python to check instead of "ran on these".

- `code_guardian/plain.py`: a plain-language layer over a scan report -- a five-label harm level, one sentence per score, what was and was not checked, a card per finding and the fix-first list, in words for a reader who does not write code. It reads the report and changes nothing in it; the scores and findings are unchanged ([ADR 0007](docs/adr/0007-plain-language-layer-never-scores.md)).

## code-guardian 0.3.4 (2026-10-22)

Review fixes (external review triage, 2026-10-21). One behaviour change in the scanner (URL credentials are
redacted); otherwise the scores, findings and CLI behave as in 0.3.2.

This also brings the version strings on `main` back in line with what is released: the `v0.3.3` tag carries
`0.3.3`, but it sits on a hotfix branch that was never merged, so `main` still reported `0.3.2` from
`code-guardian --version`, the MCP `serverInfo.version`, a report's `version` field and `server.json`. All of them
now say `0.3.4`.

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
- **The test harness no longer leaves a thread running after a test** (`tests/conftest.py`). The stub HTTP server
  the timeout tests use left a daemon handler thread asleep in its route delay after the client had given up; that
  thread then wrote a socketserver traceback to stderr for a socket nobody was reading, and a thread writing to
  stderr while CPython finalises aborts the process (`Fatal Python error: _enter_buffered_busy`, exit code 134) —
  after the suite had already reported every test passed. The delay is now interruptible, handler threads are
  joined by `close()`, and a client hanging up is recorded instead of printed, with anything unexpected failing
  the test that caused it (`tests/test_stub_server.py`). No change to code-guardian itself.

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
