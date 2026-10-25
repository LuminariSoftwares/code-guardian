# Calibration

code-guardian 0.2.0 scanned at pinned commits of five well-known, clean Python projects and the four
LuminariSoftwares guardian repositories. The rule: every Safe FAIL on a clean repo is fixed in the check or justified
here. After the fixes listed below there are **no FAIL findings on any of the nine repositories**; every WARN is
listed with its verdict.

Reproduce with `python tools/calibrate.py` (it fetches each repository at the pinned commit and scans it offline).
Scores are offline (no `--online`), so they are reproducible.

| repo | commit | Safe | Works | Complete | Overall | grade | FAIL | WARN |
|---|---|---:|---:|---:|---:|---|---:|---:|
| [psf/requests](https://github.com/psf/requests) | `611c6162cbc4` | 90 | 89 | 95 | 91 | A | 0 | 6 |
| [pallets/click](https://github.com/pallets/click) | `2247b35ea1c4` | 90 | 92 | 95 | 92 | A | 0 | 5 |
| [Textualize/rich](https://github.com/Textualize/rich) | `9d8f9a372cc5` | 77 | 71 | 90 | 78 | B | 0 | 21 |
| [encode/httpx](https://github.com/encode/httpx) | `b5addb64f016` | 85 | 95 | 100 | 91 | A | 0 | 4 |
| [pallets/flask](https://github.com/pallets/flask) | `d086db856be1` | 80 | 95 | 95 | 88 | B | 0 | 8 |
| [LuminariSoftwares/stack-guardian](https://github.com/LuminariSoftwares/stack-guardian) | `9561a8f58e69` | 93 | 95 | 100 | 95 | A | 0 | 3 |
| [LuminariSoftwares/context-guardian](https://github.com/LuminariSoftwares/context-guardian) | `ad7aebc67476` | 96 | 84 | 90 | 91 | A | 0 | 8 |
| [LuminariSoftwares/tool-guardian](https://github.com/LuminariSoftwares/tool-guardian) | `3fd93288716a` | 90 | 100 | 100 | 95 | A | 0 | 1 |
| [LuminariSoftwares/code-guardian](https://github.com/LuminariSoftwares/code-guardian) | `this release` | 100 | 100 | 100 | 100 | A | 0 | 0 |

Full commits: requests `611c6162cbc4ac2020a2f91c7cfa4f3abf9bbb60`, click `2247b35ea1c47c727d7a06e51fa280e12a863ff6`, rich `9d8f9a372cc5916fd4781fec207ced7ddac2f08f`, httpx `b5addb64f0161ff6bfe94c124ef76f6a1fba5254`, flask `d086db856be187255b8ec61ef409357393020f32`, stack-guardian `9561a8f58e696f978c2d9f8bdda75d31a4d598b4`, context-guardian `ad7aebc67476c9a5cfe294c62a782813dbbef21d`, tool-guardian `3fd93288716ab5a83ed89b0d942f586eec253638`

## What calibration changed

The first run graded requests F, flask F, httpx D and click D, with Safe FAILs in requests, httpx and flask. Each pattern below
was reproduced in a small test (`tests/test_calibration.py`, red before the fix, green after) and fixed in the check:

| pattern seen | where | fix |
|---|---|---|
| Test credentials, test certificates, `verify=False` and pickle in tests counted as Safe FAIL/WARN | requests, httpx, flask | Safe findings in test code and documentation are reported at INFO, except API-key shapes and exec of decoded data, which stay as they are |
| `password="secret"` in documentation samples | httpx docs | same rule (documentation); a value that only names its field (`secret`, `password`) is a placeholder |
| TLS switched off only when the caller passes `verify=False` | httpx `_config.py` | `tls.off` is WARN when it sits under an `if` on a function parameter; FAIL only when hard-coded |
| The RFC 3986 alphabet read as a high-entropy secret | requests `utils.py` | a literal whose characters are all distinct is an alphabet, not a token |
| `if has_simplejson: from simplejson import ...` | requests `compat.py` | a flag set inside an import-guarded `try` guards imports too |
| Example sub-projects' `[project.scripts]` resolved from the repo root | click `examples/*/pyproject.toml` (10 FAILs) | scripts resolve next to the manifest that declares them |
| Imports of modules a test writes at runtime, docs-build imports | flask, click, httpx tests and docs | `works.import_unresolved` checks product code only (not tests, not `docs/`) |
| `.env.example` asked of every library that reads `NO_COLOR` | all nine repos | `complete.env_example` applies to applications only (the lockfile rule's markers) |
| `@pytest.fixture def test_apps()` counted as a test | flask `conftest.py` | fixture-decorated functions are not tests |
| XML namespace `http://www.w3.org/2000/svg` counted as egress | rich | namespace hosts are INFO |
| Public library API reported as dead code | requests, httpx, click, flask | for a library, the public API and its re-exports count as entry points |
| `from ._client import *`, `try: import / except: def`, a property getter and setter, module `__getattr__`, `@app.post` handlers | httpx, click, flask, context-guardian | star re-exports and both bindings are followed; same-name defs are merged; module dunders and registered handlers are reached with their module |

## Re-run: provider key shapes and tainted eval/exec

Added after the first calibration: AWS, Stripe, Slack and Hugging Face key shapes, the AWS secret-key rule,
high-entropy `*_KEY` / `*_TOKEN` literals, and `exec.dynamic` FAIL when `eval` or `exec` runs input. The re-run
scanned the same commits. The score table above did not change, and every finding at every level (1,752 across the
eight external repos) is identical before and after. Nothing new is reported, not even at INFO. code-guardian's own
scan stays at 100.

One pattern was caught on the way and fixed before the re-run (`tests/test_safe_gaps.py`, red before the fix, green
after):

| pattern seen | where | fix |
|---|---|---|
| `eval(compile(f.read(), startup, "exec"))` where `startup` is `os.environ.get("PYTHONSTARTUP")` read as "runs code typed by the user" | flask `src/flask/cli.py:1022` (Safe 80 → 50, grade B → D) | only the code text is checked for taint: `compile()`'s filename argument is not code. The line stays WARN |

## Re-run for 0.3: AI leftovers and privacy

0.3.0 adds `works.todo_stub` (WARN 3), `works.commented_code` (INFO), `works.dead_flag` (INFO), `privacy.pii_log`
(Safe WARN 5) and `privacy.pii_prompt` (Safe WARN 5). The scan status, locations, redaction, fingerprints and the
opt-in `--history` change no score: before these checks the table was byte-identical to 0.2.0, and all nine repos
scan COMPLETE.

**No new FAIL anywhere.** The first run added 14 `works.todo_stub` WARNs across requests, click, rich and flask.
Thirteen were deliberate no-ops and were fixed in the check (`tests/test_leftovers.py::
test_calibration_patterns_are_not_stubs`, red before the fix, green after); one is justified below. The privacy checks
and the two INFO checks report nothing on the nine repos, at any level: no personal-data name reaches a log, a print
or a prompt, no module-level boolean flag is unread, and none of the 163 comment runs of 5+ lines parses as code.

| pattern seen | where | fix |
|---|---|---|
| `class SupportsRead(Protocol[T]): def read(self) -> T: ...` | requests `_types.py` (2), flask `globals.py` | a `Protocol[T]` base is a Protocol |
| `def __exit__(self, *a): pass`, `def __enter__(self): pass` | click `utils.py`, flask `helpers.py` | dunder methods are protocol no-ops |
| `class NullFile: def flush(self): pass`, `class MockRequest: def add_header(...): raise NotImplementedError(...)` | rich `_null_file.py` (4), requests `cookies.py` | methods of null objects (`Null*`, `Noop*`, `Dummy*`, `Mock*`, `Fake*`) |
| `@click.group() def cli(): pass` | click `examples/` (3) | a `@group` callback does its work in its subcommands |

The score table above changed in one row: requests Works 92 → 89, Overall 92 → 91 (still A), from the one
justified WARN.

## Every FAIL and WARN

### psf/requests

| level | check | where | verdict | why |
|---|---|---|---|---|
| WARN | `complete.readme_sections` | `README.md:1` | true (rule) | the README has no heading of that kind; the information may sit in text or external docs |
| WARN | `exec.dynamic` | `src/requests/packages.py:9` | true | the vendored-alias shim imports modules by computed name on purpose |
| WARN | `works.todo_stub` | `src/requests/adapters.py:599` | true (rule) | `HTTPAdapter.add_headers` is a documented hook ("does nothing by default, but is left for overriding by users that subclass"); the subclasses live in users' code, which the scan cannot see |
| WARN | `works.test_no_assert` | `tests/test_packages.py:4` | true | smoke tests that rely on no exception being raised |
| WARN | `works.test_no_assert` | `tests/test_requests.py:87` | true | smoke tests that rely on no exception being raised |
| WARN | `works.test_no_assert` | `tests/test_testserver.py:63` | true | smoke tests that rely on no exception being raised |

### pallets/click

| level | check | where | verdict | why |
|---|---|---|---|---|
| WARN | `complete.readme_sections` | `README.md:1` | true (rule) | the README has no heading of that kind; the information may sit in text or external docs |
| WARN | `exec.dynamic` | `examples/complex/complex/cli.py:42` | true | example plugin loader; examples are not excluded from Safe |
| WARN | `works.test_no_assert` | `tests/test_deprecations.py:98` | true | smoke tests that rely on no exception being raised |
| WARN | `works.test_no_assert` | `tests/test_utils/test_echo.py:46` | true | smoke tests that rely on no exception being raised |
| WARN | `works.test_no_assert` | `tests/test_utils/test_open_file.py:67` | true | smoke tests that rely on no exception being raised |

### Textualize/rich

| level | check | where | verdict | why |
|---|---|---|---|---|
| WARN | `complete.env_example` | `rich/_unicode_data/__init__.py:67` | true (rule) | rich has a `python -m rich` demo `__main__.py` and no `[project.scripts]`, so the brief's application rule classifies it as an application; it reads optional variables (COLUMNS, NO_COLOR) |
| WARN | `works.import_unresolved` | `rich/pretty.py:228` | true | IPython is imported only when rich runs inside IPython; it is not declared |
| WARN | `deser.unsafe` | `rich/style.py:475` | true | pickle round-trip of rich's own Style objects; WARN by rule |
| WARN | `works.test_no_assert` | `tests/test_align.py:29` | true | smoke tests that rely on no exception being raised |
| WARN | `works.test_no_assert` | `tests/test_bar.py:50` | true | smoke tests that rely on no exception being raised |
| WARN | `works.test_no_assert` | `tests/test_block_bar.py:40` | true | smoke tests that rely on no exception being raised |
| WARN | `works.test_no_assert` | `tests/test_console.py:352` | true | smoke tests that rely on no exception being raised |
| WARN | `works.test_no_assert` | `tests/test_live.py:116` | true | smoke tests that rely on no exception being raised |
| WARN | `works.test_no_assert` | `tests/test_style.py:165` | true | smoke tests that rely on no exception being raised |
| WARN | `works.test_no_assert` | `tests/test_text.py:1006` | true | smoke tests that rely on no exception being raised |
| WARN | `works.test_no_assert` | `tests/test_unicode_data.py:8` | true | smoke tests that rely on no exception being raised |
| WARN | `works.import_unresolved` | `tools/make_width_tables.py:4` | true | a maintainer script imports a package the project does not declare |
| WARN | `exec.shell` | `tools/make_width_tables.py:22` | true | a maintainer script runs fixed shell commands |
| WARN | `exec.shell` | `tools/make_width_tables.py:53` | true | a maintainer script runs fixed shell commands |
| WARN | `orphan.dead` | `rich/_extension.py:4` | consequence | rich is classified as an application (see env_example), so its public API is not counted as entry points; these are public names or IPython hooks a consumer may use |
| WARN | `orphan.dead` | `rich/errors.py:17` | consequence | rich is classified as an application (see env_example), so its public API is not counted as entry points; these are public names or IPython hooks a consumer may use |
| WARN | `orphan.dead` | `rich/errors.py:29` | consequence | rich is classified as an application (see env_example), so its public API is not counted as entry points; these are public names or IPython hooks a consumer may use |
| WARN | `orphan.dead` | `rich/jupyter.py:25` | consequence | rich is classified as an application (see env_example), so its public API is not counted as entry points; these are public names or IPython hooks a consumer may use |
| WARN | `orphan.dead` | `rich/jupyter.py:41` | consequence | rich is classified as an application (see env_example), so its public API is not counted as entry points; these are public names or IPython hooks a consumer may use |
| WARN | `orphan.dead` | `rich/markdown.py:128` | consequence | rich is classified as an application (see env_example), so its public API is not counted as entry points; these are public names or IPython hooks a consumer may use |
| WARN | `orphan.dead` | `rich/prompt.py:328` | consequence | rich is classified as an application (see env_example), so its public API is not counted as entry points; these are public names or IPython hooks a consumer may use |

### encode/httpx

| level | check | where | verdict | why |
|---|---|---|---|---|
| WARN | `tls.off` | `httpx/_config.py:43` | true (WARN) | httpx implements its callers' `verify=False`: the code runs only under `elif verify is False:` (was FAIL before calibration) |
| WARN | `tls.off` | `httpx/_config.py:44` | true (WARN) | httpx implements its callers' `verify=False`: the code runs only under `elif verify is False:` (was FAIL before calibration) |
| WARN | `net.egress` | `httpx/_utils.py:44` | true (rule) | plain-http URL to a host chosen at runtime (a local server or proxy address) |
| WARN | `works.test_no_assert` | `tests/client/test_proxies.py:104` | true | smoke tests that rely on no exception being raised |

### pallets/flask

| level | check | where | verdict | why |
|---|---|---|---|---|
| WARN | `complete.readme_sections` | `README.md:1` | true (rule) | the README has no heading of that kind; the information may sit in text or external docs |
| WARN | `exec.dynamic` | `src/flask/cli.py:245` | true | app discovery (`__import__`) and the `flask shell` startup file (`eval(compile(...))`), by design |
| WARN | `exec.dynamic` | `src/flask/cli.py:1022` | true | app discovery (`__import__`) and the `flask shell` startup file (`eval(compile(...))`), by design |
| WARN | `exec.dynamic` | `src/flask/cli.py:1022` | true | app discovery (`__import__`) and the `flask shell` startup file (`eval(compile(...))`), by design |
| WARN | `exec.dynamic` | `src/flask/config.py:209` | true | `Config.from_pyfile` executes a config file the user names, by design |
| WARN | `exec.dynamic` | `src/flask/config.py:209` | true | `Config.from_pyfile` executes a config file the user names, by design |
| WARN | `exec.dynamic` | `src/flask/helpers.py:623` | true | `get_root_path` imports a module by name, by design |
| WARN | `works.test_no_assert` | `tests/test_basic.py:1631` | true | smoke tests that rely on no exception being raised |

### LuminariSoftwares/stack-guardian

| level | check | where | verdict | why |
|---|---|---|---|---|
| WARN | `net.egress` | `stack_guardian/serve.py:165` | true (rule) | plain-http URL to a host chosen at runtime (a local server or proxy address) |
| WARN | `net.bind_all` | `stack_guardian/serve.py:230` | false positive (justified) | a selftest asserts that binding 0.0.0.0 is refused; the parse cannot see the call raises |
| WARN | `works.test_no_assert` | `tests/test_examples.py:15` | true | smoke tests that rely on no exception being raised |

### LuminariSoftwares/context-guardian

| level | check | where | verdict | why |
|---|---|---|---|---|
| WARN | `complete.lockfile` | `.` | true | a FastAPI application (`context_guardian.py`) with loose requirements and no lockfile |
| WARN | `net.egress` | `cg_doctor.py:210` | true (rule) | plain-http URL to a host chosen at runtime (a local server or proxy address) |
| WARN | `net.egress` | `cg_mcp.py:96` | true (rule) | plain-http URL to a host chosen at runtime (a local server or proxy address) |
| WARN | `works.import_unresolved` | `context_guardian.py:95` | true | `starlette` is imported directly but only declared through `fastapi` (works by accident) |
| WARN | `net.egress` | `context_guardian.py:2366` | true (rule) | plain-http URL to a host chosen at runtime (a local server or proxy address) |
| WARN | `net.egress` | `examples/smoke_proxy.py:48` | true (rule) | plain-http URL to a host chosen at runtime (a local server or proxy address) |
| WARN | `works.import_unresolved` | `tools/make_dsh_demo_gif.py:9` | true | a maintainer script imports a package the project does not declare |
| WARN | `orphan.dead` | `tools/make_dsh_demo_gif.py:1` | true | a standalone maintainer script with no `__main__` block |

### LuminariSoftwares/tool-guardian

| level | check | where | verdict | why |
|---|---|---|---|---|
| WARN | `exec.dynamic` | `tool_guardian.py:84` | true | optional module imported by a computed name |

### LuminariSoftwares/code-guardian

None.

### Backup folders and test values (0.4.1)

Two changes in 0.4.1 move findings, so they are calibrated the same way: counts on a real project folder before and
after, no change on the fixtures, and no change on the five pinned repositories. The counts are written when the
section is built (P88 S5), from `cg_review.py` on the release candidate; a blank cell is not measured yet.

A real Windows scripts folder (the maintainer's own, scanned as a whole, then with its backup copies left out at the
person's request, then with test values graded):

| scan | FAIL | INFO (looks like a test value) |
|---|---:|---:|
| 0.4.0, every file | | |
| 0.4.1, backup copies left out with `--exclude` | | |
| 0.4.1, and key-shaped test values graded | | |

Fixtures and pinned repositories:

| set | what changed | result |
|---|---|---|
| the 8 fixture repos (`tests/fixtures`, `risky_repo` as built by `tests/make_risky.py`) | scan report, sha256 of the canonical JSON | 0 delta against 0.4.0 (`tests/test_p88_s4_acceptance.py`) |
| the 5 pinned 0.2.0 repos (requests, click, rich, httpx, flask) re-scanned with 0.4.1 | | no new FAIL and no FAIL moved to INFO: they carry no key shapes today, so any move would be a bug |
