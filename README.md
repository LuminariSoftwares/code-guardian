# code-guardian

[![ci](https://github.com/LuminariSoftwares/code-guardian/actions/workflows/ci.yml/badge.svg)](https://github.com/LuminariSoftwares/code-guardian/actions/workflows/ci.yml)
[![privacy](https://github.com/LuminariSoftwares/code-guardian/actions/workflows/privacy.yml/badge.svg)](https://github.com/LuminariSoftwares/code-guardian/actions/workflows/privacy.yml)

mcp-name: io.github.LuminariSoftwares/code-guardian

One command that tells you three things about any repo, without running it:

- **Safe**: is it safe to run?
- **Works**: will it work?
- **Complete**: does it have what it needs?

Each is a score out of 100 (higher is better), combined into an **Overall** score and an A–F grade. Scores come only
from deterministic checks with fixed weights: same repo, same version, same output, every time. On top of that:

- **Orphan code**: functions, classes and modules nothing reachable from the project's entry points uses, judged
  against a small goal contract.
- An optional **plain-English explanation** from a local model, which never adds, removes or rescores a finding.

It parses the code (`ast` for Python; `json`, `tomllib` and `configparser` for manifests; regular expressions for
secrets) and never executes, imports or installs it. A scan makes
no network calls. Python 3.11+, standard library only. Status: **0.2.0 is the current release.** The fourth guardian,
next to [stack-guardian](https://github.com/LuminariSoftwares/stack-guardian),
[context-guardian](https://github.com/LuminariSoftwares/context-guardian) and
[tool-guardian](https://github.com/LuminariSoftwares/tool-guardian).

## Install

```
pip install code-guardian-mcp
```

The distribution is `code-guardian-mcp` (`code-guardian` on PyPI is someone else's project); the commands are
`code-guardian` and `code-guardian-mcp`. To run the MCP server without installing anything: `uvx code-guardian-mcp mcp`.

From a clone (for the tests):

```
git clone https://github.com/LuminariSoftwares/code-guardian.git
cd code-guardian
python -m venv .venv
.venv\Scripts\activate          # Windows;  macOS/Linux: source .venv/bin/activate
pip install -e . pytest
python -m pytest -q
```

## 30-second example

`tests/fixtures/risky_repo` is a small project that trips every scanner. Its key-shaped strings are never stored in
the repository; `tests/make_risky.py` adds them to a copy at test time:

```
python tests/make_risky.py risky_repo
code-guardian scan risky_repo
```

Real output:

```
code-guardian 0.2.0  scan of risky
files: 7 Python, 3 manifests, 2 other (0 skipped, 0 excluded by the goal file)

  Safe       0/100  is it safe to run?           -237
  Works     85/100  will it work?                -15
  Complete  35/100  does it have what it needs?  -65
  Overall   33/100  grade F  (a Safe check is FAIL (exec.shell, obfuscation, secret.key, tls.off): the grade is at most D)

biggest deductions:
  -60  Safe     secret.key FAIL          x3   first at deploy/id_rsa:1
  -40  Safe     obfuscation FAIL         x1   first at risky/loader.py:7
  -30  Safe     exec.shell FAIL          x1   first at risky/runner.py:7
  -25  Safe     tls.off FAIL             x1   first at risky/network.py:11
  -23  Safe     install.hook WARN        x3   first at package.json:5

findings (6 FAIL, 19 WARN, 7 INFO; egress listed below):
  Safe:
    FAIL  secret.key    deploy/id_rsa:1  private-key block in the source; value redacted
    WARN  install.hook  package.json:5  npm postinstall script runs on install
    INFO  deps.unpinned package.json:8  dependency left-pad has no pin or upper bound
    INFO  deps.unpinned pyproject.toml:4  dependency flask has no pin or upper bound
    WARN  obfuscation   risky/loader.py:3  base64-like blob of 340 characters
    WARN  exec.dynamic  risky/loader.py:7  exec() runs code built at runtime
    FAIL  obfuscation   risky/loader.py:7  exec() runs decoded or decompressed data
    FAIL  tls.off       risky/network.py:11  TLS certificate checking is switched off (verify=False)
    WARN  net.bind_all  risky/network.py:16  binds to all interfaces (0.0.0.0)
    FAIL  exec.shell    risky/runner.py:7  os.system runs a shell command built from input, env or network
    WARN  exec.shell    risky/runner.py:11  subprocess.run(shell=True) runs a command through the shell
    WARN  exec.dynamic  risky/runner.py:15  eval() runs code built at runtime
    FAIL  secret.key    risky/settings.py:1  sk- key shape (privacy pattern 5) in the source; value redacted
    FAIL  secret.key    risky/settings.py:2  password-like literal assigned to 'password' in the source; value redacted
    WARN  obfuscation   risky/settings.py:3  high-entropy literal of 48 characters
    WARN  deser.unsafe  risky/storage.py:8  pickle.load can run code hidden in the data
    WARN  deser.unsafe  risky/storage.py:12  yaml.load without SafeLoader can build arbitrary Python objects
    WARN  fs.outside    risky/storage.py:16  writes outside the project: /tmp/risky-report.txt (absolute path)
    WARN  install.hook  setup.py:5  class PostInstall overrides the install command
    INFO  deps.unpinned setup.py:13  dependency requests has no pin or upper bound
    WARN  install.hook  setup.py:14  setup() cmdclass overrides build/install commands
  Works:
    WARN  works.tests_missing .  no test files: nothing checks that the code works
  Complete:
    WARN  complete.ci_missing .  no CI configuration: nothing runs the tests on each change
    WARN  complete.license_missing .  no licence file: nobody may legally reuse this code
    WARN  complete.readme_missing .  no README: nobody can tell what this is or how to run it
    WARN  complete.license_undeclared pyproject.toml:1  the package metadata declares no licence
    WARN  complete.metadata pyproject.toml:1  pyproject.toml [project] is missing: requires-python
    INFO  deps.declared_unused pyproject.toml:4  dependency flask is declared but never imported

egress inventory (4):
  WARN  risky/network.py:5  url   http://{host}:8080/upload
  INFO  risky/network.py:6  url   https://example.com/docs
  INFO  risky/network.py:7  ip    100.64.0.5
  INFO  risky/network.py:11  call  requests.post

hygiene (inferred (library public API) entry points: 1): 0 dead, 0 test-only, 0 uncertain

notes:
  - code-guardian analyses Python only: 1 file(s) in other languages (.js 1) got the secret scan only

weights used (each check (code + level) deducts its weight once, plus a quarter of the weight per extra occurrence (rounded up), at most 2x the weight; INFO is never scored):
  Safe     deps.unpinned INFO 0 · deser.unsafe WARN 10 · exec.dynamic FAIL 30 · exec.dynamic WARN 10 ·
           exec.shell FAIL 30 · exec.shell WARN 10 · fs.outside WARN 3 · install.hook WARN 15 ·
           net.bind_all WARN 5 · net.egress INFO 0 · net.egress WARN 2 · obfuscation FAIL 40 ·
           obfuscation WARN 10 · secret.key FAIL 40 · secret.key INFO 0 · supply.lookalike WARN 15 ·
           supply.unknown_package FAIL 40 · supply.unknown_package INFO 0 · supply.unknown_package WARN 10 ·
           tls.off FAIL 25 · tls.off WARN 10
  Works    orphan.dead WARN 3 · works.entry_missing FAIL 30 · works.import_unresolved WARN 10 ·
           works.relative_missing FAIL 25 · works.syntax FAIL 30 · works.syntax INFO 0 ·
           works.test_no_assert WARN 5 · works.tests_missing WARN 15
  Complete complete.ci_missing WARN 10 · complete.env_example WARN 10 · complete.license_missing WARN 20 ·
           complete.license_undeclared WARN 5 · complete.lockfile WARN 10 · complete.metadata WARN 10 ·
           complete.readme_missing WARN 20 · complete.readme_sections WARN 5 · complete.readme_short WARN 10 ·
           deps.declared_unused INFO 0

static analysis: every finding is LIKELY; the scores come from fixed weights, never from a model
```

Exit code 1: there are FAIL findings. `--json` prints the same report as JSON (shape below); `--fail-on WARN` (or
`INFO`) lowers the bar for CI.

| exit | meaning |
|---|---|
| 0 | nothing at or above `--fail-on` (default `FAIL`) |
| 1 | findings at or above it |
| 2 | usage error, a missing PATH, or a bad goal file |

`scan` gates on every scored finding (Safe, Works and Complete); `code-guardian orphans PATH` gates on the hygiene
findings.

## How the scores work

Every check is a small pure function with its own tests. Every finding has the guardian family's shape (`code`,
`severity`, `level`, `node` = `file:line`, `summary` of at most 120 characters, `evidence`, `try`) and confidence
`LIKELY`: a parse proves the code is there, not that it runs. Each check code belongs to one dimension: Safe, Works or
Complete.

- **Per check, not per occurrence.** A check (one row of the tables below: a code at a level) deducts its weight
  once, plus a quarter of the weight for each extra occurrence (rounded up), at most twice the weight. Fifty copies of
  one minor issue cannot zero a score.
- **Dimension score** = max(0, 100 − its deductions). Safe is 100 minus the v0.1 threat score; its weights are the
  v0.1 weights, unchanged.
- **Overall** = 0.5 × Safe + 0.3 × Works + 0.2 × Complete, rounded half up.
- **Grade**: **A** ≥ 90 · **B** ≥ 75 · **C** ≥ 60 · **D** ≥ 40 · **F** below 40.
- **FAIL cap**: any Safe finding at FAIL caps the grade at **D**, whatever the average. One leaked key never hides
  behind a good README.
- INFO findings are never scored. Every report prints the weight table it used.

The weight tables live in `code_guardian/score.py` (`TABLES`); `tests/test_readme_sync.py` fails if the tables in
this README drift from them.

### JSON shape (`--json`, and the MCP `scan` tool)

```
{
  "tool", "version", "path", "goal_file",
  "files": {"python", "manifests", "other", "skipped", "ignored", "excluded", "unparsed"},
  "other_languages": {".js": 1, ...},
  "anchor": "pyproject.toml",                (the file repo-level findings are attached to in SARIF)
  "scores": {"safe", "works", "complete", "overall", "grade", "grade_uncapped", "capped", "cap_reason"},
  "dimensions": {"safe" | "works" | "complete": {"score", "deducted",
                 "checks": [{"code", "level", "count", "weight", "deduction", "first"}]}},
  "top": [the five biggest deductions, each a check row plus "dimension"],
  "weights": {"safe" | "works" | "complete": {"code LEVEL": weight}},
  "weights_rule": "...",
  "findings": [{"code", "severity", "level", "node", "summary", "evidence", "try", "confidence", "fix"}],
  "egress": [{"node", "level", "kind", "target"}],
  "hygiene": {"source", "goal", "entry_points", "keep", "findings", "counts", "notes"},
  "notes": [...],
  "explanation": {"label", "text"}          (only with --explain and a model that answered)
}
```

The MCP `scan` reply adds `exit_code`. Nothing in the report depends on the clock.

## Safe checks

| code | what it looks for | level | weight |
|---|---|---|---|
| `secret.key` | API-key shapes (the privacy workflow's built-in list: `sk-` (which covers Anthropic's `sk-ant-`), `sk-or-`, `tvly-`, `ghp_`, `github_pat_`, `nvapi-`, `gsk_`, `AIza`; plus AWS access key IDs `AKIA`/`ASIA` + 16, Stripe `sk_live_`/`rk_live_`, Slack `xox[abprs]-`, Hugging Face `hf_` + 30 letters), a 40-character AWS secret key assigned to a name containing `aws` and `secret`, private-key blocks, `password = "<literal>"` (also `api_key`, `secret`, `access_token`…), and any `*_KEY` / `*_TOKEN` name holding a long, high-entropy literal. One finding per line. Values are never printed; values that call themselves fake (`mock`, `dummy`, `example`…) are skipped | FAIL | 40 |
| `secret.key` | a Stripe test-mode key (`sk_test_`) | INFO | 0 |
| `exec.dynamic` | `eval`, `exec`, `compile` on non-literal input; `__import__` with a variable | WARN | 10 |
| `exec.dynamic` | …when `eval` or `exec` runs text from `input()`, `sys.argv`, request data, `os.environ` or a network read (the `exec.shell` taint rule, one function deep; `exec(compile(...))` counts at the `exec`): "runs code typed by the user" | FAIL | 30 |
| `exec.shell` | `os.system`, `os.popen`, `subprocess.*(..., shell=True)` | WARN | 10 |
| `exec.shell` | …when the command is built from `input()`, `os.environ`, `sys.argv` or a network read | FAIL | 30 |
| `deser.unsafe` | `pickle.load(s)`, `marshal.loads`, `yaml.load` without `SafeLoader`, `torch.load` without `weights_only=True` | WARN | 10 |
| `net.egress` | every URL and IP literal plus every `urllib`/`requests`/`httpx`/`socket.connect` call site: the **egress inventory** | INFO | 0 |
| `net.egress` | a publicly routable IP, or plain `http`/`ws`/`ftp` to a public name or to a host chosen at runtime | WARN | 2 |
| `net.bind_all` | binding `0.0.0.0` or `::` | WARN | 5 |
| `tls.off` | `verify=False`, `ssl._create_unverified_context`, `CERT_NONE`, `check_hostname = False`, hard-coded | FAIL | 25 |
| `tls.off` | …only under an `if` on a function parameter: the caller opts out (how `httpx` implements `verify=False`) | WARN | 10 |
| `install.hook` | `setup.py` `cmdclass` or install-command subclasses, `package.json` `preinstall`/`install`/`postinstall`, an in-tree build backend | WARN | 15 |
| `obfuscation` | `exec`/`eval` of `base64`/`zlib`/`marshal`/hex-decoded data | FAIL | 40 |
| `obfuscation` | base64 or hex blobs of 200+ characters, high-entropy string literals | WARN | 10 |
| `fs.outside` | writes, deletes and moves aimed at absolute paths, `~`, or `..` escapes | WARN | 3 |
| `deps.unpinned` | dependencies with no pin or upper bound (`pyproject.toml`, `setup.py`, `setup.cfg`, `requirements*.txt`, `package.json`) | INFO | 0 |

`net.egress` targets that stay in the inventory at INFO: https to a named host, loopback, the local network
(non-global addresses such as 10/8, 192.168/16 and 100.64/10, single-label names like `gpu-box`, `.local`, `.lan`,
`.internal`, `.home.arpa`) and reserved documentation names (`example.com`, `.test`, `.invalid`).

The walk skips `.git`, `venv`/`.venv`, `node_modules`, `__pycache__`, `dist`, `build` and the tool caches, anything
the root `.gitignore` matches (simple globs; `!` negation is ignored), binary files, files over 2 MB and symlinks.

### Invented and lookalike packages (Safe)

AI coding assistants sometimes suggest a package that does not exist. Anyone can register that name on PyPI and
put anything in it, and attackers do exactly that with the names assistants invent. **A package existing is not
proof it is safe**: these checks flag names worth a second look; they do not vouch for any package.

| code | what it looks for | level | weight |
|---|---|---|---|
| `supply.unknown_package` | offline (default): a declared dependency or an unresolved import that is not in the bundled list of known packages; run with `--online` to check it exists | INFO | 0 |
| `supply.unknown_package` | `--online`: PyPI has no such project (likely invented by an AI assistant; anyone could register the name) | FAIL | 40 |
| `supply.unknown_package` | `--online`: the project's first release is under 90 days old, or it has only one release | WARN | 10 |
| `supply.lookalike` | one or two edits (insert, delete, change, swap) away from a known package without being it; two edits only for names of 8+ characters, none under 5 | WARN | 15 |

- **Offline is the default and makes no network call.** The bundled list,
  `code_guardian/data/known_packages.txt.gz`, holds about 960 widely used PyPI projects. It is **hand-built**
  (`tools/known_packages.txt`, written for this project and not derived from any download dataset) and verified to
  exist on PyPI by `python tools/build_known_packages.py --verify`. The brief asked for the top ~15,000 projects by
  downloads; the usual source (hugovk/top-pypi-packages) carries no licence we could confirm, so a smaller
  hand-built list ships instead. A name missing from it is not suspicious by itself, which is why offline misses are
  INFO.
- **`--online`** asks `https://pypi.org/pypi/<name>/json` (override with `CODE_GUARDIAN_PYPI_URL`, timeout
  `CODE_GUARDIAN_PYPI_TIMEOUT`, default 10 s) once per name per run. A timeout or error becomes a note; it never
  fails the scan. Online answers depend on PyPI and on today's date, so `--online` output is not reproducible run
  to run; offline output is.

## Works checks

Will it work? Read from the parse and the manifests, never by importing or running anything.

| code | what it looks for | level | weight |
|---|---|---|---|
| `works.syntax` | a `.py` file that `ast.parse` rejects (Python 2 code, a typo); it still gets the secret scan | FAIL | 30 |
| `works.syntax` | …when the project's `requires-python` is newer than the Python running code-guardian (it cannot tell) | INFO | 0 |
| `works.import_unresolved` | an absolute import that is not in the standard library, not a module or package in the repo, and not a declared dependency | WARN | 10 |
| `works.relative_missing` | a relative import (`from .x import y`) that points at a module the repo does not have | FAIL | 25 |
| `works.tests_missing` | no test files at all (`tests/`, `test_*.py`, `*_test.py`, `tests.py`, `conftest.py`) | WARN | 15 |
| `works.test_no_assert` | test functions with no `assert`, no `pytest.raises`/`warns`, no `self.assert*` and no call to a local helper that asserts; once per file, with the count | WARN | 5 |
| `works.entry_missing` | a `[project.scripts]` (or `setup.cfg` console script) target `module:function` whose module or function is not in the tree | FAIL | 30 |
| `orphan.dead` | dead code from the hygiene section (below), folded in at a low weight, only when entry points exist | WARN | 3 |

How `works.import_unresolved` decides:

- **Standard library**: `sys.stdlib_module_names` plus the modules removed after 3.11 (`distutils`, `imp`, `cgi`…)
  and added since (`annotationlib`, `compression`), so the answer does not depend on which Python runs the scan.
- **In the repo**: any directory name or module stem in the tree (a script's sibling module counts).
- **Declared**: every dependency in `pyproject.toml` (`[project]`, optional dependencies, `dependency-groups`,
  `build-system.requires`, Poetry, PDM, uv), `setup.py` (parsed, never run), `setup.cfg`, `requirements*.txt`,
  `requirements/*.txt` and `Pipfile`. Import names map to distributions through a bundled table of known
  mismatches (`yaml`→PyYAML, `PIL`→Pillow, `cv2`→opencv-python, `sklearn`→scikit-learn, `bs4`→beautifulsoup4,
  `dateutil`→python-dateutil…) plus the normalised name, `python-X`/`pyX`/`X-python` forms and namespace packages
  (`google`→`google-cloud-*`). It never reads the scanner's own installed packages: they describe this machine, not
  the repo.
- **Product code only**: test files and `docs/` are not checked (their dependencies are dev tools, and tests often
  import modules they write at runtime).
- **Not reported**: imports inside either branch of `try: … except ImportError`, under `if TYPE_CHECKING:`, or under an
  `if` on a flag such a `try` sets (`if has_simplejson:`); `setuptools` and friends in `setup.py`.
- A dependency that is only installed because another one pulls it in still counts as undeclared: it works by
  accident. Undeclared dependencies have one owner, this check; Complete does not report them again.

## Complete checks

Does it have what it needs? File presence plus basic parsing.

| code | what it looks for | level | weight |
|---|---|---|---|
| `complete.license_missing` | no `LICENSE`, `LICENCE`, `COPYING` or `UNLICENSE` file at the root | WARN | 20 |
| `complete.license_undeclared` | packaging metadata (`[project]`, Poetry, `setup.cfg`, `setup()`) declares no licence (`license`, `license-files` or a `License ::` classifier) | WARN | 5 |
| `complete.readme_missing` | no README at the root | WARN | 20 |
| `complete.readme_short` | the README is under 200 bytes | WARN | 10 |
| `complete.readme_sections` | a README of 200+ bytes with no install heading (install, setup, getting started, quick start) or no usage heading (usage, examples, tutorial, run, CLI…) | WARN | 5 |
| `complete.ci_missing` | no CI configuration (`.github/workflows/`, `.gitlab-ci.yml`, `.circleci/`, `azure-pipelines.yml`, `.travis.yml`, `Jenkinsfile`…) | WARN | 10 |
| `complete.metadata` | `pyproject.toml` `[project]` without `name`, `version` (or `dynamic`) or `requires-python` | WARN | 10 |
| `complete.lockfile` | an **application** with no lockfile (`uv.lock`, `poetry.lock`, `Pipfile.lock`, `pdm.lock`, `pixi.lock`, `requirements.lock`, or a fully pinned `requirements.txt`) | WARN | 10 |
| `complete.env_example` | the code reads environment variables (`os.environ`, `os.getenv`, dotenv) and there is no `.env.example` (or `.env.sample`, `.env.template`, `example.env`) | WARN | 10 |
| `deps.declared_unused` | a runtime dependency that nothing in the repo imports (runners, linters, `types-*` and `pytest-*` plugins are skipped) | INFO | 0 |

**Lockfiles count only for applications.** A repo is an application when it has any of these markers: a
`Dockerfile`/`Containerfile`; a `__main__.py` while the project declares no `[project.scripts]`; or a module-level
web app object (`Flask(…)`, `FastAPI(…)`, `Starlette(…)`, `Quart(…)`, `Sanic(…)`, Django's
`get_wsgi_application()`/`get_asgi_application()`). Markers under `examples/`, `docs/`, `tests/` and similar folders do
not count. A library (it has `[project]` and none of these markers) is not penalised for having no lockfile.

**`.env.example` is required only for applications that read environment variables** (the same markers as the
lockfile rule), outside tests and examples. Libraries read optional variables such as `NO_COLOR` all the time and do
not ship `.env` files; calibration showed every clean library tripping the check otherwise. A read through a variable
that merely holds `os.environ` is not followed.

**Undeclared dependencies are owned by `works.import_unresolved`**; Complete reports only the opposite case,
declared but unused. A repo with no Python source and no manifest has nothing for Works or Complete to check: it
scores 100 there, and the report says so.

## Outputs, GitHub Action and pre-commit

| flag | prints |
|---|---|
| *(none)* | the text report shown above |
| `--json` | the full report (shape above) |
| `--sarif` | SARIF 2.1.0 for GitHub code scanning: one rule per check code (title, meaning, fix and false-positive notes from the catalogue below; Safe rules carry `security-severity`), one result per finding. Repo-level findings (no file) are attached to the root manifest or README, because code scanning needs a file for every result. Validated in CI against the official schema |
| `--markdown` | a Markdown report for a pull-request comment or a job summary |

Every format is deterministic: no timestamps, no absolute paths. `--fail-on` works the same with each. The MCP
`scan` tool keeps returning JSON.

**GitHub Action** (`action.yml` in this repo, a composite action). It installs code-guardian from the action's own
checkout, writes `code-guardian.sarif`, adds the Markdown report to the job summary, uploads the SARIF to code
scanning, and then fails the job when a finding is at or above `fail-on`:

```yaml
name: code-guardian
on: [push, pull_request]
permissions:
  contents: read
  security-events: write   # for the SARIF upload
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: LuminariSoftwares/code-guardian@v0.2.0
        with:
          path: .
          fail-on: FAIL        # or WARN
          online: "false"      # "true" asks PyPI about unknown dependency names
```

Inputs: `path`, `fail-on`, `online`, `sarif-file` (default `code-guardian.sarif`), `upload-sarif` (default `true`),
`python-version` (default `3.11`). Outputs: `overall`, `grade`, `exit-code`. Inputs reach the shell only through
environment variables, never by text substitution.

**pre-commit** (`.pre-commit-hooks.yaml`). It scans the whole repository, not just the staged files:

```yaml
repos:
  - repo: https://github.com/LuminariSoftwares/code-guardian
    rev: v0.2.0
    hooks:
      - id: code-guardian
        # args: [--fail-on, WARN]
```

## Check catalogue

Every finding code: what it means, how to fix it, and when it can be wrong. Weights are in the dimension tables
above. Two rules apply across Safe:

- **Test code and documentation are reported at INFO.** Safe findings in tests (`tests/`, `test_*.py`,
  `conftest.py`, fixture and test-data folders) and in documentation (`docs/`, `.md`, `.rst`, `.txt`) keep their
  place in the report but do not score: users run the product, not its tests or its doc samples. Two
  exceptions keep their level: API-key shapes (a real key is leaked wherever it sits) and `exec` of decoded data
  (a payload in `conftest.py` runs on every `pytest`).
- **Calibration.** Each false-positive note below comes from scanning five well-known clean projects and the
  four guardian repositories; see [calibration.md](calibration.md).

| code | dimension | what it means | how to fix it | false positives |
|---|---|---|---|---|
| `check.crashed` | Safe | One of code-guardian's own checks raised on this file; the rest of the scan ran. | Report it at github.com/LuminariSoftwares/code-guardian/issues with the file if you can share it. | It is a code-guardian bug, never a finding about your code. |
| `deps.unpinned` | Safe | A dependency with no pin and no upper bound. | Pin it (==) or cap it (< next major). | Libraries often prefer open ranges on purpose; INFO, never scored. |
| `deser.unsafe` | Safe | pickle, marshal, yaml.load without SafeLoader, or torch.load without weights_only=True can run code hidden in the data. | Load only files you created, or use a data-only format (json, safetensors, yaml.safe_load). | Caches the program writes and reads itself are lower risk. |
| `exec.dynamic` | Safe | eval, exec or compile runs a non-literal string, or __import__ loads a module named at runtime; FAIL when eval or exec runs text from input(), sys.argv, request data, the environment or the network. | Use a parser, a lookup table or ast.literal_eval; import modules by name; never run input as code. | Plugin loaders and REPL-style tools use these on purpose. |
| `exec.shell` | Safe | os.system, os.popen or subprocess with shell=True; FAIL when the command text comes from input, the environment or the network. | Pass an argument list without shell=True; validate any outside value against an allow-list. | Fixed command strings in build scripts are WARN, not FAIL; taint is tracked one function deep. |
| `fs.outside` | Safe | A write, delete or move aimed at an absolute path, the home directory or a .. escape. | Write under the project or under a path the user passes in. | Tools whose job is to write to /tmp or a user config folder. |
| `install.hook` | Safe | setup.py cmdclass or install-command subclasses, package.json preinstall/install/postinstall, or an in-tree build backend. | Read what the hook runs before installing; prefer packages without install-time code. | Projects that compile extensions legitimately customise build commands. |
| `net.bind_all` | Safe | A server binds 0.0.0.0 or ::, so other machines can reach it. | Bind to 127.0.0.1 unless other machines must connect. | Containers usually must bind 0.0.0.0; a test that asserts the bind is refused still matches. |
| `net.egress` | Safe | The egress inventory: every URL and IP literal and every network call site. WARN for a public IP, or plain http/ws/ftp to a public name or to a host set at runtime. | Use https, and confirm each destination is expected. | Local-network and documentation hosts stay INFO; a URL in a help string is still inventoried. |
| `obfuscation` | Safe | exec/eval of base64, zlib, marshal or hex-decoded data (FAIL); long encoded blobs or high-entropy literals (WARN). | Decode the payload offline and read what it does before running anything. | Embedded icons, test vectors and hashes can look like blobs. |
| `secret.key` | Safe | An API-key shape (OpenAI-style sk-, GitHub, Google, AWS, Stripe live, Slack, Hugging Face and others), an AWS secret key, a private-key block, a password-like literal or a high-entropy literal in a name ending _KEY or _TOKEN is written into a file (a Stripe test key is INFO). | Move it to an environment variable or a secret store, and rotate it: it is in the history. | Test fixtures and documentation samples; values that call themselves fake (mock, dummy, example) are skipped. |
| `supply.lookalike` | Safe | The name is one or two edits away from a known package without being it: the typosquatting pattern. | Check you meant the well-known package. | Real packages with names close to a popular one. |
| `supply.unknown_package` | Safe | Offline: the name is not in the bundled list of known packages (INFO). Online: PyPI has no such project (FAIL), or it is new or has a single release (WARN). | Check the name is the one you meant; remove names an assistant invented; run with --online. | Offline misses are common for less-known real packages, which is why they are INFO. Existing is not safe. |
| `tls.off` | Safe | verify=False, ssl._create_unverified_context, CERT_NONE or check_hostname = False. | Remove it; point at a CA bundle if the certificate is private. | Rare: code that deliberately probes broken servers. |
| `orphan.dead` | Works | A function, class or module nothing reachable from the entry points uses. | Delete it, or list it in keep if something loads it by name. | Code loaded by name (plugins, entry points of other tools); add those to keep. |
| `orphan.test_only` | Works | Only tests reach this code; the product never does. | Delete it with its tests, or call it from the product. | Test helpers kept in the package on purpose. |
| `orphan.uncertain` | Works | getattr/globals/importlib with a computed name, or a string registry, could reach it. | List it in keep if it is loaded by name; otherwise delete it. | It is reported as uncertain precisely because the parse cannot tell. |
| `works.entry_missing` | Works | A [project.scripts] (or setup.cfg console script) target module:function is not in the tree. | Point the script at an existing module:function. | Modules generated at build time. |
| `works.import_unresolved` | Works | An absolute import that is not in the standard library, not in the repo and not a declared dependency. | Declare the distribution that provides it, or guard an optional import with try/except ImportError. | Packages pulled in only by another dependency (they work by accident); import names the mapping table misses. |
| `works.relative_missing` | Works | from .x import y points at a module (or a package name) the repo does not have. | Fix the module path or add the missing module. | Modules generated at build time. |
| `works.syntax` | Works | ast.parse rejects the file, so it cannot be imported or run (INFO when the project needs a newer Python than the one scanning). | Fix the syntax error; port Python 2 code to Python 3. | Files kept on purpose for another interpreter, or templates with a .py name. |
| `works.test_no_assert` | Works | Test functions with no assert, no pytest.raises/warns, no self.assert* and no call to an asserting helper. | Assert on the result; use pytest.raises for expected errors. | Smoke tests that only check nothing raises; helpers defined in another file. |
| `works.tests_missing` | Works | There are no test files at all. | Add a tests/ folder with at least one test per entry point. | Tests kept in another repository. |
| `complete.ci_missing` | Complete | No CI configuration was found. | Add a CI workflow that runs the tests on each change. | CI configured outside the repository. |
| `complete.env_example` | Complete | The code reads environment variables but there is no .env.example listing them. | Add a .env.example with every variable and a safe placeholder. | Libraries that read only optional, well-known variables (NO_COLOR, TERM). |
| `complete.license_missing` | Complete | There is no LICENSE, LICENCE, COPYING or UNLICENSE file at the root. | Add a LICENSE file. | Licences kept only in a subfolder. |
| `complete.license_undeclared` | Complete | Packaging metadata exists but declares no licence. | Add license = "..." (or license-files) to [project]. | Licences declared only by a build plugin. |
| `complete.lockfile` | Complete | The repo is an application (a Dockerfile, a __main__.py without scripts, or a web app object) and has no lockfile. | Commit a lockfile (uv lock, poetry lock or pip-compile). | Libraries are never asked for one; an example app outside examples/ can make a library look like an app. |
| `complete.metadata` | Complete | pyproject.toml [project] lacks name, version (or dynamic) or requires-python. | Add the missing keys to [project]. | None known. |
| `complete.readme_missing` | Complete | There is no README at the root. | Add a README.md that says what it is, how to install it and how to use it. | README kept under docs/ only. |
| `complete.readme_sections` | Complete | A README of 200+ bytes with no install heading or no usage heading. | Add an Install heading and a Usage heading. | Headings worded differently from the words the check knows. |
| `complete.readme_short` | Complete | The README is under 200 bytes. | Describe what it does, how to install it and how to use it. | A README that only links to full documentation. |
| `deps.declared_unused` | Complete | A runtime dependency nothing in the repo imports. | Remove it, or note why it is needed (a plugin or a runner). | Plugins and runners loaded by other tools; INFO, never scored. |

## Goal contract

`code-guardian.goal.toml` at the project root (optional) says what the project is for and where it starts:

```toml
goal = "One sentence: what this project is for."
entry_points = ["pkg.cli:main", "pkg.server:app"]   # module:function, or module:__main__ for its main block
keep = ["pkg.plugins.*"]                             # loaded dynamically; never reported
exclude = ["tests/fixtures/*"]                       # path globs the scan skips (the report counts them)
```

```
code-guardian init            # writes a starter file with the inferred entry points; --force replaces one
code-guardian orphans .       # hygiene only
```

Without a contract, entry points are inferred from `[project.scripts]` (and `setup.cfg` console scripts),
`if __name__ == "__main__":` blocks, `__main__.py` files and `__all__` of top-level packages, and the report says
"inferred". With no entry points at all, nothing is reported.

The call graph is built with `ast` from imports, `from x import y`, attribute use on imported modules and method calls.
Anything not reachable from an entry point is an orphan:

| code | meaning | level |
|---|---|---|
| `orphan.dead` | nothing reachable uses it | WARN |
| `orphan.test_only` | only tests reach it | INFO |
| `orphan.uncertain` | `getattr`/`globals()`/`importlib` with a computed name could reach it, or its name is a string in reachable code (a registry) | INFO |

A method counts as used when its class is used and its name is read as an attribute anywhere reachable; a class with a
base outside the project (a framework) keeps all its methods. A def wrapped in a registering decorator (`@app.get`,
`@click.command`, `@pytest.fixture`) and a module-level `__getattr__` are reached with their module, because the
decorator or the interpreter calls them. For a **library** (inferred entry points, packaging metadata and no
application marker), the public API counts as entry points: every public module, its public functions and classes,
their public methods, and everything a public module re-exports (`from ._client import Client`,
`from ._transports import *`); the hygiene source then reads "inferred (library public API)". Orphans go into the **hygiene** section and never touch
the Safe score.

## `--explain`

```
CODE_GUARDIAN_LLM_URL=http://127.0.0.1:11434/api/chat CODE_GUARDIAN_LLM_MODEL=qwen3:8b code-guardian scan . --explain
```

`CODE_GUARDIAN_LLM_URL` is an Ollama `/api/chat` URL or any OpenAI-compatible `/v1/chat/completions` URL, detected
by path (a bare host means Ollama, a `.../v1` base means OpenAI-compatible). Optional: `CODE_GUARDIAN_LLM_KEY`
(bearer token), `CODE_GUARDIAN_LLM_TIMEOUT` (seconds, default 60).

Guarantees, each covered by a test against a stub model on loopback:

- **It never changes a score.** The report with `--explain` equals the report without it, plus one block labelled
  `model explanation (not part of the score)` and one note line.
- **It sends findings only:** `code`, `level`, `file:line` and the ≤120-character summary, plus the scores, grade
  and hygiene counts. No source code, no evidence lines, no secret values.
- **It talks to one URL:** the one you configured, directly (no proxy). The scan itself never touches the network.
- **It fails soft:** with the URL unset or unreachable, the report is unchanged and one note line says why.

## MCP server

`code-guardian-mcp` (or `code-guardian mcp`) speaks MCP over stdio with three read-only tools, each with a `title`
and `readOnlyHint: true`, `destructiveHint: false`, `idempotentHint: true`:

| tool | does | `openWorldHint` |
|---|---|---|
| `scan` | the full report for `path` (+ optional `goal`, `fail_on`; the reply carries `exit_code`) | false |
| `orphans` | the hygiene section for `path` | false |
| `explain` | `scan` plus the model explanation | true |

A `path` argument is resolved and must exist. Claude Code:

```
claude mcp add code-guardian -- uvx code-guardian-mcp mcp
```

Any MCP client:

```json
{
  "mcpServers": {
    "code-guardian": {
      "command": "uvx",
      "args": ["code-guardian-mcp", "mcp"],
      "env": {"CODE_GUARDIAN_LLM_URL": "http://127.0.0.1:11434/api/chat", "CODE_GUARDIAN_LLM_MODEL": "qwen3:8b"}
    }
  }
}
```

The `env` block is only needed for `explain`.

## Limitations

- **Only Python is analysed.** Manifests (`package.json`, `setup.py`, `setup.cfg`, `pyproject.toml`,
  `requirements*.txt`) are read for install hooks and pins; every other language gets the secret scan only, and the
  report says which files.
- **Static analysis cannot see runtime behaviour.** A finding means the code is there, not that it runs; code that
  builds its behaviour at runtime (downloaded plugins, `exec` of fetched text) is flagged where the parse can see it
  and invisible where it cannot. A grade A is "nothing the scanners recognise", not "proven safe".
- Python files are parsed by the interpreter running code-guardian. Run it with a Python at least as new as the
  project's `requires-python`; when it is older, a parse failure is reported as `works.syntax` INFO, not FAIL.
- Taint tracking for `exec.shell` FAIL is one function deep: assignments inside the same function, not calls between
  functions.
- The orphan graph over-approximates "used" (a method name read anywhere keeps every reached class's method of that
  name), so it reports less dead code rather than wrong dead code.
- `.gitignore` support is simple globs from the root file; negation (`!`) and nested `.gitignore` files are ignored.

## Every module tests itself

```
python -m code_guardian.scanners --selftest
scanners selftest: 18 checks, 18 passed, 0 failed
```

Each of `finding`, `walk`, `scanners`, `manifests`, `score`, `goal`, `orphans`, `works`, `complete`, `supply`,
`explain`, `report`, `cli` and `mcp_server` has one; `tests/test_selftests.py` runs them all.

## License

MIT. See [LICENSE](LICENSE).
