# code-guardian

[![ci](https://github.com/LuminariSoftwares/code-guardian/actions/workflows/ci.yml/badge.svg)](https://github.com/LuminariSoftwares/code-guardian/actions/workflows/ci.yml)
[![privacy](https://github.com/LuminariSoftwares/code-guardian/actions/workflows/privacy.yml/badge.svg)](https://github.com/LuminariSoftwares/code-guardian/actions/workflows/privacy.yml)

mcp-name: io.github.LuminariSoftwares/code-guardian

One command that answers: **is this codebase safe to run, and is all of it actually used?**

- A **threat score** (0–100, grade A–F) computed only by deterministic scanners: same input, same score, every time.
- **Orphan code**: functions, classes and modules nothing reachable from the project's entry points uses, judged
  against a small goal contract.
- An optional **plain-English explanation** from a local model, which never adds, removes or rescores a finding.

It parses the code (`ast` for Python; `json`, `tomllib` and `configparser` for manifests; regular expressions for
secrets) and never executes, imports or installs it. A scan makes
no network calls. Python 3.11+, standard library only. Status: **0.1.0, unreleased.** The fourth guardian, next to
[stack-guardian](https://github.com/LuminariSoftwares/stack-guardian),
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
code-guardian 0.1.0  scan of risky_repo
files: 7 Python, 3 manifests, 2 other (0 skipped, 0 excluded by the goal file)

threat score 100/100 (raw 340)  grade F
top contributors:
   40  secret.key    FAIL  deploy/id_rsa:1  private-key block in the source; value redacted
   40  obfuscation   FAIL  risky/loader.py:7  exec() runs decoded or decompressed data
   40  secret.key    FAIL  risky/settings.py:1  sk- key shape (privacy pattern 5) in the source; value redacted
   40  secret.key    FAIL  risky/settings.py:2  password-like literal assigned to 'password' in the source; value redacted
   30  exec.shell    FAIL  risky/runner.py:7  os.system runs a shell command built from input, env or network

findings (6 FAIL, 13 WARN, 6 INFO; egress listed below):
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

egress inventory (4):
  WARN  risky/network.py:5  url   http://{host}:8080/upload
  INFO  risky/network.py:6  url   https://example.com/docs
  INFO  risky/network.py:7  ip    100.64.0.5
  INFO  risky/network.py:11  call  requests.post

hygiene (inferred entry points: 1): 6 dead, 0 test-only, 0 uncertain
  WARN  orphan.dead       risky/loader.py:1  module risky.loader is never reached from the entry points
  WARN  orphan.dead       risky/network.py:1  module risky.network is never reached from the entry points
  WARN  orphan.dead       risky/runner.py:10  function risky.runner.list_files is never reached from the entry points
  WARN  orphan.dead       risky/runner.py:14  function risky.runner.calculate is never reached from the entry points
  WARN  orphan.dead       risky/settings.py:1  module risky.settings is never reached from the entry points
  WARN  orphan.dead       risky/storage.py:1  module risky.storage is never reached from the entry points

notes:
  - v1 analyses Python only: 1 file(s) in other languages (.js 1) got the secret scan only

static analysis: every finding is LIKELY; scanned in 0.01 s
```

Exit code 1: there are FAIL findings. `--json` prints the same report as JSON; `--fail-on WARN` (or `INFO`) lowers
the bar for CI.

| exit | meaning |
|---|---|
| 0 | nothing at or above `--fail-on` (default `FAIL`) |
| 1 | findings at or above it |
| 2 | usage error, a missing PATH, or a bad goal file |

`scan` gates on the threat findings; `code-guardian orphans PATH` gates on the hygiene findings.

## Scanners and weights

Every scanner is a small pure function with its own tests. Every finding has the guardian family's shape (`code`,
`severity`, `level`, `node` = `file:line`, `summary` of at most 120 characters, `evidence`, `try`) and confidence
`LIKELY`: a parse proves the code is there, not that it runs.

**Threat score** = min(100, Σ weight), with one fixed weight per code and level (`WEIGHTS` in
`code_guardian/score.py`). Grade: **A** 0–9 · **B** 10–24 · **C** 25–49 · **D** 50–74 · **F** 75+. The report
shows the score, the uncapped sum (`raw`), the grade and the top five contributors.

| code | what it looks for | level | weight |
|---|---|---|---|
| `secret.key` | API-key shapes (the privacy workflow's built-in list: `sk-`, `sk-or-`, `tvly-`, `ghp_`, `github_pat_`, `nvapi-`, `gsk_`, `AIza`), private-key blocks, `password = "<literal>"` (also `api_key`, `secret`, `access_token`…). Values are never printed; values that call themselves fake (`mock`, `dummy`, `example`…) are skipped | FAIL | 40 |
| `exec.dynamic` | `eval`, `exec`, `compile` on non-literal input; `__import__` with a variable | WARN | 10 |
| `exec.shell` | `os.system`, `os.popen`, `subprocess.*(..., shell=True)` | WARN | 10 |
| `exec.shell` | …when the command is built from `input()`, `os.environ`, `sys.argv` or a network read | FAIL | 30 |
| `deser.unsafe` | `pickle.load(s)`, `marshal.loads`, `yaml.load` without `SafeLoader`, `torch.load` without `weights_only=True` | WARN | 10 |
| `net.egress` | every URL and IP literal plus every `urllib`/`requests`/`httpx`/`socket.connect` call site: the **egress inventory** | INFO | 0 |
| `net.egress` | a publicly routable IP, or plain `http`/`ws`/`ftp` to a public name or to a host chosen at runtime | WARN | 2 |
| `net.bind_all` | binding `0.0.0.0` or `::` | WARN | 5 |
| `tls.off` | `verify=False`, `ssl._create_unverified_context`, `CERT_NONE`, `check_hostname = False` | FAIL | 25 |
| `install.hook` | `setup.py` `cmdclass` or install-command subclasses, `package.json` `preinstall`/`install`/`postinstall`, an in-tree build backend | WARN | 15 |
| `obfuscation` | `exec`/`eval` of `base64`/`zlib`/`marshal`/hex-decoded data | FAIL | 40 |
| `obfuscation` | base64 or hex blobs of 200+ characters, high-entropy string literals | WARN | 10 |
| `fs.outside` | writes, deletes and moves aimed at absolute paths, `~`, or `..` escapes | WARN | 3 |
| `deps.unpinned` | dependencies with no pin or upper bound (`pyproject.toml`, `setup.py`, `setup.cfg`, `requirements*.txt`, `package.json`) | INFO | 0 |
| `parse.skipped` | a `.py` file that does not parse as Python 3 (it still gets the secret scan) | INFO | 0 |

`net.egress` targets that stay in the inventory at INFO: https to a named host, loopback, the local network
(non-global addresses such as 10/8, 192.168/16 and 100.64/10, single-label names like `gpu-box`, `.local`, `.lan`,
`.internal`, `.home.arpa`) and reserved documentation names (`example.com`, `.test`, `.invalid`).

The walk skips `.git`, `venv`/`.venv`, `node_modules`, `__pycache__`, `dist`, `build` and the tool caches, anything
the root `.gitignore` matches (simple globs; `!` negation is ignored), binary files, files over 2 MB and symlinks.

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
| `orphan.uncertain` | `getattr`/`globals()`/`importlib` with a computed name could reach it, its name is a string in reachable code (a registry), or a registering decorator wraps it | INFO |

A method counts as used when its class is used and its name is read as an attribute anywhere reachable; a class with a
base outside the project (a framework) keeps all its methods. Orphans go into the **hygiene** section and never touch
the threat score.

## `--explain`

```
CODE_GUARDIAN_LLM_URL=http://127.0.0.1:11434/api/chat CODE_GUARDIAN_LLM_MODEL=qwen3:8b code-guardian scan . --explain
```

`CODE_GUARDIAN_LLM_URL` is an Ollama `/api/chat` URL or any OpenAI-compatible `/v1/chat/completions` URL, detected
by path (a bare host means Ollama, a `.../v1` base means OpenAI-compatible). Optional: `CODE_GUARDIAN_LLM_KEY`
(bearer token), `CODE_GUARDIAN_LLM_TIMEOUT` (seconds, default 60).

Guarantees, each covered by a test against a stub model on loopback:

- **It never changes the score.** The report with `--explain` equals the report without it, plus one block labelled
  `model explanation (not part of the score)` and one note line.
- **It sends findings only:** `code`, `level`, `file:line` and the ≤120-character summary, plus the score, grade and
  hygiene counts. No source code, no evidence lines, no secret values.
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

- **v1 analyses Python only.** Manifests (`package.json`, `setup.py`, `setup.cfg`, `pyproject.toml`,
  `requirements*.txt`) are read for install hooks and pins; every other language gets the secret scan only, and the
  report says which files.
- **Static analysis cannot see runtime behaviour.** A finding means the code is there, not that it runs; code that
  builds its behaviour at runtime (downloaded plugins, `exec` of fetched text) is flagged where the parse can see it
  and invisible where it cannot. A grade A is "nothing the scanners recognise", not "proven safe".
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

Each of `finding`, `walk`, `scanners`, `manifests`, `score`, `goal`, `orphans`, `explain`, `report`, `cli` and
`mcp_server` has one; `tests/test_selftests.py` runs them all.

## License

MIT. See [LICENSE](LICENSE).
