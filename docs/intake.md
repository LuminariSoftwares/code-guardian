# Repo intake: a first look at an untrusted repository

`code-guardian intake PATH` answers one question before you open, install or run a repository you did not write:
**does anything in it look like a way to attack me?** It is aimed at the attacks that ride inside a repository
itself, not at the quality of its code (that is `code-guardian scan`).

It is deterministic and standard library only: no model, no network (the optional stars signal aside), and nothing
from the repository is ever executed, imported, installed or followed.

## Use

```
code-guardian intake /home/user/downloads/some-repo           # plain-English report
code-guardian intake /home/user/downloads/some-repo --json     # the same, as JSON
code-guardian intake /home/user/downloads/some-repo --sarif    # SARIF 2.1.0, one result per finding
code-guardian intake PATH --bad-hashes my_hashes.json          # add your own known-bad SHA-256 list
code-guardian intake PATH --stars owner/repo                   # optional bought-stars signal (needs your own token)
code-guardian intake PATH --fail-on medium                     # exit 1 on medium or high (default: high)
```

Exit codes: 0 nothing at or above `--fail-on` (default `high`) and no known-bad match; 1 a finding at or above it, or
a known-bad match; 2 usage error (not a folder, a bad hash file).

## Quarantine: a read-only copy, never the clone

Intake does not scan the folder you give it. It first copies the regular files into a temporary folder, makes the
copy read-only, runs every check on the copy and deletes it. Symlinks, device files and the `.git` folder are not
copied (only non-sample files in `.git/hooks`, which a normal clone never contains, are checked); `node_modules`,
`venv`, `.venv` and `__pycache__` are not scanned and are listed under `skipped_dirs`. A file over 25 MB is hashed
whole but only its first 64 KB is kept. The clone is left exactly as it was.

## What it checks

Each finding records the file, the line, the rule id, the confidence and the exact text that matched (invisible
characters appear as `\uXXXX` escapes; very long text is cut and says by how much).

| Rule | What it finds | Confidence |
| --- | --- | --- |
| `hash.known_bad` | File matches a known-bad hash | high, and forces the malicious verdict |
| `binary.disguised_executable` | Program file with a harmless-looking name | high |
| `binary.embedded_executable` | Executable shipped inside the repo | high: a Windows executable written out as base64/hex text; medium: `.exe` and friends, extensionless ELF; low: `.dll`, `.so`, `.dylib` |
| `exec.on_import` | Code runs as soon as the module is imported | high: in `__init__.py`, or exec/eval of decoded data; medium: other modules; low: scripts, examples and tests |
| `exec.pth_import` | .pth file that runs code | high |
| `lure.pipe_to_shell` | Docs tell you to pipe a download into a shell | high: from an IP address, plain http or a link shortener/paste site, or an encoded command; medium: otherwise |
| `lure.run_download` | Docs push you toward running a downloaded program | high: switch off antivirus, or an archive password; medium: run as administrator, or download-and-run an executable; low: run an executable |
| `hidden.long_line` | Very long line of code | medium; low for minified or bundled file names |
| `hidden.whitespace_pad` | Code pushed far right behind whitespace | high: exec/eval-like text after the padding; medium otherwise |
| `hidden.oversized_file` | Single source file over 1 MB | medium |
| `hidden.high_entropy` | Packed-looking blob inside source code | medium for base64-looking blobs; low for hex |
| `hidden.blob_to_exec` | Encoded data is decoded and executed | high: the encoded data is a literal in the statement; medium: it comes from a variable |
| `hollow.readme_heavy` | Large README, almost no code | medium: with binaries/archives or a download push; low: a big README and no code |
| `hook.npm_lifecycle` | npm install-time script runs a command | high: fetches and runs, or encoded command; medium: inline code (`node -e`) or a download; low: runs a script file from the repo |
| `hook.vscode_folder_open` | VS Code task runs automatically when the folder is opened | high: fetches and runs, or hidden from view; medium: any other folder-open task |
| `hook.msbuild_exec` | Build file runs a command or inline code during the build | high: fetch and run, encoded command; medium: inline PowerShell/cmd, a download, an inline C# task |
| `hook.makefile_fetch_exec` | Makefile fetches from the network and runs it | high: fetch and run; medium: inline code; low: a download |
| `hook.setup_exec` | setup.py reaches the network or runs commands | high: network and process calls together; medium: network only; low: a process call only |
| `hook.build_backend_local` | Python build runs code from the repo or fetches build tools by URL | medium |
| `hook.git_hooks` | Git hooks are shipped in the repo | high: the hook fetches and runs code; medium: non-sample file in `.git/hooks` or inline code; low: a plain shipped hook |
| `text.invisible_unicode` | Invisible characters in a text file | high: bidi override, tag character, or any zero-width character in code, config or agent files; medium: zero-width in other text |
| `text.agent_instructions` | Text aimed at an AI agent | high: override/conceal/exfiltrate wording in an agent file or inside an HTML comment; medium: the same in visible README text or a code comment; low: weaker wording, or any line that is plainly discussing prompt injection |

Details for each rule (what it means, how it false-positives) are in the report, the JSON (`why`,
`false_positives`) and the SARIF rule help.

## Confidence and the verdict

Every finding is **low**, **medium** or **high**. Confidence is how likely a hit is to be a real problem rather than
a false positive. Generic heuristics (long lines, entropy, hollow repos, lures in docs) can and do false-positive,
so they are low or medium on purpose; only patterns that are rarely innocent reach high.

| Verdict | When |
| --- | --- |
| `malicious` | a file matches the known-bad hash list |
| `suspicious` | at least one high-confidence finding |
| `review` | medium findings, nothing higher |
| `weak_signals` | only low findings |
| `nothing_flagged` | no check fired |

**"No checks fired" is not a guarantee.** The checks are fixed patterns; they see only what they were written to
look for, and a new or well-hidden attack passes them. Every verdict carries `"trust": "advisory"` and says so.

## The known-bad hash list

`code_guardian/data/known_bad_hashes.json` ships **empty**: no hash is invented. Add your own entries, or pass a
second file with `--bad-hashes FILE` or the `CODE_GUARDIAN_BAD_HASHES` environment variable (entries are merged):

```
{
  "schema_version": 1,
  "sha256": {
    "<64 hex characters: the SHA-256 of a whole file>": "short label: a name, a report link, a date"
  }
}
```

A listed hash anywhere in the scanned copy forces the `malicious` verdict. Store only digests, never the sample. A
bad file (not JSON, wrong `schema_version`, a digest that is not 64 hex characters) stops the scan with a usage error
that names the problem.

## Bought-stars signal (optional, separate)

`--stars OWNER/REPO` asks the GitHub API for a sample of the repo's stargazers and reports three signals: a burst of
stars within a few hours, accounts created within 30 days of starring, and empty profiles. It needs **your own**
token in the `CODE_GUARDIAN_GITHUB_TOKEN` environment variable (or `GITHUB_TOKEN`). The token is read when the
command runs, sent only as a Bearer header to the API host (never over plain http except to a loopback test
server, redirects are not followed), and never stored, written or printed. Without a token, or on an API error or
rate limit, the signal is skipped with the reason. It is a **signal, not a verdict**: it never changes the intake
verdict, and a repository that reached a front page shows a burst without any buying.

## Output

JSON (`--json`): `tool`, `schema_version`, `version`, `trust`, `verdict` (`level`, `text`, `caveat`), `counts`,
`findings` (each: `rule`, `confidence`, `file`, `line`, `match`, `summary`, `why`, `false_positives`),
`quarantine`, `skipped`, `skipped_dirs`, `check_errors`, and `stars` when asked for. Key-shaped secrets in matched
text are masked. SARIF (`--sarif`) is 2.1.0 with one rule per check and one result per finding: `high` is `error`,
`medium` is `warning`, `low` is `note`; the matched text is the region snippet, and the verdict is in the run
properties.

## Advisory first, and how misses feed back

Intake verdicts are advisory. Treat the first batch of results on a new kind of repository as something to
read, not something to act on blindly: a person or an AI session looks at each finding and at what did *not* fire.
Anything wrong in either direction goes back into the repository as a case:

1. A false positive (a rule fired on something innocent) or a miss (a bad repo passed) is opened with the *Intake miss
   or false positive* issue form. Describe it with a small synthetic reproduction; never paste a real malware sample.
2. The case is added as a JSON file under `tests/intake_cases/` and watched fail (red) first.
3. The rule is changed until the case passes and the whole suite stays green.

`tests/test_intake_corpus.py` runs every case on every change, so a fixed mistake stays fixed.

## Limits

- Static text and header checks only: a payload fetched later from a server the repo never names, or hidden in a
  format the checks do not read (an archive inside an archive, an image with data appended), passes.
- Python is parsed (`ast`); JavaScript, shell, PowerShell and the rest are read as text, so code that runs on import
  is only detected in Python.
- Minified, vendored and generated files, security tools and test data legitimately contain the patterns; this
  repository's own tests do. That is why confidence exists.
- It does not look inside binaries beyond the header, and it does not look at git history.

## Credit

Check categories inspired by public write-ups on repo-borne malware (including Carter Perez's erinyes research); implemented independently.
