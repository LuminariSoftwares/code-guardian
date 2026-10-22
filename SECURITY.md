# Security policy

## Reporting a vulnerability

Report it privately through GitHub: open the repository's
[**Security** tab → **Report a vulnerability**](https://github.com/LuminariSoftwares/code-guardian/security/advisories/new)
(GitHub private vulnerability reporting). Please do not open a public issue for a vulnerability, and please do not
send it by email — the advisory thread keeps the report, the fix and the disclosure in one place.

Include what you have: the version (`code-guardian --version`), the platform, a repository or file that reproduces
it, and what you expected instead. If the reproduction itself contains something sensitive, describe its shape
rather than pasting it.

This is a single-maintainer project worked on in evenings and at weekends. Expect an acknowledgement within about a
week, and a fix released when there is one — there is no paid support and no bounty. Only the latest release is
patched.

## Supported versions

| version | supported |
|---|---|
| latest release on PyPI (`code-guardian-mcp`) | yes |
| anything older | no — upgrade |

## What leaves the machine

code-guardian is a static analyser. It parses the code it is pointed at (`ast` for Python, `json`/`tomllib`/
`configparser` for manifests, regular expressions for secrets) and never executes, imports or installs it.

- **A scan makes no network calls.** `code-guardian scan`, `baseline`, `diff`, `plan` and `orphans` — and the MCP
  tools of the same names — read files and write to stdout. Nothing is uploaded, no telemetry, no analytics.
- **`explain` (CLI `--explain`, MCP `explain`) posts findings to one URL: the one you configured.** Set
  `CODE_GUARDIAN_LLM_URL` (and optionally `CODE_GUARDIAN_LLM_MODEL`) and that endpoint, normally a local Ollama or
  an OpenAI-compatible server, receives the findings — code, level, `file:line`, summary and the scores. It does
  not receive your source. The payload goes through the same redaction as every other output: key shapes, AWS
  secrets, private-key headers and email addresses are masked, and the credentials a URL can carry (userinfo,
  query-parameter values, a webhook path) are masked in egress targets. With nothing configured, `explain` makes
  no request: the explanation is `null` and a note says why.
- **`--online` queries PyPI.** Only with that flag, and only to ask whether a dependency *name* exists
  (`https://pypi.org/pypi/<name>/json`). Without it the check uses the offline list of known project names
  shipped in the wheel. Your code is not sent.
- **`--history` reads your local git history** by running `git` in the repository. Nothing is pushed.

## What is written

- Only the files you ask for: `code-guardian baseline --out`, and whatever you redirect `--json`, `--sarif` or
  `--markdown` into. The GitHub Action writes the SARIF file you name.
- The scanned project is never modified. `plan` describes fixes; it does not apply them.
- A baseline holds `sha256` fingerprints, not source. A SARIF or JSON report holds findings with `file:line` and
  the redacted evidence line, so treat a report like any other build artefact: it names your files.

## Trust boundary for agents

The MCP tools return findings that quote text from the scanned repository — file paths, identifiers, string
literals. That text is data, not instruction. An agent acting on a report should not follow instructions that
appear inside it; the tool descriptions say so, and `scan`, `plan` and `orphans` repeat it in their replies'
documentation.
