"""Shipped AI-agent configuration files, reported as Safe findings. Reads text; never runs, imports or installs it.

A repository can ship files that steer an AI coding agent: hook commands, permission lists, MCP server launch lines and
instruction files. Whoever clones it and opens an agent in the folder inherits them. This module reads those files
from the scanned root and reports the risky parts. It opens nothing but the files named below, follows no symlink,
skips the walk's SKIP_DIRS and runs nothing: no hook, no server command and no package manager is ever started.

The idea (scan a repository's agent configs and instruction files for risky hooks, auto-approve settings, unpinned
MCP servers and injection text) comes from MCP and agent security scanners reviewed on Glama, for example
invariantlabs-ai/mcp-scan. This module is rewritten from the idea; no code, test, wording or identifier is copied.

Files read, relative to the scanned root:
    .claude/settings.json  .claude/settings.local.json  .mcp.json  .cursor/mcp.json  .cursor/rules*
    AGENTS.md  CLAUDE.md  GEMINI.md  .github/copilot-instructions.md

Findings (all Safe; a finding here keeps its level in a .md file, because to an agent that file is the product):
    safe.agent_hook_runs_command  WARN   a hooks entry with a `command`
    safe.agent_auto_approve       FAIL   skipPermissions / dangerouslySkipPermissions on, or permissions.allow holding
                                         `Bash(*)` or `*`
    safe.agent_pipe_to_shell      FAIL   a curl or wget fetch piped into sh or bash, in a hook or an instruction file
    safe.agent_mcp_unpinned       WARN   an MCP server launched by npx, uvx or pipx run with no version fixed
                                         (one finding per server; a server with a version fixed gets none)
    safe.agent_injection_text     WARN   text matching an injection.* pattern in data/injection_patterns.json
    safe.agent_hidden_unicode     FAIL   a character in the injection.hidden_unicode class of the same file

Public contract:
    FILES, CODES
    find(root) -> [rel]                      the agent config files that exist under root, sorted
    check(root, rels) -> {"findings": [...], "read": [rel], "unreadable": [rel]}
    load_patterns() -> {"regex": [(injection code, compiled, note)], "unicode": [(code, [(lo, hi)], note)]}
"""

import json
import os
import re
from pathlib import Path

from . import walk
from .finding import make_finding

CONFIG_FILES = (".claude/settings.json", ".claude/settings.local.json", ".mcp.json", ".cursor/mcp.json")
INSTRUCTION_FILES = ("AGENTS.md", "CLAUDE.md", "GEMINI.md", ".github/copilot-instructions.md")
FILES = CONFIG_FILES + (".cursor/rules*",) + INSTRUCTION_FILES
CODES = ("safe.agent_hook_runs_command", "safe.agent_auto_approve", "safe.agent_pipe_to_shell",
         "safe.agent_mcp_unpinned", "safe.agent_injection_text", "safe.agent_hidden_unicode")
PATTERNS_FILE = Path(__file__).resolve().parent / "data" / "injection_patterns.json"
RULES_DEPTH = 4
SHOW = 80  # characters of a command quoted in evidence

PIPE_TO_SHELL = re.compile(r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:/(?:usr/)?bin/)?(?:ba)?sh\b")
AUTO_KEYS = ("skippermissions", "dangerouslyskippermissions")
OPEN_ALLOW = ("Bash(*)", "*")
RUNNERS = ("npx", "uvx", "pipx")
VERSION_AT = re.compile(r"[\w\]]@v?\d")
SERVER_TABLES = ("mcpServers", "servers")


# ---- finding and reading -----------------------------------------------------------------------------------------

def _finding(code, level, rel, line, summary, evidence, advice):
    return make_finding(code, "partial", level, "%s:%d" % (rel, line), summary, evidence=list(evidence),
                        try_=[advice])


def _line_of(text, *needles):
    """1-based line of the first needle found in text, else 1."""
    for needle in needles:
        at = text.find(needle) if needle else -1
        if at >= 0:
            return text.count("\n", 0, at) + 1
    return 1


def _plain_file(root, rel):
    """True when every part of rel is a real folder or file below root (no symlink, no skipped folder)."""
    here = root
    for part in rel.split("/"):
        if part in walk.SKIP_DIRS:
            return False
        here = os.path.join(here, part)
        if os.path.islink(here):
            return False
    return os.path.isfile(here)


def _rules_files(root):
    """The files under .cursor named rules* (a file `rules`, or the files inside a `rules` folder), as rel paths."""
    out, base = [], os.path.join(root, ".cursor")
    if os.path.islink(base) or not os.path.isdir(base):
        return out
    try:
        names = sorted(n for n in os.listdir(base) if n.startswith("rules"))
    except OSError:
        return out

    def descend(rel, depth):
        here = os.path.join(root, *rel.split("/"))
        if os.path.islink(here):
            return
        if os.path.isdir(here):
            if depth > RULES_DEPTH:
                return
            try:
                kids = sorted(os.listdir(here))
            except OSError:
                return
            for kid in kids:
                if kid not in walk.SKIP_DIRS:
                    descend(rel + "/" + kid, depth + 1)
        elif os.path.isfile(here):
            out.append(rel)

    for name in names:
        descend(".cursor/" + name, 0)
    return out


def find(root):
    """The agent config files that exist under root: sorted rel paths with forward slashes."""
    root = os.fspath(root)
    rels = [rel for rel in CONFIG_FILES + INSTRUCTION_FILES if _plain_file(root, rel)]
    return sorted(set(rels + _rules_files(root)))


def _read(root, rel):
    path = os.path.join(root, *rel.split("/"))
    if os.path.getsize(path) > walk.MAX_BYTES:
        raise OSError("larger than %d bytes" % walk.MAX_BYTES)
    with open(path, "rb") as fh:
        return fh.read().decode("utf-8", errors="replace")


def _is_json(rel):
    return rel.endswith(".json")


# ---- the injection patterns ----------------------------------------------------------------------------------------

def _ranges(spec):
    out = []
    for part in str(spec).split(","):
        part = part.strip()
        if part:
            lo, _, hi = part.partition("-")
            out.append((int(lo, 16), int(hi or lo, 16)))
    return out


_PATTERNS = {}


def load_patterns():
    """{"regex": [(code, compiled, note)], "unicode": [(code, [(lo, hi)], note)]} from data/injection_patterns.json."""
    if not _PATTERNS:
        data = json.loads(PATTERNS_FILE.read_text(encoding="utf-8"))
        regex, uni = [], []
        for p in data["patterns"]:
            if p["kind"] == "regex":
                regex.append((p["code"], re.compile(p["value"]), p.get("note", "")))
            elif p["kind"] == "unicode_class":
                uni.append((p["code"], _ranges(p["value"]), p.get("note", "")))
        _PATTERNS.update({"regex": regex, "unicode": uni})
    return _PATTERNS


# ---- the checks ----------------------------------------------------------------------------------------------------

def _hidden_unicode(rel, text, patterns):
    out = []
    for code, ranges, note in patterns["unicode"]:
        if code != "injection.hidden_unicode":
            continue
        for lineno, line in enumerate(text.split("\n"), 1):
            marks = []
            for col, ch in enumerate(line, 1):
                if lineno == 1 and col == 1 and ch == "﻿":
                    continue  # a byte-order mark at the very start of a file is how some editors save it
                if any(lo <= ord(ch) <= hi for lo, hi in ranges):
                    marks.append("U+%04X at column %d" % (ord(ch), col))
            if marks:
                out.append(_finding(
                    "safe.agent_hidden_unicode", "FAIL", rel, lineno,
                    "%s holds %d invisible character(s) a reader cannot see" % (rel, len(marks)),
                    ["found: " + ", ".join(marks[:5]) + (" and %d more" % (len(marks) - 5) if len(marks) > 5 else ""),
                     "class: %s" % (note or code)],
                    "delete the invisible characters, or open the file in an editor that shows them"))
    return out


def _injection_text(rel, text, patterns):
    out = []
    for lineno, line in enumerate(text.split("\n"), 1):
        seen = set()
        for code, rx, note in patterns["regex"]:
            if code in seen or code == "injection.hidden_unicode" or not rx.search(line):
                continue
            seen.add(code)
            out.append(_finding(
                "safe.agent_injection_text", "WARN", rel, lineno,
                "%s line %d reads like an instruction aimed at the agent (%s)" % (rel, lineno, code),
                ["pattern: %s" % code, "why: %s" % (note or code)],
                "read the line; delete it unless you wrote it and want an agent to follow it"))
    return out


def _pipe_to_shell(rel, line, where, command):
    if not PIPE_TO_SHELL.search(command):
        return None
    return _finding("safe.agent_pipe_to_shell", "FAIL", rel, line,
                    "%s fetches a script from the network and runs it unread" % where,
                    ["in: %s" % where, "text: %s" % (command.strip()[:SHOW] + ("..." if len(command.strip()) > SHOW else ""))],
                    "download the script, read it, pin it by checksum, then run it")


def _instruction_checks(rel, text, patterns):
    out = _injection_text(rel, text, patterns)
    for lineno, line in enumerate(text.split("\n"), 1):
        got = _pipe_to_shell(rel, lineno, "%s line %d" % (rel, lineno), line)
        if got:
            out.append(got)
    return out


def _hook_commands(node, event=None):
    """[(event, command)] for every dict with a str `command` under the hooks table."""
    out = []
    if isinstance(node, dict):
        if isinstance(node.get("command"), str) and node["command"].strip():
            out.append((event, node["command"]))
        for key, value in node.items():
            out.extend(_hook_commands(value, event or (key if isinstance(key, str) else None)))
    elif isinstance(node, list):
        for item in node:
            out.extend(_hook_commands(item, event))
    return out


def _walk_keys(node):
    """(key, value) for every key in a JSON value, at any depth."""
    if isinstance(node, dict):
        for key, value in node.items():
            yield key, value
            yield from _walk_keys(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_keys(item)


def _auto_approve(rel, text, data):
    out = []
    for key, value in _walk_keys(data):
        if isinstance(key, str) and key.lower() in AUTO_KEYS and value is True:
            out.append(_finding("safe.agent_auto_approve", "FAIL", rel, _line_of(text, '"%s"' % key),
                                "%s switches the agent's permission prompts off (%s)" % (rel, key),
                                ["setting: %s is on" % key],
                                "remove it, so the agent asks before it acts"))
    perms = data.get("permissions") if isinstance(data, dict) else None
    allow = perms.get("allow") if isinstance(perms, dict) else None
    for item in allow if isinstance(allow, list) else ():
        if isinstance(item, str) and item.strip() in OPEN_ALLOW:
            out.append(_finding("safe.agent_auto_approve", "FAIL", rel, _line_of(text, json.dumps(item), item),
                                "%s lets the agent run %s without asking" % (
                                    rel, "any shell command" if item.strip() == "Bash(*)" else "any tool"),
                                ["permissions.allow holds %s" % item.strip()],
                                "allow only the exact commands the project needs, such as Bash(npm test)"))
    return out


def _hooks(rel, text, data):
    out = []
    hooks = data.get("hooks") if isinstance(data, dict) else None
    for event, command in _hook_commands(hooks) if hooks else ():
        line = _line_of(text, json.dumps(command)[1:-1], command)
        where = "%s hook %s" % (rel, event or "entry")
        out.append(_finding("safe.agent_hook_runs_command", "WARN", rel, line,
                            "%s runs a shell command every time it fires" % where,
                            ["event: %s" % (event or "unknown"),
                             "command: %s" % (command.strip()[:SHOW] + ("..." if len(command.strip()) > SHOW else ""))],
                            "read the command; keep it only if you want it to run on every collaborator's machine"))
        got = _pipe_to_shell(rel, line, where, command)
        if got:
            out.append(got)
    return out


def _package_of(argv):
    """The package an npx / uvx / pipx launch line fetches, or None. argv is the command and its arguments."""
    if not argv:
        return None
    runner = os.path.basename(str(argv[0]).replace("\\", "/")).lower()
    runner = re.sub(r"\.(cmd|exe|bat)$", "", runner)
    if runner not in RUNNERS:
        return None
    rest = [str(a) for a in argv[1:]]
    if runner == "pipx":
        if "run" not in rest:
            return None
        rest = rest[rest.index("run") + 1:]
    takes_value = {"--from", "-p", "--package", "--spec"}
    i = 0
    while i < len(rest):
        arg = rest[i]
        if arg in takes_value and i + 1 < len(rest):
            return rest[i + 1]
        if arg.startswith("--from=") or arg.startswith("--package=") or arg.startswith("--spec="):
            return arg.partition("=")[2]
        if arg.startswith("-"):
            i += 1
            continue
        return arg
    return None


def _fixed_version(package):
    if "==" in package:
        return True
    if "://" in package or package.startswith("git+"):
        return "@" in package.rsplit("/", 1)[-1]
    return bool(VERSION_AT.search(package))


def _local(package):
    return package.startswith((".", "/", "~", "file:")) or re.match(r"^[A-Za-z]:[\\/]", package) is not None


def _mcp_servers(rel, text, data):
    out = []
    tables = [data.get(k) for k in SERVER_TABLES] if isinstance(data, dict) else []
    for table in tables:
        if not isinstance(table, dict):
            continue
        for name, spec in table.items():
            if not isinstance(spec, dict) or not isinstance(spec.get("command"), str):
                continue
            args = spec.get("args") if isinstance(spec.get("args"), list) else []
            package = _package_of(spec["command"].split() + args)
            if not package or _local(package) or _fixed_version(package):
                continue
            out.append(_finding("safe.agent_mcp_unpinned", "WARN", rel, _line_of(text, json.dumps(name)),
                                "MCP server %s fetches %s with no version fixed, so each run can fetch new code" % (
                                    name, package),
                                ["server: %s" % name, "package: %s" % package,
                                 "launched by: %s" % os.path.basename(spec["command"].split()[0])],
                                "name an exact version, such as %s@1.2.3 (npx) or %s==1.2.3 (uvx, pipx)" % (
                                    package.split("@")[0] or "package", package.split("==")[0])))
    return out


def check(root, rels):
    """Read each file in rels (from find) and return {"findings", "read", "unreadable"}. Nothing is run."""
    root, patterns = os.fspath(root), load_patterns()
    findings, read, unreadable = [], [], []
    for rel in rels:
        try:
            text = _read(root, rel)
        except OSError:
            unreadable.append(rel)
            continue
        read.append(rel)
        findings.extend(_hidden_unicode(rel, text, patterns))
        if _is_json(rel):
            try:
                data = json.loads(text)
            except ValueError:
                continue  # not JSON: the invisible-character scan above is all that can be said
            findings.extend(_auto_approve(rel, text, data))
            findings.extend(_hooks(rel, text, data))
            findings.extend(_mcp_servers(rel, text, data))
        else:
            findings.extend(_instruction_checks(rel, text, patterns))
    return {"findings": findings, "read": read, "unreadable": unreadable}
