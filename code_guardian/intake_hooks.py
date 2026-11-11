"""Repo intake, auto-run hooks: files that make something run when a repository is installed, built, opened in an
editor or committed to. All text is read from the quarantined copy and parsed as data (json, tomllib, ast, regex);
nothing is executed.

    hook.npm_lifecycle        package.json preinstall / install / postinstall / prepare scripts that fetch or run code
    hook.vscode_folder_open   .vscode/tasks.json tasks with runOptions.runOn = folderOpen (run when the folder opens)
    hook.msbuild_exec         MSBuild / .csproj Pre/PostBuildEvent and Exec commands that fetch or run code, inline tasks
    hook.makefile_fetch_exec  Makefile recipes that fetch and run code
    hook.setup_exec           setup.py that fetches from the network and/or runs commands
    hook.build_backend_local  pyproject.toml build backend that lives in the repo, or build requirements fetched by URL
    hook.git_hooks            git hooks shipped in the repo (.githooks, .husky, hooks/, non-sample .git/hooks files)
"""

import ast
import json
import re
import tomllib

from . import intake_rules as R
from .intake_rules import check, finding, command_signal

R.RULES.update({
    "hook.npm_lifecycle": {
        "title": "npm install-time script runs a command",
        "means": "package.json has a preinstall, install, postinstall or prepare script. npm runs these by itself when "
                 "someone installs the package or runs npm install in the folder, so whatever the script says runs "
                 "on your machine with your permissions.",
        "false_positives": "Many real packages build native code or set up git hooks this way (node-gyp, husky). "
                           "Those are not reported. A script that runs a file from the repo is low confidence: "
                           "read that file.",
    },
    "hook.vscode_folder_open": {
        "title": "VS Code task runs automatically when the folder is opened",
        "means": ".vscode/tasks.json has a task with runOn: folderOpen. Opening the folder in VS Code (after the "
                 "trust prompt, which many people click through) runs the task without you pressing anything.",
        "false_positives": "A few projects start a dev server or install dependencies this way on purpose.",
    },
    "hook.msbuild_exec": {
        "title": "Build file runs a command or inline code during the build",
        "means": "A .csproj / .targets / .props file has a PreBuildEvent, PostBuildEvent or Exec that fetches or runs "
                 "code, or an inline task that compiles and runs C# code. Building the project runs it.",
        "false_positives": "Copying files and restoring tools are common and not reported; scripts that do real work "
                           "(code generation) can still look like this.",
    },
    "hook.makefile_fetch_exec": {
        "title": "Makefile fetches from the network and runs it",
        "means": "A Makefile recipe downloads something and pipes it to a shell or runs it, or downloads at build time. "
                 "Running make runs it.",
        "false_positives": "Downloading a dependency or a test file in a recipe is normal (low confidence).",
    },
    "hook.setup_exec": {
        "title": "setup.py reaches the network or runs commands",
        "means": "setup.py is ordinary Python that runs when the package is installed from source (pip install, "
                 "python setup.py). One that downloads and runs things can do anything on your machine at install time.",
        "false_positives": "Reading a version from git or building a C extension runs commands legitimately "
                           "(low confidence).",
    },
    "hook.build_backend_local": {
        "title": "Python build runs code from the repo or fetches build tools by URL",
        "means": "pyproject.toml points the build at a backend inside the repo (backend-path), or lists a build "
                 "requirement fetched from a URL instead of the package index. Installing or building runs that code.",
        "false_positives": "A few projects ship their own small build backend on purpose.",
    },
    "hook.git_hooks": {
        "title": "Git hooks are shipped in the repo",
        "means": "The repo contains git hook scripts. They run on commit or push once a hooks path or a tool like "
                 "husky points git at them; a non-sample file inside .git/hooks runs without any setup at the next "
                 "git command, and a normal clone never contains one.",
        "false_positives": "Teams ship hooks for linting on purpose; most are low confidence unless they fetch or run code.",
    },
})

LIFECYCLE = ("preinstall", "install", "postinstall", "prepare")
NPM = {"obfuscated_exec": "high", "fetch_exec": "high", "inline_exec": "medium", "fetch_only": "medium", "local_script": "low"}
VSCODE = {"obfuscated_exec": "high", "fetch_exec": "high", "inline_exec": "high"}
MSBUILD = {"obfuscated_exec": "high", "fetch_exec": "high", "inline_exec": "medium", "fetch_only": "medium"}
MAKE = {"obfuscated_exec": "high", "fetch_exec": "high", "inline_exec": "medium", "fetch_only": "low"}
HOOK = {"obfuscated_exec": "high", "fetch_exec": "high", "inline_exec": "medium", "fetch_only": "medium"}
NETWORK_CALLS = ("urlopen", "urlretrieve", "urlcleanup", "create_connection", "HTTPConnection", "HTTPSConnection")
NETWORK_ROOTS = ("requests", "urllib3", "httpx", "aiohttp", "http")
EXEC_CALLS = ("system", "popen", "run", "call", "check_call", "check_output", "Popen", "exec", "eval", "execv", "execve",
              "execl", "spawn", "spawnl", "startfile")
KNOWN_BACKENDS = ("setuptools.", "hatchling.", "poetry.", "flit_core.", "maturin", "pdm.", "scikit_build_core.", "mesonpy",
                  "sipbuild.", "uv_build", "setuptools_scm", "flit.")


def _name(path):
    return path.rsplit("/", 1)[-1]


def _line_of(lines, needle, start=0):
    for i in range(start, len(lines)):
        if needle in lines[i]:
            return i + 1
    return 0


# ---- package.json ------------------------------------------------------------------------------------------------

@check("hook.npm_lifecycle")
def npm_lifecycle(ctx):
    out = []
    for rel in ctx.files:
        if _name(rel) != "package.json" or ctx.text(rel) is None:
            continue
        try:
            doc = json.loads(ctx.text(rel))
        except ValueError:
            continue
        scripts = doc.get("scripts") if isinstance(doc, dict) else None
        if not isinstance(scripts, dict):
            continue
        lines = ctx.lines(rel)
        for key in LIFECYCLE:
            cmd = scripts.get(key)
            kind = command_signal(cmd) if isinstance(cmd, str) else None
            if kind:
                line = _line_of(lines, '"%s"' % key)
                out.append(finding("hook.npm_lifecycle", NPM[kind], rel, line, "%s: %s" % (key, cmd),
                                   "%s script %s (%s)" % (key, "runs" if kind == "local_script" else "fetches or runs code",
                                                          kind.replace("_", " "))))
    return out


# ---- .vscode/tasks.json ------------------------------------------------------------------------------------------

def jsonc_loads(text):
    """json.loads for VS Code's JSON with comments and trailing commas."""
    out, i, n, in_str = [], 0, len(text), False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 1
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
            out.append(c)
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
            continue
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 1
        else:
            out.append(c)
        i += 1
    return json.loads(re.sub(r",(\s*[}\]])", r"\1", "".join(out)))


@check("hook.vscode_folder_open")
def vscode_folder_open(ctx):
    out = []
    for rel in ctx.files:
        name = _name(rel)
        if not (rel.endswith("/.vscode/tasks.json") or rel == ".vscode/tasks.json" or name.endswith(".code-workspace")):
            continue
        if ctx.text(rel) is None:
            continue
        try:
            doc = jsonc_loads(ctx.text(rel))
        except ValueError:
            continue
        tasks = (doc.get("tasks") if name.endswith(".code-workspace") and isinstance(doc, dict) else doc)
        tasks = tasks.get("tasks") if isinstance(tasks, dict) else None
        if not isinstance(tasks, list):
            continue
        lines, seen = ctx.lines(rel), 0
        for task in tasks:
            if not isinstance(task, dict):
                continue
            opts = task.get("runOptions")
            if not (isinstance(opts, dict) and opts.get("runOn") == "folderOpen"):
                continue
            line = _line_of(lines, "folderOpen", seen)
            seen = line
            cmd = " ".join([str(task.get("command", ""))] + [str(a) for a in task.get("args", []) if isinstance(a, (str, int))])
            kind = command_signal(cmd)
            pres = task.get("presentation") if isinstance(task.get("presentation"), dict) else {}
            hidden = pres.get("reveal") == "never" or pres.get("echo") is False
            conf = VSCODE.get(kind, "medium")
            if hidden and kind:
                conf = "high"
            out.append(finding("hook.vscode_folder_open", conf, rel, line, cmd.strip() or str(task.get("label", "")),
                               "task %r runs when the folder is opened%s" % (task.get("label", "?"), ", out of sight" if hidden else "")))
    return out


# ---- MSBuild -----------------------------------------------------------------------------------------------------

_MSB_EXT = (".csproj", ".vbproj", ".fsproj", ".vcxproj", ".targets", ".props", ".proj")
_MSB_EVENT = re.compile(r"<(PreBuildEvent|PostBuildEvent)>(.*?)</\1>", re.S)
_MSB_EXEC = re.compile(r"<Exec\b[^>]*?\bCommand\s*=\s*\"([^\"]*)\"", re.S)
_MSB_INLINE = re.compile(r"TaskFactory\s*=\s*\"(?:CodeTaskFactory|RoslynCodeTaskFactory)\"")
_ENTITIES = (("&amp;", "&"), ("&lt;", "<"), ("&gt;", ">"), ("&quot;", '"'), ("&apos;", "'"), ("&#10;", "\n"))


def _unxml(s):
    for a, b in _ENTITIES:
        s = s.replace(a, b)
    return s


def _line_at(text, pos):
    return text.count("\n", 0, pos) + 1


@check("hook.msbuild_exec")
def msbuild_exec(ctx):
    out = []
    for rel in ctx.files:
        if not rel.lower().endswith(_MSB_EXT) or ctx.text(rel) is None:
            continue
        text = ctx.text(rel)
        for rx, label in ((_MSB_EVENT, None), (_MSB_EXEC, "Exec")):
            for m in rx.finditer(text):
                cmd = _unxml(m.group(2 if label is None else 1)).strip()
                kind = command_signal(cmd)
                if kind in MSBUILD:
                    out.append(finding("hook.msbuild_exec", MSBUILD[kind], rel, _line_at(text, m.start()), cmd,
                                       "%s runs code at build time (%s)" % (label or m.group(1), kind.replace("_", " "))))
        for m in _MSB_INLINE.finditer(text):
            out.append(finding("hook.msbuild_exec", "medium", rel, _line_at(text, m.start()), m.group(0),
                               "inline task compiles and runs code during the build"))
    return out


# ---- Makefile ----------------------------------------------------------------------------------------------------

@check("hook.makefile_fetch_exec")
def makefile_fetch_exec(ctx):
    out = []
    for rel in ctx.files:
        name = _name(rel)
        if not (name in ("Makefile", "makefile", "GNUmakefile") or name.endswith(".mk")) or ctx.text(rel) is None:
            continue
        lines, i = ctx.lines(rel), 0
        while i < len(lines):
            start, joined = i, lines[i]
            while joined.rstrip().endswith("\\") and i + 1 < len(lines):
                i += 1
                joined = joined.rstrip()[:-1] + " " + lines[i].strip()
            i += 1
            if joined.lstrip().startswith("#"):
                continue
            kind = command_signal(joined)
            if kind in MAKE:
                out.append(finding("hook.makefile_fetch_exec", MAKE[kind], rel, start + 1, " ".join(joined.split()),
                                   "recipe %s" % kind.replace("_", " ")))
    return out


# ---- setup.py / pyproject.toml -----------------------------------------------------------------------------------

def _call_name(call):
    f = call.func
    parts = []
    while isinstance(f, ast.Attribute):
        parts.append(f.attr)
        f = f.value
    if isinstance(f, ast.Name):
        parts.append(f.id)
    return list(reversed(parts))


@check("hook.setup_exec")
def setup_exec(ctx):
    out = []
    for rel in ctx.files:
        if _name(rel) != "setup.py" or ctx.text(rel) is None:
            continue
        try:
            tree = ast.parse(ctx.text(rel))
        except (SyntaxError, ValueError):
            continue
        net, run = [], []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            parts = _call_name(node)
            if not parts:
                continue
            if parts[-1] in NETWORK_CALLS or (parts[0] in NETWORK_ROOTS and parts[-1] in ("get", "post", "request", "urlopen")):
                net.append(node)
            elif parts[-1] in EXEC_CALLS and (parts[0] in ("os", "subprocess", "pty", "commands") or parts[-1] in ("exec", "eval")):
                run.append(node)
        lines = ctx.lines(rel)
        if net and run:
            n = min(net + run, key=lambda c: c.lineno)
            out.append(finding("hook.setup_exec", "high", rel, n.lineno, lines[n.lineno - 1].strip(),
                               "setup.py reaches the network and also runs commands"))
        elif net:
            out.append(finding("hook.setup_exec", "medium", rel, net[0].lineno, lines[net[0].lineno - 1].strip(),
                               "setup.py reaches the network at install time"))
        elif run:
            out.append(finding("hook.setup_exec", "low", rel, run[0].lineno, lines[run[0].lineno - 1].strip(),
                               "setup.py runs a command at install time"))
    return out


@check("hook.build_backend_local")
def build_backend_local(ctx):
    out = []
    for rel in ctx.files:
        if _name(rel) != "pyproject.toml" or ctx.text(rel) is None:
            continue
        try:
            bs = tomllib.loads(ctx.text(rel)).get("build-system", {})
        except (tomllib.TOMLDecodeError, ValueError):
            continue
        lines = ctx.lines(rel)
        if bs.get("backend-path"):
            out.append(finding("hook.build_backend_local", "medium", rel, _line_of(lines, "backend-path"),
                               "backend-path = %s, build-backend = %s" % (bs["backend-path"], bs.get("build-backend", "?")),
                               "the build runs a backend that lives in the repo"))
        for req in bs.get("requires", []) or []:
            if isinstance(req, str) and re.search(r"@\s*(?:https?|git\+|file|ftp)", req):
                out.append(finding("hook.build_backend_local", "medium", rel, _line_of(lines, req.split("@")[0].strip()), req,
                                   "a build requirement is fetched from a URL, not the package index"))
    return out


# ---- shipped git hooks -------------------------------------------------------------------------------------------

_HOOK_DIRS = (".githooks/", ".husky/", "hooks/", ".git/hooks/")


@check("hook.git_hooks")
def git_hooks(ctx):
    out = []
    for rel in ctx.files:
        if not rel.startswith(_HOOK_DIRS) or rel.startswith(".husky/_/") or rel.endswith(".sample"):
            continue
        text = ctx.text(rel)
        if text is None:
            continue
        in_git = rel.startswith(".git/hooks/")
        best, hit = None, (0, "")
        for i, line in enumerate(text.split("\n"), 1):
            kind = command_signal(line)
            if kind in HOOK and (best is None or R.CONFIDENCES.index(HOOK[kind]) > R.CONFIDENCES.index(best)):
                best, hit = HOOK[kind], (i, line.strip())
        conf = best or ("medium" if in_git else "low")
        if in_git and conf == "low":
            conf = "medium"
        line, match = hit if best else (1, text.split("\n", 1)[0].strip())
        out.append(finding("hook.git_hooks", conf, rel, line, match,
                           ("a non-sample file in .git/hooks runs at the next git command" if in_git
                            else "ships a git hook script") + ("; it fetches or runs code" if best else "")))
    return out
