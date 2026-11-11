"""Repo intake, code that runs without being called, and instructions that talk a reader into running something.

    exec.on_import     Python module scope (including class bodies, try/if/with/for at module level) that reaches the
                       network, starts a process or execs/evals; not function bodies, not an `if __name__ == "__main__"`
                       block. __init__.py is where this is most dangerous: importing the package runs it.
    exec.pth_import    a .pth file with an `import` line (Python runs these at every interpreter start)
    lure.pipe_to_shell README / docs steps that pipe a download into a shell
    lure.run_download  README / docs steps that tell you to download and run an executable, switch off antivirus, run
                       as administrator, or open an archive with a password

The code is parsed with ast and never imported or run.
"""

import ast
import re
from urllib.parse import urlparse

from . import intake_rules as R
from .intake_rules import check, finding, command_signal

R.RULES.update({
    "exec.on_import": {
        "title": "Code runs as soon as the module is imported",
        "means": "At the top level of a Python file (not inside a function) there is a call that uses the network, "
                 "starts a program or runs exec/eval. Importing the package runs it, with no one calling anything; "
                 "in __init__.py that means a plain `import` or a test run triggers it.",
        "false_positives": "Scripts that do their work at the top level (scripts/, examples/) and small helpers that read "
                           "a git version at import are common; those are lower confidence.",
    },
    "exec.pth_import": {
        "title": ".pth file that runs code",
        "means": "Python executes any line of a .pth file that starts with `import` every time the interpreter "
                 "starts, in every program that uses that environment.",
        "false_positives": "Some packaging tools write one-line .pth files; a .pth committed to a repo is unusual.",
    },
    "lure.pipe_to_shell": {
        "title": "Docs tell you to pipe a download into a shell",
        "means": "A README or doc step downloads a script and runs it in one go (curl ... | sh, iwr ... | iex). You "
                 "never see what ran. A plain https install line from a well-known project is common; one from a raw "
                 "IP address, an http link or a link shortener is high.",
        "false_positives": "Many honest projects document an install one-liner this way (medium).",
    },
    "lure.run_download": {
        "title": "Docs push you toward running a downloaded program",
        "means": "A README or doc step tells you to download and run an executable or installer, to switch off antivirus "
                 "or run as administrator, or gives a password for an archive (a way to stop scanners opening it). "
                 "Fake 'releases' work this way.",
        "false_positives": "Windows tools legitimately say run as administrator, and projects ship installers; the "
                           "antivirus and archive-password patterns are the strong ones.",
    },
})

NETWORK_CALLS = frozenset({"urlopen", "urlretrieve", "create_connection", "HTTPConnection", "HTTPSConnection"})
NETWORK_ROOTS = frozenset({"requests", "urllib3", "httpx", "aiohttp"})
HTTP_VERBS = frozenset({"get", "post", "put", "request", "head", "patch", "delete", "urlopen"})
RUN_CALLS = frozenset({"system", "popen", "run", "call", "check_call", "check_output", "Popen", "execv", "execve", "execl", "execlp",
                       "execvp", "spawnl", "spawnv", "startfile"})
DECODERS = frozenset({"b64decode", "decompress", "fromhex", "unhexlify", "loads", "decode", "a2b_base64", "urlsafe_b64decode"})
INIT_NAMES = ("__init__.py", "sitecustomize.py", "usercustomize.py")
NOT_IMPORTED_DIRS = frozenset({"scripts", "script", "bin", "examples", "example", "docs", "tools", "benchmarks", "demo", "demos"})


def _parts(call):
    f, parts = call.func, []
    while isinstance(f, ast.Attribute):
        parts.append(f.attr)
        f = f.value
    if isinstance(f, ast.Name):
        parts.append(f.id)
    return list(reversed(parts))


def _is_main_guard(test):
    return isinstance(test, ast.Compare) and any(isinstance(c, ast.Constant) and c.value == "__main__" for c in test.comparators) \
        and isinstance(test.left, ast.Name) and test.left.id == "__name__"


class _ModuleScope(ast.NodeVisitor):
    """Collect the dangerous calls that run when the module is imported: everything outside function bodies."""

    def __init__(self):
        self.hits = []  # (lineno, kind, obfuscated)

    def visit_FunctionDef(self, node):  # defined, not run
        return

    visit_AsyncFunctionDef = visit_FunctionDef
    visit_Lambda = visit_FunctionDef

    def visit_If(self, node):
        if _is_main_guard(node.test):
            for n in node.orelse:
                self.visit(n)
            return
        self.generic_visit(node)

    def visit_Call(self, node):
        parts = _parts(node)
        if parts:
            kind = None
            if parts[-1] in NETWORK_CALLS or (parts[0] in NETWORK_ROOTS and parts[-1] in HTTP_VERBS):
                kind = "network"
            elif parts[0] in ("os", "subprocess", "pty") and parts[-1] in RUN_CALLS:
                kind = "process"
            elif parts in (["exec"], ["eval"], ["execfile"]):
                kind = "exec"
            if kind:
                obf = kind == "exec" and any(isinstance(n, ast.Call) and _parts(n) and _parts(n)[-1] in DECODERS for n in ast.walk(node))
                self.hits.append((node.lineno, kind, obf))
        self.generic_visit(node)


def _where(rel):
    segs = rel.split("/")
    name = segs[-1]
    if "tests" in segs[:-1] or "test" in segs[:-1] or name.startswith("test_") or name.endswith("_test.py"):
        return "test"
    if name in INIT_NAMES:
        return "init"
    if NOT_IMPORTED_DIRS & set(segs[:-1]):
        return "script"
    return "module"


@check("exec.on_import")
def on_import(ctx):
    out = []
    for rel in ctx.files:
        if R.ext(rel) not in (".py", ".pyw") or rel.rsplit("/", 1)[-1] == "setup.py" or ctx.text(rel) is None:
            continue
        try:
            tree = ast.parse(ctx.text(rel))
        except (SyntaxError, ValueError):
            continue
        scope = _ModuleScope()
        for stmt in tree.body:
            scope.visit(stmt)
        if not scope.hits:
            continue
        line, kind, obf = min(scope.hits)
        where = _where(rel)
        conf = {"init": "high", "module": "medium", "script": "low", "test": "low"}[where]
        if obf and where != "test":
            conf = "high"
        out.append(finding("exec.on_import", conf, rel, line, ctx.lines(rel)[line - 1].strip(),
                           "%s call at module level runs on import%s (%d in this file)" % (kind, " (decodes then execs)" if obf else "", len(scope.hits))))
    return out


@check("exec.pth_import")
def pth_import(ctx):
    out = []
    for rel in ctx.files:
        if not rel.endswith(".pth") or ctx.text(rel) is None:
            continue
        for i, line in enumerate(ctx.lines(rel), 1):
            if re.match(r"import[ \t]", line):
                out.append(finding("exec.pth_import", "high", rel, i, line.strip(), ".pth line that runs code at interpreter start"))
                break
    return out


# ---- lures -------------------------------------------------------------------------------------------------------

DOC_EXT = frozenset({".md", ".markdown", ".txt", ".rst", ".adoc", ".mdx"})
SHORTENERS = ("bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "pastebin.com", "paste.ee", "hastebin.com",
              "ghostbin", "transfer.sh", "anonfiles", "cdn.discordapp.com", "gofile.io", "mega.nz", "temp.sh")
URL = re.compile(r"https?://[^\s'\"`)<>|]+")
EXE_RUN = re.compile(r"(?i)\b(download|install|run|launch|open|double[- ]click|execute|extract|unzip)\b[^.\n]{0,60}?\b([\w.-]+\.(?:exe|msi|scr|bat|cmd|ps1|vbs|jar|dmg|pkg|apk|appimage|lnk))\b")
AV_OFF = re.compile(r"(?i)(?:disable|turn off|pause|exclude|whitelist|add (?:an )?exclusion|bypass)[^.\n]{0,40}(?:antivirus|anti-virus|defender|windows security|smartscreen)")
ARCHIVE_PW = re.compile(r"(?i)\b(?:archive|zip|rar|7z)\b[^.\n]{0,60}\bpassword\b|\bpassword\b[^.\n]{0,30}\b(?:archive|zip|rar|7z)\b|^\s*(?:[-*>]|\d+[.)])?\s*password\s*:\s*\S{2,}")
AS_ADMIN = re.compile(r"(?i)run (?:it |as |this )?(?:as )?(?:an )?administrator|as admin(?:istrator)?\b")
DEEP_VERBS = ("download", "install", "double-click", "double click", "extract", "unzip")


def _url_risk(line):
    for u in URL.findall(line):
        p = urlparse(u)
        host = (p.hostname or "").lower()
        if p.scheme == "http" or re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host) or any(host == s or host.endswith("." + s) or s in host for s in SHORTENERS):
            return True
    return False


@check("lure.pipe_to_shell")
def pipe_to_shell(ctx):
    out = []
    for rel in ctx.files:
        if R.ext(rel) not in DOC_EXT or ctx.text(rel) is None:
            continue
        for i, line in enumerate(ctx.lines(rel), 1):
            kind = command_signal(line)
            if kind in ("fetch_exec", "obfuscated_exec") and (kind == "obfuscated_exec" or "|" in line):
                conf = "high" if kind == "obfuscated_exec" or _url_risk(line) else "medium"
                out.append(finding("lure.pipe_to_shell", conf, rel, i, line.strip(),
                                   "docs pipe a download into a shell%s" % (" from a risky address" if conf == "high" else "")))
                break
    return out


@check("lure.run_download")
def run_download(ctx):
    out = []
    for rel in ctx.files:
        if R.ext(rel) not in DOC_EXT or ctx.text(rel) is None:
            continue
        done = set()
        for i, line in enumerate(ctx.lines(rel), 1):
            for kind, rx, conf in (("antivirus", AV_OFF, "high"), ("archive password", ARCHIVE_PW, "high"), ("administrator", AS_ADMIN, "medium"),
                                   ("run executable", EXE_RUN, None)):
                m = rx.search(line)
                if not m or kind in done:
                    continue
                if kind == "run executable":
                    conf = "medium" if m.group(1).lower() in DEEP_VERBS else "low"
                done.add(kind)
                out.append(finding("lure.run_download", conf, rel, i, line.strip(), "docs: %s" % kind))
    return out
