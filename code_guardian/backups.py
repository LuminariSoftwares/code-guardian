"""Which folders and files look like backup copies, and which of them may be offered for leaving out of a check.

AI-written projects collect copies: an _archive/ folder, old/, main.py.backup-20260824. Their findings are real
findings in files nobody runs, and they can bury the ones that matter. This module names those copies and says which
of them the page may offer to leave out. It never leaves anything out itself: an offer is a question for the person,
and a copy that is not offered says why (P88 C1).

Pure: it reads only what it is given (findings, the walk, an orphans.Graph, file texts); nothing is executed or read
from the disk.

Public contract:
    FOLDER (regex of a backup folder's name), FILE_MARKS, FILE_ENDS, NEVER_LEFT_OUT, ALWAYS_HELD
    looks_like_backup(rel) -> the glob the path falls under ("_archive/*", "pkg/_backups/*", "*.backup-*") or None
    wanted(findings) -> True when a finding sits in a backup copy (only then does offer need graph and texts)
    offer(findings, inventory, graph=None, texts=None) -> (offered, held)
        offered: [{"glob", "files", "findings", "by_code": {"<code> <level>": n}, "fail"}], most findings first
        held:    [{"glob", "why"}]   a copy with findings that is not offered, and the reason in plain words

A copy is offered only when it has at least one finding and the code kept beside it does not use it. It is held when
a module outside it imports a module inside it (graph), when a file outside it holds a string naming its folder with a
path separator, or exactly ("_archive/seed.json", "old"; a bare word in a sentence is not enough) (texts), or when it
holds an install.hook finding at any level or an obfuscation / exec.dynamic / exec.shell FAIL: a risk that runs
code is never left out on a suggestion. Without graph or texts those two checks cannot be made and hold nothing.

    python -m code_guardian.backups --selftest
"""

import ast
import glob as globlib
import io
import re
import sys
import tokenize

from .finding import summarize
from .orphans import Graph, module_name

# A folder whose whole name says it is a copy: _archive, old, backups, Backup-2026-08-24, _old_20260824, to_delete.
# Matched case-insensitively against one path segment; "old_timer" and "archive.py" are not copies.
FOLDER = re.compile(r"^_?(?:archive|archived|archives|backup|backups|bak|old|to_delete|trash)(?:[-_. ]?\d[\d._-]*)?$",
                    re.IGNORECASE)
FILE_MARKS = (".backup-", ".bak-")  # a mark inside the name: main.py.backup-20260824 -> "*.backup-*"
FILE_ENDS = (".backup", ".bak", ".orig", ".old", "~")  # a mark at the end: settings.py.bak -> "*.bak"
ALWAYS_HELD = frozenset({"install.hook"})  # held at any level: it runs at install time, wherever it sits
NEVER_LEFT_OUT = frozenset({"obfuscation", "exec.dynamic", "exec.shell"})  # held at FAIL
_SEP = re.compile(r"[/\\]")
_QUOTED = re.compile(r"\"([^\"\r\n]*)\"|'([^'\r\n]*)'")
_WORD = re.compile(r"[^\s\"'`<>()\[\]{},;=|]+")
_DOTTED = re.compile(r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+$")
_PREFIX = re.compile(r"^[A-Za-z]*(\"\"\"|'''|\"|')")


def _mark(name):
    """The glob a file or folder name's backup mark gives ("*.backup-*", "*.BAK"), keeping the case as walked."""
    low = name.lower()
    for mark in FILE_MARKS:
        at = low.find(mark, 1)
        if at > 0:
            return "*" + name[at:at + len(mark)] + "*"
    for end in FILE_ENDS:
        if low.endswith(end) and len(name) > len(end):
            return "*" + name[len(name) - len(end):]
    return None


def looks_like_backup(rel):
    """The glob rel falls under, outermost copy first, or None. A backup folder at any depth gives its own path
    ("pkg/_backups/*"); a backup mark on a name gives the mark's glob ("*.backup-*"), which the walk also applies to
    a folder so named. Either glob, given as an exclude, leaves out exactly the paths that fall under it."""
    parts = rel.split("/")
    for i, seg in enumerate(parts):
        if i < len(parts) - 1 and FOLDER.match(seg):
            return globlib.escape("/".join(parts[:i + 1])) + "/*"
        mark = _mark(seg)
        if mark:
            return mark
    return None


def _rel(node):
    """The file a finding's node names: "_archive/a.py:3" -> "_archive/a.py"."""
    node = str(node)
    return node.rpartition(":")[0] or node


def wanted(findings):
    return any(looks_like_backup(_rel(f["node"])) for f in findings)


def _folder(glob):
    """(the folder's last segment, its module path) for a folder glob, or (None, None) for a mark glob."""
    if not glob.endswith("/*") or glob.startswith("*"):
        return None, None
    folder = re.sub(r"\[(.)\]", r"\1", glob[:-2])  # undo globlib.escape
    return folder.rsplit("/", 1)[-1], module_name(folder + "/__init__.py")


def _into(qualified, prefix, inside):
    """True when a qualified import name reaches into the copy: its folder's module path, or one of its modules."""
    if prefix and (qualified == prefix or qualified.startswith(prefix + ".")):
        return True
    return any(qualified == m or qualified.startswith(m + ".") for m in inside)


def _importers(graph, glob, prefix):
    """The files outside the copy whose imports reach into it, sorted."""
    inside = {m for m, rel in graph.modules.items() if looks_like_backup(rel) == glob}
    out = set()
    for mod, rel in graph.modules.items():
        if mod in inside:
            continue
        names = list(graph.aliases.get(mod, {}).values()) + list(graph.stars.get(mod, ()))
        if any(_into(q, prefix, inside) for q in names):
            out.add(rel)
    return sorted(out)


def _literals(rel, text):
    """(strings, words) of one file: the string literals (a Python file's tokens, else what sits in quotes), and for a
    file that is not Python every path-shaped word too (a config value need not be quoted)."""
    strings = []
    if rel.endswith(".py"):
        try:
            for tok in tokenize.generate_tokens(io.StringIO(text).readline):
                if tok.type == tokenize.STRING:
                    strings.append(_PREFIX.sub("", tok.string).strip("\"'"))
                elif tok.type == getattr(tokenize, "FSTRING_MIDDLE", None):
                    strings.append(tok.string)
            return strings, []
        except (tokenize.TokenError, SyntaxError, ValueError):
            strings = []
    strings = [a or b for a, b in _QUOTED.findall(text)]
    return strings, [w for w in _WORD.findall(text) if _SEP.search(w)]


def _names(literal, segment, python):
    """True when a string names the folder: with a path separator, exactly, or (Python) as a dotted module path."""
    pattern = r"(?:^|[/\\])%s(?:[/\\]|$)" % re.escape(segment)
    if re.search(pattern, literal, re.IGNORECASE):
        return True
    return python and bool(_DOTTED.match(literal)) and segment.lower() in literal.lower().split(".")


def _naming_files(texts, glob, segment):
    out = []
    for rel in sorted(texts):
        if looks_like_backup(rel) == glob:
            continue
        strings, words = _literals(rel, texts[rel])
        python = rel.endswith(".py")
        if (any(_names(s, segment, python) for s in strings)
                or any(re.search(r"(?:^|[/\\])%s[/\\]" % re.escape(segment), w, re.IGNORECASE) for w in words)):
            out.append(rel)
    return out


def _listing(rels, one, many):
    """'app/main.py imports it', 'a.py, b.py and 2 more import it'."""
    shown = ", ".join(rels[:3]) + (" and %d more" % (len(rels) - 3) if len(rels) > 3 else "")
    return "%s %s" % (shown, one if len(rels) == 1 else many)


def _why(glob, group, graph, texts):
    """The reasons a copy with findings is not offered, in plain words; empty when it may be offered."""
    reasons = []
    risky = [f for f in group if f["code"] in ALWAYS_HELD or (f["code"] in NEVER_LEFT_OUT and f["level"] == "FAIL")]
    if risky:
        f = risky[0]
        reasons.append("it holds %s %s at %s, and a risk that runs code is never left out on a suggestion"
                       % ("an" if f["code"][0] in "aeiou" else "a", f["code"] + " " + f["level"], f["node"]))
    segment, prefix = _folder(glob)
    if graph is not None:
        importers = _importers(graph, glob, prefix)
        if importers:
            reasons.append(_listing(importers, "imports it", "import it"))
    if texts is not None and segment:
        naming = _naming_files(texts, glob, segment)
        if naming:
            reasons.append(_listing(naming, "names %s/ in a string" % segment, "name %s/ in a string" % segment))
    return "; ".join(reasons)


def offer(findings, inventory, graph=None, texts=None):
    """(offered, held) for the backup copies in a scan. inventory is what walk.walk returned; graph is an
    orphans.Graph of the parsed Python files; texts maps rel -> the text of every file read."""
    files, grouped = {}, {}
    seen = set(inventory["python"]) | set(inventory["manifests"]) | set(inventory["other"])
    seen |= {rel for rel, _ in inventory["skipped"]}
    for rel in seen:
        glob = looks_like_backup(rel)
        if glob:
            files[glob] = files.get(glob, 0) + 1
    for f in findings:
        glob = looks_like_backup(_rel(f["node"]))
        if glob:
            grouped.setdefault(glob, []).append(f)
    offered, held = [], []
    for glob in sorted(grouped, key=lambda g: (-len(grouped[g]), g)):
        group = grouped[glob]
        why = _why(glob, group, graph, texts)
        if why:
            held.append({"glob": glob, "why": why})
            continue
        by_code = {}
        for f in group:
            key = "%s %s" % (f["code"], f["level"])
            by_code[key] = by_code.get(key, 0) + 1
        offered.append({"glob": glob, "files": files.get(glob, 0), "findings": len(group),
                        "by_code": dict(sorted(by_code.items(), key=lambda kv: (-kv[1], kv[0]))),
                        "fail": sum(1 for f in group if f["level"] == "FAIL")})
    return offered, held


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if "--selftest" in argv:
        return selftest()
    sys.stderr.write("usage: python -m code_guardian.backups --selftest\n")
    return 2


def selftest():
    def inv(*rels, other=()):
        return {"python": sorted(rels), "manifests": [], "other": sorted(other), "skipped": [], "excluded": 0,
                "ignored": 0}

    def f(code, level, node):
        return {"code": code, "level": level, "node": node}

    def run(files, found, other=()):
        trees = {rel: ast.parse(src) for rel, src in files.items() if rel.endswith(".py")}
        return offer(found, inv(*[r for r in files if r.endswith(".py")], other=other), Graph(trees), files)

    plain = {"app/main.py": "import os\n", "_archive/a.py": "X = 1\n", "_archive/b.py": "Y = 2\n"}
    key = [f("secret.key", "FAIL", "_archive/a.py:1"), f("secret.key", "FAIL", "_archive/b.py:2")]
    keys_only = run(plain, key)
    imported = run({"app/main.py": "from old import helper\n", "old/__init__.py": "", "old/helper.py": "X = 1\n"},
                   [f("secret.key", "FAIL", "old/helper.py:1")])
    dotted = run({"app/main.py": "import old.helper\n", "old/helper.py": "X = 1\n"},
                 [f("secret.key", "FAIL", "old/helper.py:1")])
    shell = run(plain, key + [f("exec.shell", "FAIL", "_archive/b.py:3")])
    warn = run(plain, key + [f("exec.shell", "WARN", "_archive/b.py:3")])
    hook = run(plain, key + [f("install.hook", "INFO", "_archive/b.py:3")])
    named = run(dict(plain, **{"app/main.py": 'DATA = "_archive/seed.json"\n'}), key)
    exact = run(dict(plain, **{"app/main.py": 'WHERE = "_archive"\n'}), key)
    word = run({"app/main.py": 'MSG = "the old value"\n', "old/a.py": "X = 1\n"}, [f("secret.key", "FAIL", "old/a.py:1")])
    config = run(dict(plain, **{"deploy.yml": "seed: _archive/seed.json\n"}), key, other=("deploy.yml",))
    nested = run({"pkg/__init__.py": "", "pkg/mod.py": "import os\n", "pkg/_archive/x.py": "X = 1\n"},
                 [f("secret.key", "FAIL", "pkg/_archive/x.py:1")])
    sibling = run({"pkg/__init__.py": "", "pkg/mod.py": "from pkg import other\n", "pkg/other.py": "",
                   "pkg/_archive/x.py": "X = 1\n"}, [f("secret.key", "FAIL", "pkg/_archive/x.py:1")])
    ordered = run({"app/main.py": "", "_archive/a.py": "", "_backup/b.py": ""},
                  [f("secret.key", "FAIL", "_archive/a.py:1"), f("secret.key", "FAIL", "_backup/b.py:1"),
                   f("secret.key", "WARN", "_backup/b.py:2")])
    checks = [
        ("folder", looks_like_backup("_archive/x/y.py") == "_archive/*"),
        ("file_mark", looks_like_backup("a/b.py.backup-20260824") == "*.backup-*"),
        ("name_containing_old", looks_like_backup("tools/old_timer.py") is None),
        ("archive_file_not_folder", looks_like_backup("src/archive.py") is None),
        ("case_kept", looks_like_backup("_ARCHIVE/z.py") == "_ARCHIVE/*"),
        ("any_depth", looks_like_backup("pkg/_backups/m.py") == "pkg/_backups/*"),
        ("dated_folder", looks_like_backup("Backup-2026-08-24/a.py") == "Backup-2026-08-24/*"
         and looks_like_backup("old_timer/a.py") is None),
        ("file_ends", looks_like_backup("conf/settings.py.BAK") == "*.BAK" and looks_like_backup("a.py~") == "*~"
         and looks_like_backup(".bak") is None and looks_like_backup("app/main.py") is None),
        ("outermost_first", looks_like_backup("old/_archive/a.py.bak") == "old/*"),
        ("empty_inventory", offer([], inv()) == ([], [])),
        ("keys_only_offered", keys_only == ([{"glob": "_archive/*", "files": 2, "findings": 2,
                                              "by_code": {"secret.key FAIL": 2}, "fail": 2}], [])),
        ("imported_held", imported[0] == [] and imported[1][0]["glob"] == "old/*"
         and imported[1][0]["why"] == "app/main.py imports it"),
        ("import_dotted_held", dotted[0] == [] and "app/main.py imports it" in dotted[1][0]["why"]),
        ("exec_shell_fail_held", shell[0] == [] and "exec.shell FAIL" in shell[1][0]["why"]),
        ("exec_shell_warn_offered", warn[1] == [] and warn[0][0]["by_code"] == {"secret.key FAIL": 2,
                                                                                "exec.shell WARN": 1}),
        ("install_hook_any_level_held", hook[0] == [] and "install.hook INFO" in hook[1][0]["why"]),
        ("string_with_separator_held", named[0] == [] and named[1][0]["why"] == "app/main.py names _archive/ in a string"),
        ("string_exactly_held", exact[0] == [] and exact[1][0]["glob"] == "_archive/*"),
        ("bare_word_offered", word[1] == [] and [g["glob"] for g in word[0]] == ["old/*"]),
        ("config_path_held", config[0] == [] and "deploy.yml" in config[1][0]["why"]),
        ("package_import_not_into_copy", [g["glob"] for g in nested[0]] == ["pkg/_archive/*"]
         and [g["glob"] for g in sibling[0]] == ["pkg/_archive/*"]),
        ("sorted_by_findings", [(g["glob"], g["findings"], g["fail"]) for g in ordered[0]]
         == [("_backup/*", 2, 1), ("_archive/*", 1, 1)]),
        ("no_findings_no_group", run(plain, [f("exec.shell", "WARN", "app/main.py:1")]) == ([], [])),
        ("wanted", wanted(key) and not wanted([f("exec.shell", "WARN", "app/main.py:1")])),
    ]
    return summarize("backups", checks)


if __name__ == "__main__":
    sys.exit(main())
