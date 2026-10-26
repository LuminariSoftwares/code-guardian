"""Works checks for JavaScript and TypeScript: will it load and run as written? Read from the token lists jsts.py cuts and
from package.json / tsconfig.json; nothing is imported, installed or run (no npm, no node).

    works.syntax             FAIL  a template literal or block comment never closes: the file does not tokenise
                             INFO  ( [ { do not balance at the end of the file
    works.import_unresolved  WARN  a bare import is not a Node builtin or a package the nearest package.json declares
                             INFO  the same, when aliases (tsconfig paths / baseUrl) or monorepo packages may explain it,
                                   once per file; and an import loaded from a URL or a registry scheme, once per import
    works.relative_missing   FAIL  a relative import points at a file or folder that is not there
                             INFO  the same when it points into built output (dist, build, out, lib, .next) and the
                                   nearest package.json has scripts.build
    works.entry_missing      FAIL  package.json main, module, browser, bin or an exports target does not exist
                             INFO  built output with scripts.build; types / typings targets
    works.tests_missing      WARN  JS files, no Python files, no test file and no scripts.test (works.py reports the
                                   Python-only and mixed cases)

NOT_CHECKED lists the Python-side Works codes this module does not port. A relative path that leaves the scanned folder
is not judged (nothing is known about it); a path that is on disk but not in `files` (a binary, a gitignored file, built
output) counts as present.

Public contract:
    NOT_CHECKED, BUILTINS
    load(root, files, javascript=None) -> {"javascript": [rel], "js_tokens": {rel: tokens}, "package_json": {rel: dict},
                                           "tsconfig": {rel: dict}, "notes": [str]}
    check(project) -> [finding]    # project: report.scan's dict plus the five load() keys; reads root, python, files
"""

import json
import os
import posixpath
import re
import sys
import tempfile
from fnmatch import fnmatchcase

from . import jsts
from .finding import crash_finding, make_finding, summarize
from .walk import read

NOT_CHECKED = ("works.test_no_assert", "works.todo_stub", "works.commented_code", "works.dead_flag", "orphan.*")

FLAVOURS = {".js": "js", ".mjs": "js", ".cjs": "js", ".jsx": "jsx", ".ts": "ts", ".tsx": "tsx"}
RESOLVE_EXTS = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".json", ".node")
TS_SWAPS = {".js": (".ts", ".tsx", ".d.ts"), ".mjs": (".mts", ".d.mts"), ".cjs": (".cts", ".d.cts"), ".jsx": (".tsx",)}
BUILD_DIRS = frozenset({"dist", "build", "out", "lib", ".next"})
URL_SCHEMES = frozenset({"http", "https", "data", "blob", "npm", "jsr"})
DEP_FIELDS = ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies")
TEST_DIRS = frozenset({"__tests__", "test", "tests", "cypress", "e2e"})
TYPES_KEYS = frozenset({"types", "typings"})
NO_TEST_SCRIPT = "no test specified"
FAILS_TO_LOAD = "file does not tokenise: it cannot be loaded"
CLOSERS = {")": "(", "]": "[", "}": "{"}

# The documented Node module names that import without a "node:" prefix (test, sea and sqlite are node:-only).
BUILTINS = frozenset(
    "assert async_hooks buffer child_process cluster console constants crypto dgram diagnostics_channel dns domain events "
    "fs http http2 https inspector module net os path perf_hooks process punycode querystring readline repl stream "
    "string_decoder sys timers tls trace_events tty url util v8 vm wasi worker_threads zlib".split())

_SCHEME = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*):")
_PACKAGE = re.compile(r"((?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*)(?=/|$)", re.I)
_JSON_TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"|[{}\[\],:]|[^\s{}\[\],:"]+', re.S)


def _finding(code, level, node, summary, evidence=(), try_=()):
    return make_finding(code, "partial", level, node, summary, evidence=list(evidence), try_=list(try_))


# ---- reading the manifests ---------------------------------------------------------------------------------------------

def _loose(text):
    """JSON text with // and /* */ comments and trailing commas blanked. Newlines stay where they were, so a line in the
    result is the same line in the file."""
    text = text.lstrip("﻿")
    out = []
    commas = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            j = i + 1
            while j < n and text[j] != '"' and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            out.append(text[i:j + 1])
            i = j + 1
            continue
        nx = text[i + 1:i + 2]
        if c == "/" and nx == "/":
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
            continue
        if c == "/" and nx == "*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append("".join("\n" if ch == "\n" else " " for ch in text[i:j]))
            i = j
            continue
        if c == ",":
            commas.append(len(out))
        out.append(c)
        i += 1
    for k in commas:
        j = k + 1
        while j < len(out) and not out[j].strip():
            j += 1
        if j < len(out) and out[j][:1] in ("}", "]"):
            out[k] = " "
    return "".join(out)


def _parse(text):
    """(dict, None) for a JSON object after _loose, else (None, why)."""
    try:
        value = json.loads(_loose(text))
    except (ValueError, RecursionError) as exc:
        return None, str(exc)
    return (value, None) if isinstance(value, dict) else (None, "not a JSON object")


def _key_lines(text):
    """{path tuple: line} for every object key and array element in JSON text (after _loose)."""
    toks = []
    pos = 0
    line = 1
    for m in _JSON_TOKEN.finditer(text):
        line += text.count("\n", pos, m.start())
        pos = m.start()
        toks.append((m.group(), line))
    lines = {}
    n = len(toks)

    def value(i, path):
        if i >= n:
            return i
        t = toks[i][0]
        if t == "{":
            i += 1
            while i < n and toks[i][0] != "}":
                key, ln = toks[i]
                if i + 1 < n and toks[i + 1][0] == ":" and key.startswith('"'):
                    name = json.loads(key)
                    lines[path + (name,)] = ln
                    i = value(i + 2, path + (name,))
                else:
                    i += 1
                if i < n and toks[i][0] == ",":
                    i += 1
            return i + 1
        if t == "[":
            i += 1
            k = 0
            while i < n and toks[i][0] != "]":
                lines[path + (k,)] = toks[i][1]
                i = value(i, path + (k,))
                k += 1
                if i < n and toks[i][0] == ",":
                    i += 1
            return i + 1
        return i + 1

    try:
        value(0, ())
    except (RecursionError, ValueError):
        pass
    return lines


def _flavour(rel):
    return FLAVOURS.get(posixpath.splitext(rel)[1].lower())


def load(root, files, javascript=None):
    """Tokenise the JS / TS files and parse the package.json, tsconfig.json and jsconfig.json files among `files`. A file
    that cannot be read, tokenised or parsed is left out and named in notes."""
    files = list(files)
    if javascript is None:
        javascript = [rel for rel in files if _flavour(rel)]
    out = {"javascript": [], "js_tokens": {}, "package_json": {}, "tsconfig": {}, "notes": []}
    notes = out["notes"]
    for rel in sorted(set(javascript)):
        flavour = _flavour(rel)
        if flavour is None:
            continue
        try:
            tokens = jsts.tokenize(read(root, rel)[1], flavour)
        except Exception as exc:  # noqa: BLE001 - one unreadable file must not stop the rest
            notes.append("%s: not read (%s: %s)" % (rel, type(exc).__name__, exc))
            continue
        out["javascript"].append(rel)
        out["js_tokens"][rel] = tokens
    for rel in sorted(files):
        name = posixpath.basename(rel)
        if name == "package.json":
            key = "package_json"
        elif name in ("tsconfig.json", "jsconfig.json"):
            key = "tsconfig"
        else:
            continue
        try:
            data, why = _parse(read(root, rel)[1])
        except OSError as exc:
            data, why = None, str(exc)
        if data is None:
            notes.append("%s: left out, it does not parse as JSON after stripping comments and trailing commas (%s)"
                         % (rel, why))
        else:
            out[key][rel] = data
    return out


# ---- the project as the checks see it ----------------------------------------------------------------------------------

def _join(folder, name):
    return folder + "/" + name if folder else name


def _norm(folder, spec):
    """Root-relative path of `spec` taken from `folder` ("" is the root); None when it leaves the scanned folder."""
    path = posixpath.normpath(posixpath.join(folder, spec))
    if path == ".":
        return ""
    return None if path == ".." or path.startswith("../") or path.startswith("/") else path


def _glob(pattern, path):
    pattern = pattern.strip().lstrip("./").rstrip("/")
    rx = "".join(".*" if tok == "**" else "[^/]*" if tok == "*" else re.escape(tok)
                 for tok in re.split(r"(\*\*|\*)", pattern))
    return re.fullmatch(rx, path) is not None


def _scripts(manifest):
    scripts = manifest.get("scripts")
    return scripts if isinstance(scripts, dict) else {}


class _Tree:
    """What exists, which package.json a file belongs to, and what the tsconfig and workspaces say about it."""

    def __init__(self, project):
        self.root = project.get("root") or ""
        self.files = set(project.get("files") or ())
        self.dirs = {""}
        for rel in self.files:
            parts = rel.split("/")
            self.dirs.update("/".join(parts[:i]) for i in range(1, len(parts)))
        self.packages = project.get("package_json") or {}
        self.tsconfigs = project.get("tsconfig") or {}
        self._disk = {}
        self._lines = {}
        self.workspace_names = self._workspace_names()

    def _workspace_names(self):
        spaces = (self.packages.get("package.json") or {}).get("workspaces")
        if isinstance(spaces, dict):
            spaces = spaces.get("packages")
        globs = [g for g in spaces if isinstance(g, str)] if isinstance(spaces, list) else []
        names = set()
        for rel, manifest in self.packages.items():
            folder = posixpath.dirname(rel)
            listed = any(_glob(g, folder) for g in globs if not g.startswith("!"))
            if (rel != "package.json" and isinstance(manifest.get("name"), str) and listed
                    and not any(_glob(g[1:], folder) for g in globs if g.startswith("!"))):
                names.add(manifest["name"])
        return names

    def monorepo(self):
        return isinstance((self.packages.get("package.json") or {}).get("workspaces"), (list, dict))

    def _on_disk(self, path, probe):
        if not self.root:
            return False
        key = (probe is os.path.isdir, path)
        if key not in self._disk:
            self._disk[key] = probe(os.path.join(self.root, *path.split("/")))
        return self._disk[key]

    def is_file(self, path):
        return path in self.files or self._on_disk(path, os.path.isfile)

    def is_dir(self, path):
        return path in self.dirs or self._on_disk(path, os.path.isdir)

    def resolves(self, path):
        """True when `path` names what Node or a bundler would load: the file, with an extension added, a TS source
        for a .js spelling, or a folder with an index file or a package.json."""
        if path and (self.is_file(path) or any(self.is_file(path + ext) for ext in RESOLVE_EXTS)):
            return True
        ext = posixpath.splitext(path)[1]
        if ext in TS_SWAPS and any(self.is_file(path[:-len(ext)] + alt) for alt in TS_SWAPS[ext]):
            return True
        return self.is_dir(path) and (self.is_file(_join(path, "package.json"))
                                      or any(self.is_file(_join(path, "index" + e)) for e in RESOLVE_EXTS))

    def nearest(self, rel):
        """(package.json path, its dict) for the closest package.json at or above the file; (None, {}) without one."""
        folder = posixpath.dirname(rel)
        while True:
            cand = _join(folder, "package.json")
            if cand in self.packages:
                return cand, self.packages[cand]
            if not folder:
                return None, {}
            folder = posixpath.dirname(folder)

    def aliased(self, rel):
        """True when a tsconfig / jsconfig at or above the file sets paths or baseUrl."""
        folder = posixpath.dirname(rel)
        while True:
            for name in ("tsconfig.json", "jsconfig.json"):
                options = (self.tsconfigs.get(_join(folder, name)) or {}).get("compilerOptions")
                if isinstance(options, dict) and ("paths" in options or "baseUrl" in options):
                    return True
            if not folder:
                return False
            folder = posixpath.dirname(folder)

    def key_lines(self, rel):
        if rel not in self._lines:
            try:
                with open(os.path.join(self.root, *rel.split("/")), "rb") as fh:
                    text = fh.read().decode("utf-8", errors="replace")
            except OSError:
                text = ""
            self._lines[rel] = _key_lines(_loose(text))
        return self._lines[rel]

    def built_output(self, path, manifest_rel, manifest):
        """True when `path` is under a build folder of the package that owns it and that package has scripts.build."""
        if manifest_rel is None or not _scripts(manifest).get("build"):
            return False
        folder = posixpath.dirname(manifest_rel)
        if folder:
            if not path.startswith(folder + "/"):
                return False
            path = path[len(folder) + 1:]
        return path.split("/")[0] in BUILD_DIRS


# ---- the checks --------------------------------------------------------------------------------------------------------

def _syntax(rel, tokens):
    for t in tokens:
        if t.kind == "error" and t.value in ("template", "comment"):
            what = "template literal" if t.value == "template" else "block comment"
            return [_finding("works.syntax", "FAIL", "%s:%d" % (rel, t.line), FAILS_TO_LOAD,
                             ["an unterminated %s runs to the end of the file" % what],
                             ["close the %s" % what])]
    opened = {"(": [], "[": [], "{": []}
    stray = []
    for t in tokens:
        if t.kind != "punct":
            continue
        if t.value in opened:
            opened[t.value].append(t.line)
        elif t.value in CLOSERS:
            if opened[CLOSERS[t.value]]:
                opened[CLOSERS[t.value]].pop()
            else:
                stray.append(t.line)
    lines = [ln for stack in opened.values() for ln in stack] + stray
    if not lines:
        return []
    evidence = ["unclosed %s: %d" % (b, len(stack)) for b, stack in opened.items() if stack]
    if stray:
        evidence.append("closing brackets with no opener: %d" % len(stray))
    return [_finding("works.syntax", "INFO", "%s:%d" % (rel, min(lines)),
                     "brackets do not balance (may be JSX text or an unsupported construct)", evidence,
                     ["check the brackets near this line"])]


def _declared(name, manifest):
    deps = set()
    for field in DEP_FIELDS:
        if isinstance(manifest.get(field), dict):
            deps.update(manifest[field])
    types = "@types/" + (name[1:].replace("/", "__") if name.startswith("@") else name)
    return name in deps or types in deps or name == manifest.get("name")


def _imports(tree, rel, tokens):
    out = []
    manifest_rel, manifest = tree.nearest(rel)
    folder = posixpath.dirname(rel)
    unresolved = []
    for imp in jsts.imports(tokens):
        spec = imp.spec
        if not spec:
            continue
        node = "%s:%d" % (rel, imp.line)
        scheme = _SCHEME.match(spec)
        if spec == "." or spec == ".." or spec.startswith(("./", "../")):
            path = _norm(folder, re.split(r"[?#]", spec)[0])
            if path is None or tree.resolves(path):
                continue
            if tree.built_output(path, manifest_rel, manifest):
                out.append(_finding("works.relative_missing", "INFO", node,
                                    "relative import %s points at built output: run the build first" % spec,
                                    ["scripts.build in %s" % manifest_rel], ["run the build, then scan again"]))
            else:
                out.append(_finding("works.relative_missing", "FAIL", node,
                                    "relative import %s points at nothing in the repo" % spec,
                                    ["looked for: the path, the path with an extension, an index file, a package.json"],
                                    ["fix the path or add the missing file"]))
        elif scheme:
            if scheme.group(1).lower() in URL_SCHEMES:
                out.append(_finding("works.import_unresolved", "INFO", node,
                                    "import loaded from a URL at run time, not from package.json",
                                    ["scheme: %s" % scheme.group(1).lower()], []))
        elif spec[0] not in "#/~!":
            m = _PACKAGE.match(spec)
            name = m.group(1) if m else None
            if (name and name not in BUILTINS and not name.startswith("@types/") and not _declared(name, manifest)
                    and name not in tree.workspace_names):
                unresolved.append((imp.line, name))
    return out + _unresolved_findings(tree, rel, manifest_rel, unresolved)


def _unresolved_findings(tree, rel, manifest_rel, unresolved):
    """The findings for the bare imports no package.json declares: WARN each, or one INFO per file when aliases or
    monorepo packages may explain them."""
    if not unresolved:
        return []
    where = manifest_rel or "no package.json"
    why = "aliased imports are not checked" if tree.aliased(rel) else (
        "monorepo packages are not resolved" if tree.monorepo() else None)
    if why:
        line, name = unresolved[0]
        return [_finding("works.import_unresolved", "INFO", "%s:%d" % (rel, line),
                          "import %s: not in %s (%s)" % (name, where, why),
                          ["unresolved bare imports in this file: %d" % len(unresolved)], [])]
    return [_finding("works.import_unresolved", "WARN", "%s:%d" % (rel, line),
                      "import %s: not a Node builtin or a dependency in %s" % (name, where),
                      ["package: %s" % name],
                      ["add %s to dependencies in package.json" % name,
                       "or remove the import if nothing uses it"]) for line, name in unresolved]


def _entry_leaves(manifest):
    """[(path tuple, target string)] for every entry point the manifest names."""
    leaves = []
    for key in ("main", "module", "browser", "types", "typings", "bin", "exports"):
        stack = [((key,), manifest.get(key))]
        while stack:
            path, value = stack.pop()
            if isinstance(value, str):
                if value.strip() and "*" not in value and not _SCHEME.match(value) and not value.startswith("/"):
                    leaves.append((path, value.strip()))
            elif isinstance(value, dict) and key in ("bin", "exports"):
                stack.extend((path + (k,), v) for k, v in value.items())
            elif isinstance(value, list) and key == "exports":
                stack.extend((path + (k,), v) for k, v in enumerate(value))
    return sorted(leaves, key=lambda leaf: [str(p) for p in leaf[0]])


def _entries(tree, manifest_rel, manifest):
    out = []
    lines = tree.key_lines(manifest_rel)
    folder = posixpath.dirname(manifest_rel)
    for path, target in _entry_leaves(manifest):
        resolved = _norm(folder, target)
        if resolved is None or tree.resolves(resolved):
            continue
        key = path
        while key and key not in lines:
            key = key[:-1]
        node = "%s:%d" % (manifest_rel, lines.get(key, 1))
        label = " > ".join(str(p) for p in path)
        if TYPES_KEYS & {str(p) for p in path}:
            level, summary = "INFO", "%s: %s does not exist (type declarations only)" % (label, target)
        elif tree.built_output(resolved, manifest_rel, manifest):
            level, summary = "INFO", "%s: %s is built output: run the build first" % (label, target)
        else:
            level, summary = "FAIL", "%s: %s does not exist" % (label, target)
        out.append(_finding("works.entry_missing", level, node, summary,
                            ["the package cannot be loaded from this entry point"] if level == "FAIL" else [],
                            ["point %s at an existing file" % path[0]] if level == "FAIL" else []))
    return out


def _is_test(rel):
    parts = rel.split("/")
    return (any(p in TEST_DIRS for p in parts[:-1]) or fnmatchcase(parts[-1], "*.test.*")
            or fnmatchcase(parts[-1], "*.spec.*"))


def _tests_missing(project, tree):
    if not project.get("javascript") or project.get("python"):
        return []
    if any(_is_test(rel) for rel in tree.files):
        return []
    for manifest in tree.packages.values():
        script = _scripts(manifest).get("test")
        if isinstance(script, str) and script.strip() and NO_TEST_SCRIPT not in script:
            return []
    return [_finding("works.tests_missing", "WARN", ".", "no test files: nothing checks that the code works",
                     ["looked for: *.test.*, *.spec.*, __tests__/, test/, tests/, cypress/, e2e/ and scripts.test"],
                     ["add a test folder, or a test script in package.json that runs one"])]


def _guarded(code, node, fn, *args):
    try:
        return fn(*args)
    except Exception as exc:  # noqa: BLE001 - a broken check must not take down the run
        return [crash_finding(code, exc, node)]


def check(project):
    """All JavaScript / TypeScript Works checks over one scanned project (see report.scan plus load())."""
    tree = _Tree(project)
    tokens = project.get("js_tokens") or {}
    out = []
    for rel in sorted(project.get("javascript") or ()):
        if rel in tokens:
            out += _guarded("works_js.syntax", rel, _syntax, rel, tokens[rel])
            out += _guarded("works_js.imports", rel, _imports, tree, rel, tokens[rel])
    for manifest_rel in sorted(tree.packages):
        out += _guarded("works_js.entries", manifest_rel, _entries, tree, manifest_rel, tree.packages[manifest_rel])
    out += _guarded("works_js.tests", ".", _tests_missing, project, tree)
    seen = set()
    unique = []
    for f in out:
        key = (f["code"], f["level"], f["node"], f["summary"])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if "--selftest" in argv:
        return selftest()
    sys.stderr.write("usage: python -m code_guardian.works_js --selftest\n")
    return 2


def _bad_manifest_notes():
    with tempfile.TemporaryDirectory() as root:
        with open(os.path.join(root, "tsconfig.json"), "w", encoding="utf-8") as fh:
            fh.write("{ nope")
        loaded = load(root, ["tsconfig.json"])
    return loaded["tsconfig"] == {} and len(loaded["notes"]) == 1 and "tsconfig.json" in loaded["notes"][0]


def selftest():
    def run(files, **extra):
        with tempfile.TemporaryDirectory() as root:
            for rel, text in files.items():
                path = os.path.join(root, *rel.split("/"))
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w", encoding="utf-8", newline="") as fh:
                    fh.write(text)
            names = sorted(files)
            project = {"root": root, "python": [r for r in names if r.endswith(".py")], "files": names}
            project.update(load(root, names))
            project.update(extra)
            return sorted((f["code"], f["level"], f["node"]) for f in check(project))

    pkg = '{"name": "p", "scripts": {"test": "node --test"}}'
    pkg_build = '{"name": "p", "scripts": {"test": "node --test", "build": "tsc"}}'
    paths = '{"compilerOptions": {"paths": {"@/*": ["src/*"]}},}'
    checks = [
        ("loose_json", _parse('{\n // c\n "a": "x // not a comment", /* b */ "b": [1, 2,],\n}\n')[0] ==
         {"a": "x // not a comment", "b": [1, 2]}),
        ("loose_json_rejects", _parse("{ nope")[0] is None and _parse("[1]")[0] is None),
        ("key_lines", _key_lines(_loose('{\n"a": 1,\n"bin": {\n"x": "y"\n}\n}\n')).get(("bin", "x")) == 4),
        ("unterminated_template", run({"package.json": pkg, "a.js": "const s = `x ${y};\n"}) ==
         [("works.syntax", "FAIL", "a.js:1")]),
        ("unterminated_comment_in_jsx", run({"package.json": pkg, "a.jsx": "const a = <p/>;\n/* x\n"}) ==
         [("works.syntax", "FAIL", "a.jsx:2")]),
        ("brackets", run({"package.json": pkg, "a.js": "f(1;\n"}) == [("works.syntax", "INFO", "a.js:1")]),
        ("brackets_balanced_in_strings", run({"package.json": pkg, "a.js": "const s = '(' + `[${1}` + /\\{/;\n"}) == []),
        ("builtins_and_scopes", run({"package.json": '{"scripts": {"test": "t"}, "dependencies": {"@a/b": "1"}}',
                                     "a.js": "import fs from 'fs/promises';\nimport b from '@a/b/c';\n"
                                             "import n from 'node:test';\nimport T from '@types/node';\n"}) == []),
        ("bare_unresolved", run({"package.json": pkg, "a.js": "import x from 'nope';\nrequire('nope/deep');\n"}) ==
         [("works.import_unresolved", "WARN", "a.js:1"), ("works.import_unresolved", "WARN", "a.js:2")]),
        ("types_package_declares", run({"package.json": '{"scripts": {"test": "t"}, "devDependencies": {"@types/x": "1"}}',
                                        "a.ts": "import x from 'x';\n"}) == []),
        ("scheme_is_info", run({"package.json": pkg, "a.js": "import u from 'https://example.org/x.js';\n"}) ==
         [("works.import_unresolved", "INFO", "a.js:1")]),
        ("alias_info_once", run({"package.json": pkg, "tsconfig.json": paths, "a.ts": "import a from 'x';\nimport b from 'y';\n"})
         == [("works.import_unresolved", "INFO", "a.ts:1")]),
        ("relative_resolution", run({"package.json": pkg, "src/a.ts": "import './b.js';\nimport './c';\nimport './d';\n",
                                     "src/b.ts": "", "src/c/index.js": "", "src/d/package.json": "{}"}) == []),
        ("relative_missing_and_build", run({"package.json": pkg, "a.js": "require('./dist/x');\n"}) ==
         [("works.relative_missing", "FAIL", "a.js:1")] and
         run({"package.json": pkg_build, "a.js": "require('./dist/x');\nrequire('./src/y');\n"}) ==
         [("works.relative_missing", "FAIL", "a.js:2"), ("works.relative_missing", "INFO", "a.js:1")]),
        ("entry_points", run({"package.json": '{\n"main": "gone.js",\n"bin": {"t": "bin/t.js"},\n"types": "x.d.ts",\n'
                                              '"exports": {".": {"import": "./e.mjs"}},\n"scripts": {"test": "t"}\n}\n'}) ==
         [("works.entry_missing", "FAIL", "package.json:2"), ("works.entry_missing", "FAIL", "package.json:3"),
          ("works.entry_missing", "FAIL", "package.json:5"), ("works.entry_missing", "INFO", "package.json:4")]),
        ("tests_signal", run({"package.json": '{"name": "p"}', "a.js": "1;\n"}) == [("works.tests_missing", "WARN", ".")] and
         run({"package.json": '{"name": "p"}', "a.js": "1;\n", "a.spec.js": "1;\n"}) == [] and
         run({"package.json": '{"name": "p"}', "a.js": "1;\n", "a.py": "x = 1\n"}) == []),
        ("not_checked", "orphan.*" in NOT_CHECKED and "works.todo_stub" in NOT_CHECKED),
        ("bad_tsconfig_is_a_note", _bad_manifest_notes()),
    ]
    return summarize("works_js", checks)


if __name__ == "__main__":
    sys.exit(main())
