"""Orphan code: functions, classes and modules nothing reachable from the stated entry points ever uses.

A static call graph built with ast from imports, `from x import y`, attribute use on imported modules and method
calls. It never claims more than the parse proves:
  - a method counts as used when its class is used and its name is read as an attribute anywhere reachable;
  - anything named by getattr/globals()/importlib with a computed name, named in a string, or wrapped in a
    registering decorator is `orphan.uncertain`, never `orphan.dead`;
  - something only tests reach is `orphan.test_only`.
Orphans are hygiene, not threat: they never touch the threat score.

Public contract:
    module_name(rel) -> "pkg.mod"          is_test(rel) -> bool
    Graph(trees)                           # trees: {rel: ast.Module}
    infer_entry_points(graph, manifest_entries=()) -> ["mod:func" | "mod:__main__" | "mod"]
    analyse(trees, goal=None, manifest_entries=()) -> {"source", "goal", "entry_points", "keep", "findings",
                                                       "counts", "notes"}
"""

import ast
import collections
import fnmatch
import re
import sys

from .finding import make_finding, summarize
from .score import sort_findings

LEVELS = {"orphan.dead": "WARN", "orphan.test_only": "INFO", "orphan.uncertain": "INFO"}
TEST_DIRS = frozenset({"tests", "test", "testing"})
TOOL_RUN = frozenset({"setup.py", "noxfile.py", "fabfile.py", "manage.py", "docs/conf.py", "doc/conf.py"})
PURE_DECORATORS = frozenset({"staticmethod", "classmethod", "property", "functools.wraps", "functools.lru_cache",
                             "functools.cache", "functools.cached_property", "functools.total_ordering",
                             "functools.singledispatch", "abc.abstractmethod", "abstractmethod", "dataclass",
                             "dataclasses.dataclass", "typing.overload", "overload", "typing.override", "override",
                             "contextlib.contextmanager", "contextmanager", "contextlib.asynccontextmanager"})
# A string names a definition only when it is an identifier or a dotted/colon path ending in one ("pkg.mod:run").
_NAMED = re.compile(r"(?:[A-Za-z_][A-Za-z0-9_]*[.:])*([A-Za-z_][A-Za-z0-9_]*)")


def module_name(rel):
    parts = rel[:-3].split("/") if rel.endswith(".py") else rel.split("/")
    if parts[-1] == "__init__":
        parts = parts[:-1]
    if len(parts) > 1 and parts[0] == "src":
        parts = parts[1:]
    return ".".join(parts) or "__init__"


def is_test(rel):
    parts = rel.split("/")
    name = parts[-1]
    return (any(p in TEST_DIRS for p in parts[:-1]) or name.startswith("test_") or name.endswith("_test.py")
            or name in ("conftest.py", "tests.py"))


def _is_main_guard(stmt):
    t = stmt.test if isinstance(stmt, ast.If) else None
    return (isinstance(t, ast.Compare) and isinstance(t.left, ast.Name) and t.left.id == "__name__"
            and len(t.comparators) == 1 and isinstance(t.comparators[0], ast.Constant)
            and t.comparators[0].value == "__main__")


class Node:
    __slots__ = ("q", "kind", "rel", "line", "module", "cls", "test", "refs", "attrs", "strings", "dyn",
                 "decorators", "bases")

    def __init__(self, q, kind, rel, line, module, cls=None, test=False):
        self.q, self.kind, self.rel, self.line, self.module, self.cls, self.test = q, kind, rel, line, module, cls, test
        self.refs, self.attrs, self.strings, self.dyn, self.decorators, self.bases = set(), set(), set(), [], [], []


class Graph:
    """Definitions (modules, classes, functions, methods, __main__ blocks) and what each one refers to."""

    def __init__(self, trees):
        self.nodes = {}
        self.modules = {}       # module name -> rel
        self.aliases = {}       # module name -> {local name: qualified}
        self.stars = {}         # module name -> [module names star-imported]
        self.defs = {}          # module name -> {top-level def name}
        self.methods = collections.defaultdict(list)
        self.all_names = {}     # package -> __all__ entries
        self.dupes = []
        named = {}
        for rel in sorted(trees):
            mod = module_name(rel)
            if mod in named:
                self.dupes.append(rel)
                continue
            named[mod] = rel
        for mod, rel in named.items():
            self.modules[mod] = rel
            self._aliases(mod, rel, trees[rel])
        for mod, rel in named.items():
            self._collect(mod, rel, trees[rel])

    # ----------------------------------------------------------- building

    def _package(self, mod, rel):
        return mod if rel.endswith("__init__.py") else mod.rpartition(".")[0]

    def _absolute(self, mod, rel, level, name):
        if not level:
            return name or ""
        base = self._package(mod, rel).split(".") if self._package(mod, rel) else []
        base = base[:len(base) - (level - 1)] if level > 1 else base
        return ".".join(base + ([name] if name else []))

    def _aliases(self, mod, rel, tree):
        aliases, stars, defs = {}, [], set()
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                for a in n.names:
                    aliases[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
            elif isinstance(n, ast.ImportFrom):
                src = self._absolute(mod, rel, n.level, n.module)
                for a in n.names:
                    if a.name == "*":
                        stars.append(src)
                    else:
                        aliases[a.asname or a.name] = (src + "." if src else "") + a.name
        for stmt in self._toplevel(tree.body):
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                defs.add(stmt.name)
            elif isinstance(stmt, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "__all__" for t in stmt.targets):
                if isinstance(stmt.value, (ast.List, ast.Tuple)):
                    self.all_names[mod] = [e.value for e in stmt.value.elts
                                           if isinstance(e, ast.Constant) and isinstance(e.value, str)]
        self.aliases[mod], self.stars[mod], self.defs[mod] = aliases, stars, defs

    def _toplevel(self, body):
        """Module-level statements, looking inside if/try/with blocks (but not the __main__ guard)."""
        for stmt in body:
            if _is_main_guard(stmt):
                yield stmt
                continue
            yield stmt
            if isinstance(stmt, (ast.If, ast.Try, ast.With, ast.For, ast.While)) or type(stmt).__name__ == "TryStar":
                for field in ("body", "orelse", "finalbody"):
                    yield from self._toplevel(getattr(stmt, field, []) or [])
                for h in getattr(stmt, "handlers", []) or []:
                    yield from self._toplevel(h.body)

    def _add(self, node):
        self.nodes[node.q] = node
        return node

    def _collect(self, mod, rel, tree):
        test = is_test(rel)
        mnode = self._add(Node(mod, "module", rel, 1, mod, test=test))
        for stmt in tree.body:
            self._statement(mod, rel, stmt, mnode, test)

    def _statement(self, mod, rel, stmt, mnode, test):
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            node = self._add(Node("%s.%s" % (mod, stmt.name), "function", rel, stmt.lineno, mod, test=test))
            node.decorators = [self._decorator(mod, d) for d in stmt.decorator_list]
            self._scan(mod, rel, [stmt], node)
        elif isinstance(stmt, ast.ClassDef):
            cq = "%s.%s" % (mod, stmt.name)
            cnode = self._add(Node(cq, "class", rel, stmt.lineno, mod, test=test))
            cnode.decorators = [self._decorator(mod, d) for d in stmt.decorator_list]
            cnode.bases = [self._qualify(mod, b) for b in stmt.bases]
            head = list(stmt.bases) + [k.value for k in stmt.keywords] + list(stmt.decorator_list)
            body = [s for s in stmt.body if not isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef))]
            self._scan(mod, rel, head + body, cnode)
            for s in stmt.body:
                if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    m = self._add(Node("%s.%s" % (cq, s.name), "method", rel, s.lineno, mod, cls=cq, test=test))
                    m.decorators = [self._decorator(mod, d) for d in s.decorator_list]
                    self._scan(mod, rel, [s], m)
                    self.methods[cq].append(m.q)
        elif _is_main_guard(stmt):
            main = self._add(Node("%s:__main__" % mod, "main", rel, stmt.lineno, mod, test=test))
            self._scan(mod, rel, stmt.body, main)
            for s in stmt.orelse:
                self._statement(mod, rel, s, mnode, test)
        elif isinstance(stmt, (ast.If, ast.Try, ast.With, ast.For, ast.While)) or type(stmt).__name__ == "TryStar":
            head = [getattr(stmt, f) for f in ("test", "iter", "target") if getattr(stmt, f, None) is not None]
            head += [i for i in getattr(stmt, "items", [])]
            head += [h.type for h in getattr(stmt, "handlers", []) or [] if h.type is not None]
            self._scan(mod, rel, head, mnode)
            for field in ("body", "orelse", "finalbody"):
                for s in getattr(stmt, field, []) or []:
                    self._statement(mod, rel, s, mnode, test)
            for h in getattr(stmt, "handlers", []) or []:
                for s in h.body:
                    self._statement(mod, rel, s, mnode, test)
        else:
            self._scan(mod, rel, [stmt], mnode)

    def _decorator(self, mod, d):
        target = d.func if isinstance(d, ast.Call) else d
        return self._qualify(mod, target) or ast.dump(target)[:40]

    def _qualify(self, mod, expr):
        """Qualified name for a Name/Attribute chain, through this module's imports and definitions."""
        parts = []
        while isinstance(expr, ast.Attribute):
            parts.append(expr.attr)
            expr = expr.value
        if not isinstance(expr, ast.Name):
            return None
        return ".".join([self._name(mod, expr.id)] + parts[::-1])

    def _name(self, mod, name):
        if name in self.defs.get(mod, ()):
            return "%s.%s" % (mod, name)
        if name in self.aliases.get(mod, {}):
            return self.aliases[mod][name]
        for star in self.stars.get(mod, ()):
            if name in self.defs.get(star, ()):
                return "%s.%s" % (star, name)
        return name

    def _fragments(self, expr):
        out = []
        for n in ast.walk(expr):
            if isinstance(n, ast.Constant) and isinstance(n.value, str):
                out.extend(p for p in re.split(r"%[sdr]|\{[^}]*\}", n.value) if p.strip("._"))
        return out

    def _locals(self, stmts):
        """Names a function binds itself (arguments and assignments): they shadow module-level definitions."""
        out, declared = set(), set()
        for stmt in stmts:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                a = stmt.args
                out.update(x.arg for x in a.posonlyargs + a.args + a.kwonlyargs + [a.vararg, a.kwarg] if x)
                for n in ast.walk(stmt):
                    if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                        out.add(n.id)
                    elif isinstance(n, (ast.Global, ast.Nonlocal)):
                        declared.update(n.names)
        return out - declared

    def _scan(self, mod, rel, stmts, node):
        local = self._locals(stmts) if node.kind in ("function", "method") else set()
        bare = set()
        for stmt in stmts:
            for n in ast.walk(stmt):
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)) and n.body:
                    first = n.body[0]
                    if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                        bare.add(id(first.value))
        for stmt in stmts:
            for n in ast.walk(stmt):
                self._visit(mod, rel, n, node, bare, local)

    def _visit(self, mod, rel, n, node, bare, local):
        if isinstance(n, ast.Name) and not isinstance(n.ctx, ast.Store):
            if n.id not in local:
                node.refs.add(self._name(mod, n.id))
        elif isinstance(n, ast.Attribute):
            node.attrs.add(n.attr)
            base = n
            while isinstance(base, ast.Attribute):
                base = base.value
            q = self._qualify(mod, n) if not (isinstance(base, ast.Name) and base.id in local) else None
            if q:
                node.refs.add(q)
        elif isinstance(n, ast.Import):
            for a in n.names:
                node.refs.add(a.name)
        elif isinstance(n, ast.ImportFrom):
            src = self._absolute(mod, rel, n.level, n.module)
            node.refs.add(src)
            for a in n.names:
                if a.name != "*" and (src + "." + a.name if src else a.name) in self.modules:
                    node.refs.add(src + "." + a.name if src else a.name)
        elif isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in bare:
            m = _NAMED.fullmatch(n.value.strip())
            if m:
                node.strings.add(m.group(1))
        elif isinstance(n, ast.Call):
            self._call(mod, rel, n, node)

    def _call(self, mod, rel, c, node):
        fname = self._qualify(mod, c.func) or ""
        first = c.args[0] if c.args else None
        if fname in ("getattr", "hasattr") and len(c.args) >= 2:
            name = c.args[1]
            if isinstance(name, ast.Constant) and isinstance(name.value, str):
                node.attrs.add(name.value)
                target = self._qualify(mod, first)
                if target:
                    node.refs.add(target + "." + name.value)
            else:
                target = self._qualify(mod, first) or ""
                mods = {mod} | ({target} if target in self.modules else set())
                node.dyn.append(("getattr", frozenset(mods), tuple(self._fragments(name))))
        elif fname in ("globals", "vars", "locals"):
            node.dyn.append(("%s()" % fname, frozenset({mod}), ()))
        elif fname in ("importlib.import_module", "__import__", "importlib.__import__") and first is not None:
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                target = first.value
                if target.startswith("."):
                    level = len(target) - len(target.lstrip("."))
                    target = self._absolute(mod, rel, level, target.lstrip(".") or None)
                node.refs.add(target)
            else:
                node.dyn.append(("import", None, tuple(self._fragments(first))))
        elif fname in ("pkgutil.iter_modules", "pkgutil.walk_packages", "runpy.run_module", "runpy.run_path",
                       "importlib.util.spec_from_file_location"):
            node.dyn.append(("import", None, ()))

    # ----------------------------------------------------------- resolving and reaching

    def resolve(self, q, depth=0):
        """Graph nodes a qualified reference lands on: the node itself, or the deepest known prefix (following a
        package's own imports, so pkg.name finds pkg.core.name when pkg/__init__.py imports it)."""
        if q in self.nodes:
            return [q]
        parts = q.split(".")
        for i in range(len(parts) - 1, 0, -1):
            head = ".".join(parts[:i])
            if head in self.modules:
                alias = self.aliases[head].get(parts[i])
                if alias and depth < 6 and alias != q:
                    return self.resolve(".".join([alias] + parts[i + 1:]), depth + 1) + [head]
                return [head]
            if head in self.nodes:
                return [head]
        return []

    def parents(self, node):
        out = [node.module]
        parts = node.module.split(".")
        out.extend(".".join(parts[:i]) for i in range(1, len(parts)))
        if node.cls:
            out.append(node.cls)
        return out

    def external_base(self, cq, seen=None):
        """The class has a base outside the project (a framework may call any of its methods)."""
        seen = seen or set()
        if cq in seen or cq not in self.nodes:
            return False
        seen.add(cq)
        for b in self.nodes[cq].bases:
            if b is None:
                return True
            if b in ("object", "builtins.object"):
                continue
            hits = [r for r in self.resolve(b) if self.nodes[r].kind == "class"]
            if not hits or any(self.external_base(h, seen) for h in hits):
                return True
        return False

    def reach(self, roots):
        """Every node reachable from roots, plus the attribute names read along the way."""
        seen, attrs = set(), set()
        queue = collections.deque(roots)
        while True:
            while queue:
                q = queue.popleft()
                if q in seen or q not in self.nodes:
                    continue
                seen.add(q)
                node = self.nodes[q]
                queue.extend(self.parents(node))
                for ref in node.refs:
                    queue.extend(self.resolve(ref))
                attrs |= node.attrs
            for cq in [c for c in self.methods if c in seen]:
                ext = self.external_base(cq)
                for mq in self.methods[cq]:
                    short = mq.rsplit(".", 1)[1]
                    if mq not in seen and (ext or short in attrs or (short.startswith("__") and short.endswith("__"))):
                        queue.append(mq)
            if not queue:
                return seen, attrs


def _main_nodes(graph, include_tests=False):
    return sorted(q for q, n in graph.nodes.items() if n.kind == "main" and (include_tests or not n.test))


def infer_entry_points(graph, manifest_entries=()):
    """Console scripts from the manifests, every non-test __main__ block and __main__.py, and top-level __all__."""
    out = list(manifest_entries)
    out.extend(_main_nodes(graph))
    out.extend(m for m in sorted(graph.modules) if (m == "__main__" or m.endswith(".__main__"))
               and not graph.nodes[m].test)
    for pkg in sorted(graph.all_names):
        if "." not in pkg and not graph.nodes[pkg].test:
            out.extend("%s:%s" % (pkg, name) for name in graph.all_names[pkg])
    seen = set()
    return [e for e in out if not (e in seen or seen.add(e))]


def _roots(graph, entries):
    roots, notes = [], []
    for entry in entries:
        mod, _, attr = entry.partition(":")
        if mod not in graph.modules:
            notes.append("entry point %s: module %s is not among the scanned Python files" % (entry, mod))
        elif attr == "__main__":
            q = "%s:__main__" % mod
            roots.append(q if q in graph.nodes else mod)
            if q not in graph.nodes:
                notes.append("entry point %s: the module has no __main__ block; rooted the whole module" % entry)
        elif not attr:
            roots.append(mod)
        else:
            hits = graph.resolve("%s.%s" % (mod, attr))
            if hits and graph.nodes[hits[0]].kind != "module":
                roots.append(hits[0])
            else:
                roots.append(mod)
                notes.append("entry point %s: %s is not a function or class; rooted the whole module" % (entry, attr))
    return roots, notes


def _kept(q, keep):
    return any(fnmatch.fnmatchcase(q, p) or fnmatch.fnmatchcase(q + ".", p) for p in keep)


def _uncertain_reason(graph, node, markers, strings):
    short = node.q.rsplit(".", 1)[-1]
    for rq, (kind, mods, frags) in markers:
        if kind == "import":
            if node.kind == "module" and (not frags or any(f in node.q for f in frags)):
                return "a computed import in %s may load it" % rq
        elif node.module in mods and node.kind != "module" and (not frags or any(f in short for f in frags)):
            return "%s with a computed name in %s may reach it" % (kind, rq)
    if short in strings:
        return "its name appears in a string in reachable code (a registry or dispatch table may use it)"
    registering = [d for d in node.decorators if d not in PURE_DECORATORS and not str(d).endswith((".setter", ".getter", ".deleter"))]
    if registering:
        return "decorated with @%s, which may register it" % registering[0]
    return None


def _orphan(code, node, why, source, n_entries, inside=0):
    what = {"module": "module", "class": "class", "function": "function", "method": "method"}[node.kind]
    summary = {"orphan.dead": "%s %s is never reached from the entry points",
               "orphan.test_only": "%s %s is reached only from tests",
               "orphan.uncertain": "%s %s may be reached dynamically"}[code] % (what, node.q)
    evidence = ["name: %s" % node.q, "kind: %s" % what, "entry points: %d (%s)" % (n_entries, source)]
    if why:
        evidence.append("why uncertain: %s" % why)
    if inside:
        evidence.append("definitions inside: %d" % inside)
    try_ = {"orphan.dead": ["delete it, or list it in keep if something loads it by name"],
            "orphan.test_only": ["delete it with its tests, or call it from the product"],
            "orphan.uncertain": ["list it in keep if it is loaded by name; otherwise delete it"]}[code]
    return make_finding(code, "partial", LEVELS[code], "%s:%d" % (node.rel, node.line), summary, evidence, try_)


def analyse(trees, goal=None, manifest_entries=()):
    graph = Graph(trees)
    notes = ["%s maps to a module name already taken; not analysed for orphans" % d for d in graph.dupes]
    keep = list((goal or {}).get("keep") or [])
    if goal and goal.get("entry_points"):
        source, entries = "contract", list(goal["entry_points"])
    else:
        source, entries = "inferred", infer_entry_points(graph, manifest_entries)
        if goal:
            notes.append("the goal file lists no entry_points; they were inferred")
    roots, more = _roots(graph, entries)
    notes.extend(more)
    tool_run = sorted(module_name(r) for r in graph.modules.values() if r in TOOL_RUN)
    kept = sorted(q for q in graph.nodes if _kept(q, keep))
    result = {"source": source, "goal": (goal or {}).get("goal", ""), "entry_points": entries, "keep": keep,
              "findings": [], "notes": notes,
              "counts": {"orphan.dead": 0, "orphan.test_only": 0, "orphan.uncertain": 0}}
    if not roots:
        notes.append("no entry points found, so nothing is reported: run `code-guardian init` and edit the goal file")
        return result
    reached, _ = graph.reach(roots + kept + tool_run)
    tests_reached, _ = graph.reach(sorted(q for q, n in graph.nodes.items() if n.test))
    strings = set()
    for q in reached:
        strings |= graph.nodes[q].strings
    markers = [(q, m) for q in sorted(reached) for m in graph.nodes[q].dyn]
    inside = collections.Counter(n.module for n in graph.nodes.values() if n.kind != "module")
    for q in sorted(graph.nodes):
        node = graph.nodes[q]
        if node.test or node.kind == "main" or q in reached or _kept(q, keep):
            continue
        if node.kind != "module" and node.module not in reached:
            continue
        if node.kind == "method" and node.cls not in reached:
            continue
        parent = node.module.rpartition(".")[0] if node.kind == "module" else ""
        if parent in graph.nodes and parent not in reached and not _kept(parent, keep):
            continue
        why = _uncertain_reason(graph, node, markers, strings)
        code = "orphan.uncertain" if why else "orphan.test_only" if q in tests_reached else "orphan.dead"
        result["findings"].append(_orphan(code, node, why, source, len(entries),
                                          inside[q] if node.kind == "module" else 0))
        result["counts"][code] += 1
    result["findings"] = sort_findings(result["findings"])
    return result


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if "--selftest" in argv:
        return selftest()
    sys.stderr.write("usage: python -m code_guardian.orphans --selftest\n")
    return 2


def selftest():
    src = {
        "app/__init__.py": "",
        "app/cli.py": ("import sys\nfrom app import core\nfrom app.core import Box\n"
                       "def main():\n    core.greet()\n    Box().open()\n    return getattr(sys.modules[__name__], 'cmd_' + sys.argv[1])()\n"
                       "def cmd_hi():\n    pass\n"
                       "if __name__ == '__main__':\n    main()\n"),
        "app/core.py": ("def greet():\n    pass\ndef shout():\n    pass\ndef for_tests():\n    pass\n"
                        "class Box:\n    def open(self):\n        pass\n    def close(self):\n        pass\n"),
        "app/plugins/__init__.py": "",
        "app/plugins/loud.py": "def run():\n    pass\n",
        "tests/test_core.py": "from app.core import for_tests\ndef test_it():\n    for_tests()\n",
    }
    trees = {rel: ast.parse(text) for rel, text in src.items()}
    goal = {"goal": "x", "entry_points": ["app.cli:main"], "keep": ["app.plugins.*"]}
    got = analyse(trees, goal)
    names = sorted((f["code"], f["evidence"][0][6:]) for f in got["findings"])
    inferred = analyse(trees)
    no_keep = analyse(trees, dict(goal, keep=[]))
    checks = [
        ("module_name", [module_name(r) for r in ("a/b.py", "a/__init__.py", "src/a/c.py", "x.py")] == ["a.b", "a", "a.c", "x"]),
        ("is_test", [is_test(r) for r in ("tests/x.py", "a/test_b.py", "a/b_test.py", "conftest.py", "a/b.py")]
         == [True, True, True, True, False]),
        ("contract_findings", names == [("orphan.dead", "app.core.Box.close"), ("orphan.dead", "app.core.shout"),
                                        ("orphan.test_only", "app.core.for_tests"), ("orphan.uncertain", "app.cli.cmd_hi")]),
        ("levels", sorted({f["code"]: f["level"] for f in got["findings"]}.items()) ==
         [("orphan.dead", "WARN"), ("orphan.test_only", "INFO"), ("orphan.uncertain", "INFO")]),
        ("node_is_file_line", any(f["node"] == "app/core.py:3" for f in got["findings"])),
        ("inferred", inferred["source"] == "inferred" and inferred["entry_points"] == ["app.cli:__main__"]),
        ("keep_matters", ("orphan.dead", "app.plugins") in sorted((f["code"], f["evidence"][0][6:]) for f in no_keep["findings"])),
        ("missing_entry", any("not among" in n for n in analyse(trees, dict(goal, entry_points=["nope:main"]))["notes"])),
        ("no_roots_no_claims", analyse({"a.py": ast.parse("def f():\n    pass\n")})["findings"] == []),
    ]
    return summarize("orphans", checks)


if __name__ == "__main__":
    sys.exit(main())
