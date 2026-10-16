"""AI leftovers: code an assistant (or a hurried human) left half-done. Read from the parse; nothing is run.

    works.todo_stub        WARN  a function whose body is only pass, ..., raise NotImplementedError (or a docstring
                                 plus one of those) that an entry point reaches: it will be called and do nothing
    works.commented_code   INFO  a run of 5+ consecutive comment lines that parse as Python (once per file, counted)
    works.dead_flag        INFO  a module-level ALL_CAPS boolean constant that nothing anywhere reads

Not stubs: abstract methods (@abstractmethod, or a method of a class with an ABC base or an ABCMeta metaclass),
Protocol classes (Protocol[T] too), @overload signatures, a base-class method that a subclass in the repo overrides
(the template method pattern), dunder methods (an __exit__ that does nothing), methods of null objects (classes named
Null*, Noop*, Dummy*, Mock*, Fake*) and click/typer @group callbacks. Stubs are judged against the orphan graph's reachable set, so with no entry points nothing is
claimed. Product code only: tests, fixtures and docs are skipped.

Public contract:
    is_stub(fn) -> bool
    commented_code(rel, text) -> finding or None
    check(project, reached) -> [finding]   # project: see report.scan; reached: qualified names the entry points reach
"""

import ast
import io
import sys
import textwrap
import tokenize

from .finding import make_finding, summarize
from .orphans import module_name
from .works import product

MIN_RUN = 5
# Deliberate no-ops found in calibration (calibration.md): a null object's methods, a click/typer group callback.
NULL_CLASS_PREFIXES = ("Null", "Noop", "NoOp", "Dummy", "Mock", "Fake")
REGISTERING_NOOP = ("group",)
ABSTRACT = ("abstractmethod", "abstractproperty", "abstractclassmethod", "abstractstaticmethod")
OVERLOAD = ("overload",)
TRIVIAL = (ast.Expr, ast.Pass)


def _finding(code, level, node, summary, evidence=(), try_=()):
    return make_finding(code, "partial", level, node, summary, evidence=list(evidence), try_=list(try_))


def _tail(node):
    """'abstractmethod' for abc.abstractmethod, @abstractmethod or @x.abstractmethod(...); 'Protocol' for
    t.Protocol[T]."""
    node = node.func if isinstance(node, ast.Call) else node
    node = node.value if isinstance(node, ast.Subscript) else node
    return node.attr if isinstance(node, ast.Attribute) else getattr(node, "id", "")


def _what(stmt):
    if isinstance(stmt, ast.Pass):
        return "pass"
    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and stmt.value.value is Ellipsis:
        return "..."
    if isinstance(stmt, ast.Raise) and stmt.exc is not None and _tail(stmt.exc) == "NotImplementedError":
        return "raise NotImplementedError"
    return None


def is_stub(fn):
    """The body is only pass, ..., or raise NotImplementedError, optionally after a docstring."""
    body = fn.body
    if (len(body) == 2 and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)):
        body = body[1:]
    return len(body) == 1 and _what(body[0]) is not None


def _defs(tree, mod):
    """(qualified name, def node, class node or None) for module-level functions and methods of module-level classes,
    looking inside module-level if/try/with blocks as the orphan graph does."""
    out = []

    def walk(stmts):
        for stmt in stmts:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                out.append(("%s.%s" % (mod, stmt.name), stmt, None))
            elif isinstance(stmt, ast.ClassDef):
                for s in stmt.body:
                    if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        out.append(("%s.%s.%s" % (mod, stmt.name, s.name), s, stmt))
            elif isinstance(stmt, (ast.If, ast.Try, ast.With, ast.For, ast.While)) or type(stmt).__name__ == "TryStar":
                for field in ("body", "orelse", "finalbody"):
                    walk(getattr(stmt, field, []) or [])
                for h in getattr(stmt, "handlers", []) or []:
                    walk(h.body)
    walk(tree.body)
    return out


def _abstract_class(cls):
    bases = {_tail(b) for b in cls.bases} | {_tail(k.value) for k in cls.keywords if k.arg == "metaclass"}
    return bool(bases & {"ABC", "ABCMeta", "Protocol"})


def _overridden(trees):
    """{(class name, method name)} for methods a subclass in the repo defines again."""
    out = set()
    for tree in trees.values():
        for cls in ast.walk(tree):
            if isinstance(cls, ast.ClassDef):
                names = {s.name for s in cls.body if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef))}
                for b in cls.bases:
                    out.update((_tail(b), n) for n in names)
    return out


def todo_stubs(trees, reached):
    overridden = _overridden(trees)
    out = []
    for rel in sorted(trees):
        if not product(rel):
            continue
        for q, fn, cls in _defs(trees[rel], module_name(rel)):
            if q not in reached or not is_stub(fn):
                continue
            tails = {_tail(d) for d in fn.decorator_list}
            if tails & set(ABSTRACT + OVERLOAD + REGISTERING_NOOP):
                continue
            if fn.name.startswith("__") and fn.name.endswith("__"):
                continue  # __exit__ / __enter__ no-ops satisfy a protocol
            if cls is not None and (_abstract_class(cls) or (cls.name, fn.name) in overridden
                                    or cls.name.startswith(NULL_CLASS_PREFIXES)):
                continue
            body = fn.body[-1]
            out.append(_finding("works.todo_stub", "WARN", "%s:%d" % (rel, fn.lineno),
                                "%s is a stub (its body is only %s) and an entry point reaches it" % (q, _what(body)),
                                ["def: %s" % q, "body: %s" % _what(body)],
                                ["implement it, or delete it and its callers",
                                 "if subclasses must implement it, mark it @abc.abstractmethod"]))
    return out


def _comment_runs(text):
    """[(first line, [comment text without '#'])] for runs of full-line comments, from tokenize."""
    runs, cur, last = [], [], None
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (tokenize.TokenError, SyntaxError, IndentationError):
        return []
    code_lines = {t.start[0] for t in tokens if t.type not in (tokenize.COMMENT, tokenize.NL, tokenize.NEWLINE,
                                                                 tokenize.INDENT, tokenize.DEDENT, tokenize.ENDMARKER)}
    for t in tokens:
        if t.type != tokenize.COMMENT or t.start[0] in code_lines:
            continue
        line = t.start[0]
        body = t.string[1:]
        body = body[1:] if body.startswith(" ") else body
        if cur and line == last + 1:
            cur[1].append(body)
        else:
            if cur:
                runs.append(cur)
            cur = [line, [body]]
        last = line
    if cur:
        runs.append(cur)
    return [(first, lines) for first, lines in runs]


def _is_code(lines):
    src = textwrap.dedent("\n".join(lines))
    try:
        tree = ast.parse(src)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return False
    # bare words and constants ("# TODO", "# note") parse too; real code has a statement or a call
    return any(not isinstance(s, TRIVIAL) or isinstance(getattr(s, "value", None), (ast.Call, ast.Await))
               for s in tree.body) and bool(tree.body)


def commented_code(rel, text):
    blocks = [first for first, lines in _comment_runs(text) if len(lines) >= MIN_RUN and _is_code(lines)]
    if not blocks:
        return None
    n = len(blocks)
    return _finding("works.commented_code", "INFO", "%s:%d" % (rel, blocks[0]),
                    "%d block%s of commented-out code (%d+ lines that parse as Python)" % (n, "s" if n > 1 else "",
                                                                                           MIN_RUN),
                    ["blocks: %d" % n, "first at line %d" % blocks[0]],
                    ["delete it: version control keeps the old code"])


def _reads(trees):
    """Every name read anywhere: Name loads, attribute names, imported names and __all__ strings."""
    out = set()
    for tree in trees.values():
        for n in ast.walk(tree):
            if isinstance(n, ast.Name) and not isinstance(n.ctx, ast.Store):
                out.add(n.id)
            elif isinstance(n, ast.Attribute):
                out.add(n.attr)
            elif isinstance(n, ast.ImportFrom):
                out.update(a.name for a in n.names)
            elif isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value.isidentifier():
                out.add(n.value)
    return out


def dead_flags(trees):
    reads = _reads(trees)
    out = []
    for rel in sorted(trees):
        if not product(rel):
            continue
        for stmt in trees[rel].body:
            if not (isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name)
                    and isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, bool)):
                continue
            name = stmt.targets[0].id
            if name.isupper() and len(name) > 1 and name not in reads:
                out.append(_finding("works.dead_flag", "INFO", "%s:%d" % (rel, stmt.lineno),
                                    "flag %s = %s is never read anywhere" % (name, stmt.value.value),
                                    ["flag: %s" % name], ["delete it, or wire it to the code it was meant to switch"]))
    return out


def check(project, reached):
    trees, out = project["trees"], []
    out.extend(todo_stubs(trees, reached))
    read = project.get("read")
    for rel in sorted(trees):
        if product(rel) and read:
            hit = commented_code(rel, read(rel))
            if hit:
                out.append(hit)
    out.extend(dead_flags(trees))
    return out


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if "--selftest" in argv:
        return selftest()
    sys.stderr.write("usage: python -m code_guardian.leftovers --selftest\n")
    return 2


def selftest():
    src = ("import abc\n"
           "def a():\n    pass\n"
           "def b():\n    'doc'\n    raise NotImplementedError('later')\n"
           "def c():\n    ...\n"
           "def d():\n    return 1\n"
           "class K(abc.ABC):\n    @abc.abstractmethod\n    def e(self):\n        pass\n"
           "FLAG = True\nUSED = False\nprint(USED)\n")
    tree = ast.parse(src)
    reached = {"m.a", "m.b", "m.c", "m.d", "m.K.e"}
    stubs = todo_stubs({"m.py": tree}, reached)
    code = "# x = 1\n# y = f(x)\n# if y:\n#     g()\n# return y\nz = 0\n"
    checks = [
        ("is_stub", [is_stub(f) for f in tree.body if isinstance(f, ast.FunctionDef)] == [True, True, True, False]),
        ("todo_stubs", [f["node"] for f in stubs] == ["m.py:2", "m.py:4", "m.py:7"]),
        ("unreached_not_reported", todo_stubs({"m.py": tree}, set()) == []),
        ("commented_code", commented_code("m.py", code)["node"] == "m.py:1"),
        ("prose_is_not_code", commented_code("m.py", "# Load the data.\n" * 6 + "x = 1\n") is None),
        ("short_run", commented_code("m.py", "# x = 1\n" * 4 + "y = 2\n") is None),
        ("trailing_comments_skipped", commented_code("m.py", "".join("x%d = 1  # y = 2\n" % i for i in range(6))) is None),
        ("dead_flag", [f["summary"] for f in dead_flags({"m.py": tree})] == ["flag FLAG = True is never read anywhere"]),
    ]
    return summarize("leftovers", checks)


if __name__ == "__main__":
    sys.exit(main())
