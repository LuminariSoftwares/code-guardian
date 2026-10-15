"""Works checks: will it work? Read from the parse and the manifests; nothing is imported, installed or run.

    works.syntax             FAIL  a .py file does not parse (INFO when the project needs a newer Python than this one)
    works.import_unresolved  WARN  an absolute import is not stdlib, not in the repo, not a declared dependency
    works.relative_missing   FAIL  a relative import points at a module that does not exist
    works.tests_missing      WARN  there are no test files at all
    works.test_no_assert     WARN  test functions that assert nothing (once per file, with the count)
    works.entry_missing      FAIL  a [project.scripts] target module:function is not in the tree

Undeclared dependencies have one owner: works.import_unresolved (Complete does not report them again).

Public contract:
    STDLIB, IMPORT_DISTS, TEST_TOOLS
    normalise(name) -> PEP 503 name      import_declared(module, declared) -> bool
    local_names(files) -> set            unresolved_imports(rel, tree, local, declared) -> [(line, module)]
    check(project) -> [finding]          # project: see report.scan
"""

import ast
import re
import sys

from .finding import make_finding, summarize
from .manifests import declared as declared_deps, scripts as manifest_scripts
from .orphans import is_test, module_name

# sys.stdlib_module_names is per interpreter; this union keeps the answer the same on every Python >= 3.11.
REMOVED_AFTER_311 = frozenset({"aifc", "asynchat", "asyncore", "audioop", "cgi", "cgitb", "chunk", "crypt",
                               "distutils", "imghdr", "imp", "lib2to3", "mailcap", "msilib", "nis", "nntplib",
                               "ossaudiodev", "pipes", "smtpd", "sndhdr", "spwd", "sunau", "telnetlib", "uu", "xdrlib"})
ADDED_AFTER_311 = frozenset({"annotationlib", "compression"})
STDLIB = frozenset(sys.stdlib_module_names) | REMOVED_AFTER_311 | ADDED_AFTER_311

# Import names whose distribution is called something else. Generic rules cover the rest: the normalised import
# name, python-X / pyX / X-python / X-binary, and namespace packages (google -> google-cloud-storage).
IMPORT_DISTS = {
    "yaml": ("pyyaml",), "PIL": ("pillow",), "cv2": ("opencv-python", "opencv-contrib-python",
                                                     "opencv-python-headless", "opencv-contrib-python-headless"),
    "sklearn": ("scikit-learn",), "skimage": ("scikit-image",), "bs4": ("beautifulsoup4",),
    "dateutil": ("python-dateutil",), "dotenv": ("python-dotenv",), "jwt": ("pyjwt",),
    "Crypto": ("pycryptodome", "pycrypto"), "Cryptodome": ("pycryptodomex",), "OpenSSL": ("pyopenssl",),
    "magic": ("python-magic",), "serial": ("pyserial",), "usb": ("pyusb",), "git": ("gitpython",),
    "github": ("pygithub",), "gi": ("pygobject",), "docx": ("python-docx",), "pptx": ("python-pptx",),
    "telegram": ("python-telegram-bot",), "discord": ("discord.py", "py-cord"), "slugify": ("python-slugify",),
    "jose": ("python-jose",), "multipart": ("python-multipart",), "Levenshtein": ("levenshtein", "python-levenshtein"),
    "zmq": ("pyzmq",), "MySQLdb": ("mysqlclient",), "psycopg2": ("psycopg2-binary", "psycopg2"),
    "attr": ("attrs",), "fitz": ("pymupdf",), "faiss": ("faiss-cpu", "faiss-gpu"), "mpl_toolkits": ("matplotlib",),
    "pkg_resources": ("setuptools",), "_pytest": ("pytest",), "websocket": ("websocket-client",),
    "socks": ("pysocks",), "nacl": ("pynacl",), "Xlib": ("python-xlib",), "ldap": ("python-ldap",),
    "kafka": ("kafka-python",), "dns": ("dnspython",), "grpc": ("grpcio",), "OpenGL": ("pyopengl",),
    "wx": ("wxpython",), "markdown_it": ("markdown-it-py",), "skbuild": ("scikit-build",), "hamcrest": ("pyhamcrest",),
    "umap": ("umap-learn",), "Bio": ("biopython",), "speech_recognition": ("speechrecognition",),
    "decouple": ("python-decouple",), "pythonjsonlogger": ("python-json-logger",), "lark": ("lark", "lark-parser"),
    "win32api": ("pywin32",), "win32con": ("pywin32",), "win32com": ("pywin32",), "win32gui": ("pywin32",),
    "pywintypes": ("pywin32",), "pythoncom": ("pywin32",), "Cython": ("cython",), "pyximport": ("cython",),
    "IPython": ("ipython",), "sentencepiece": ("sentencepiece",), "google": ("protobuf",),
    "typing_extensions": ("typing-extensions",), "importlib_metadata": ("importlib-metadata",),
    "sqlalchemy": ("sqlalchemy",), "flask_sqlalchemy": ("flask-sqlalchemy",), "ruamel": ("ruamel.yaml",),
    "msgpack": ("msgpack",), "lxml": ("lxml",), "jinja2": ("jinja2",), "markupsafe": ("markupsafe",),
}
TEST_TOOLS = frozenset({"pytest", "_pytest", "hypothesis", "mock", "nose", "nose2", "pytest_asyncio", "pytest_mock"})
SETUP_TOOLS = frozenset({"setuptools", "pkg_resources", "distutils", "wheel", "pip"})
MODULE_EXTS = (".py", ".pyi", ".pyx", ".pxd", ".so", ".pyd", ".c", ".cpp")
GUARD_ERRORS = frozenset({"ImportError", "ModuleNotFoundError", "Exception", "BaseException"})
ASSERT_CALLS = frozenset({"raises", "warns", "fail", "deprecated_call", "assertRaises", "assertWarns"})


def normalise(name):
    return re.sub(r"[-_.]+", "-", str(name)).lower()


def import_declared(module, declared):
    """declared holds normalised distribution names."""
    n = normalise(module)
    candidates = {n, "python-" + n, "py" + n, n + "-python", n + "-py", n + "-binary", n + "-cpu", n + "-gpu"}
    candidates.update(normalise(d) for d in IMPORT_DISTS.get(module, ()))
    return bool(candidates & declared) or any(d.startswith(n + "-") for d in declared)


def registered_modules(trees):
    """Names the repo puts into sys.modules under a literal string (sys.modules["x"] = ..., .setdefault("x", ...))."""
    out = set()
    for tree in trees.values():
        for n in ast.walk(tree):
            target = None
            if isinstance(n, ast.Subscript) and isinstance(n.ctx, ast.Store):
                target = n
            elif (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "setdefault"
                  and n.args):
                target = n.func.value
                key = n.args[0]
            if target is None:
                continue
            base = target.value if isinstance(target, ast.Subscript) else target
            if not (isinstance(base, ast.Attribute) and base.attr == "modules"
                    and isinstance(base.value, ast.Name) and base.value.id == "sys"):
                continue
            key = target.slice if isinstance(target, ast.Subscript) else key
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                out.add(key.value.split(".")[0])
    return out


def local_names(files):
    """Every directory name and module stem in the repo: anything an absolute import could find in the tree."""
    out = set()
    for rel in files:
        parts = rel.split("/")
        out.update(parts[:-1])
        stem, _, ext = parts[-1].partition(".")
        if "." + ext.rsplit(".", 1)[-1] in MODULE_EXTS:
            out.add(stem)
    return out


def _parents(tree):
    parents = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    return parents


def _handler_names(handler):
    t = handler.type
    if t is None:
        return {"BaseException"}
    elts = t.elts if isinstance(t, ast.Tuple) else [t]
    return {e.attr if isinstance(e, ast.Attribute) else getattr(e, "id", "") for e in elts}


def _guarded(node, parents):
    """Inside try/except ImportError (either branch: the try is the preferred import, the handler the fallback), or
    under `if TYPE_CHECKING:`: an optional, alternative or typing-only import."""
    child, cur = node, parents.get(node)
    while cur is not None:
        if isinstance(cur, ast.Try) and child in cur.body and any(_handler_names(h) & GUARD_ERRORS for h in cur.handlers):
            return True
        if isinstance(cur, ast.ExceptHandler) and _handler_names(cur) & GUARD_ERRORS:
            return True
        if isinstance(cur, ast.If) and child in cur.body and "TYPE_CHECKING" in ast.dump(cur.test):
            return True
        child, cur = cur, parents.get(cur)
    return False


def unresolved_imports(rel, tree, local, declared):
    """[(line, top-level module)] for absolute imports nothing in the repo or its manifests provides; one per module."""
    parents = _parents(tree)
    test = is_test(rel)
    setup = rel.rsplit("/", 1)[-1] == "setup.py"
    out, seen = [], set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            names = [a.name for a in n.names]
        elif isinstance(n, ast.ImportFrom) and not n.level and n.module:
            names = [n.module]
        else:
            continue
        for full in names:
            top = full.split(".")[0]
            if (top in seen or top == "__future__" or top in STDLIB or top in local or import_declared(top, declared)
                    or (test and top in TEST_TOOLS) or (setup and top in SETUP_TOOLS) or _guarded(n, parents)):
                continue
            seen.add(top)
            out.append((n.lineno, top))
    return sorted(out)


def _finding(code, level, node, summary, evidence=(), try_=()):
    return make_finding(code, "partial", level, node, summary, evidence=list(evidence), try_=list(try_))


def bound_names(tree):
    """Names a module binds at top level (defs, classes, assignments, imports), looking inside if/try blocks.
    None when it star-imports (anything could be bound)."""
    out = set()
    stack = list(tree.body)
    while stack:
        s = stack.pop()
        if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.add(s.name)
        elif isinstance(s, (ast.Import, ast.ImportFrom)):
            for a in s.names:
                if a.name == "*":
                    return None
                out.add(a.asname or a.name.split(".")[0])
        elif isinstance(s, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            for t in (s.targets if isinstance(s, ast.Assign) else [s.target]):
                out.update(x.id for x in ast.walk(t) if isinstance(x, ast.Name))
        elif isinstance(s, (ast.If, ast.Try, ast.With, ast.For, ast.While)) or type(s).__name__ == "TryStar":
            for field in ("body", "orelse", "finalbody"):
                stack.extend(getattr(s, field, []) or [])
            for h in getattr(s, "handlers", []) or []:
                stack.extend(h.body)
    return out


def _module_exists(path, files, dirs):
    """A module at path (no extension): any file whose name before the first dot matches, or a package directory."""
    if path in dirs:
        return True
    folder, _, stem = path.rpartition("/")
    return any(f.rpartition("/")[0] == folder and f.rpartition("/")[2].split(".")[0] == stem
               for f in files.get(folder, ()))


def relative_missing(rel, tree, by_dir, dirs, trees):
    out = []
    here = rel.split("/")[:-1]
    for n in ast.walk(tree):
        if not (isinstance(n, ast.ImportFrom) and n.level):
            continue
        if n.level - 1 > len(here):
            out.append((n.lineno, "." * n.level + (n.module or ""), "goes above the top of the repo"))
            continue
        base = here[:len(here) - (n.level - 1)]
        if n.module:
            path = "/".join(base + n.module.split("."))
            if not _module_exists(path, by_dir, dirs):
                out.append((n.lineno, "." * n.level + n.module, "no module %s in the repo" % path))
            continue
        init = "/".join(base + ["__init__.py"])
        bound = bound_names(trees[init]) if init in trees else set()
        for a in n.names:
            path = "/".join(base + [a.name])
            if not _module_exists(path, by_dir, dirs) and bound is not None and a.name not in bound:
                out.append((n.lineno, "." * n.level + " import " + a.name,
                            "%s is neither a module next to %s nor a name its package defines" % (a.name, rel)))
                break
    return out


def test_no_assert(rel, tree):
    """(first offending line, total test functions, names without an assertion) for one test file."""

    def asserts(fn, helpers):
        for n in ast.walk(fn):
            if isinstance(n, ast.Assert):
                return True
            if isinstance(n, ast.Raise) and "AssertionError" in ast.dump(n):
                return True
            if isinstance(n, ast.Call):
                name = n.func.attr if isinstance(n.func, ast.Attribute) else getattr(n.func, "id", "")
                if name.lower().startswith("assert") or name in ASSERT_CALLS or name in helpers:
                    return True
        return False

    top = [s for s in tree.body if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef))]
    helpers = {f.name for f in top if not f.name.startswith("test") and asserts(f, set())}
    tests = [(f.name, f) for f in top if f.name.startswith("test")]
    for cls in (s for s in tree.body if isinstance(s, ast.ClassDef)):
        if cls.name.startswith("Test") or cls.bases:
            tests.extend(("%s.%s" % (cls.name, f.name), f) for f in cls.body
                         if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef)) and f.name.startswith("test"))
    silent = [(f.lineno, name) for name, f in tests if not asserts(f, helpers)]
    return (silent[0][0] if silent else 0), len(tests), [name for _, name in silent]


def _requires_python(texts):
    for rel, text in texts.items():
        if rel == "pyproject.toml":
            m = re.search(r'requires-python\s*=\s*["\']\s*(?:>=|~=|==|>)\s*3\.(\d+)', text)
            if m:
                return 3, int(m.group(1))
    return None


def entry_missing(texts, trees, modules, by_dir, dirs):
    out = []
    for rel, text in sorted(texts.items()):
        for script, target, line in manifest_scripts(rel, text):
            mod, _, attr = target.partition(":")
            node = "%s:%d" % (rel, line)
            if mod not in modules:
                path = mod.replace(".", "/")
                if not (_module_exists(path, by_dir, dirs) or _module_exists("src/" + path, by_dir, dirs)):
                    out.append((node, "script %r points at %s, but module %s is not in the repo" % (script, target, mod)))
                continue
            tree = trees.get(modules[mod])
            bound = bound_names(tree) if tree is not None else None
            if attr and bound is not None and attr.split(".")[0] not in bound:
                out.append((node, "script %r points at %s, but %s defines no %s" % (script, target, mod, attr)))
    return out


def check(project):
    """All Works checks over one scanned project (see report.scan for the dict)."""
    trees, texts, files = project["trees"], project["texts"], project["files"]
    py = project["python"]
    by_dir, dirs = {}, set()
    for f in files:
        folder = f.rpartition("/")[0]
        by_dir.setdefault(folder, []).append(f)
        parts = f.split("/")
        dirs.update("/".join(parts[:i]) for i in range(1, len(parts)))
    out = []
    newer = _requires_python(texts)
    for rel, exc in sorted(project["broken"].items()):
        where = "%s:%d" % (rel, getattr(exc, "lineno", None) or 1)
        evidence = ["%s: %s" % (type(exc).__name__, getattr(exc, "msg", None) or exc)]
        if newer and newer > sys.version_info[:2]:
            out.append(_finding("works.syntax", "INFO", where,
                                "does not parse with Python %d.%d; the project requires 3.%d+" % (sys.version_info[0], sys.version_info[1], newer[1]),
                                evidence, ["run code-guardian with Python 3.%d or newer" % newer[1]]))
        else:
            out.append(_finding("works.syntax", "FAIL", where, "Python file does not parse: it cannot be imported or run",
                                evidence, ["fix the syntax error (Python 2 code needs porting to Python 3)"]))
    declared = {normalise(name) for rel, text in texts.items()
                for name, _, _ in declared_deps(rel, text, trees.get(rel))}
    local = local_names(files) | registered_modules(trees)
    modules = {module_name(rel): rel for rel in py}
    for rel in sorted(trees):
        tree = trees[rel]
        for line, mod in unresolved_imports(rel, tree, local, declared):
            out.append(_finding("works.import_unresolved", "WARN", "%s:%d" % (rel, line),
                                "import %s: not in the standard library, the repo, or a declared dependency" % mod,
                                ["module: %s" % mod, "declared dependencies: %d" % len(declared)],
                                ["add the distribution that provides %s to your dependencies" % mod,
                                 "or guard the import with try/except ImportError if it is optional"]))
        for line, what, why in relative_missing(rel, tree, by_dir, dirs, trees):
            out.append(_finding("works.relative_missing", "FAIL", "%s:%d" % (rel, line),
                                "relative import %s points at nothing in the repo" % what, ["why: %s" % why],
                                ["fix the module path or add the missing module"]))
        if is_test(rel):
            first, total, silent = test_no_assert(rel, tree)
            if silent:
                out.append(_finding("works.test_no_assert", "WARN", "%s:%d" % (rel, first),
                                    "%d of %d test functions in this file make no assertion" % (len(silent), total),
                                    ["without an assertion: %s" % ", ".join(silent)],
                                    ["assert on the result, or use pytest.raises for the expected error"]))
    if py and not any(is_test(rel) for rel in py):
        out.append(_finding("works.tests_missing", "WARN", ".", "no test files: nothing checks that the code works",
                            ["looked for: tests/, test_*.py, *_test.py, tests.py, conftest.py"],
                            ["add a tests/ folder with at least one test per entry point"]))
    for node, summary in entry_missing(texts, trees, modules, by_dir, dirs):
        out.append(_finding("works.entry_missing", "FAIL", node, summary, ["the installed command would crash on start"],
                            ["point the script at an existing module:function"]))
    return out


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if "--selftest" in argv:
        return selftest()
    sys.stderr.write("usage: python -m code_guardian.works --selftest\n")
    return 2


def selftest():
    guarded = ast.parse("try:\n    import ujson\nexcept ImportError:\n    ujson = None\n"
                        "if TYPE_CHECKING:\n    import pandas\nimport numpy\nimport os\nimport yaml\nimport mypkg.sub\n")
    weak = ast.parse("def helper():\n    assert True\ndef test_a():\n    pass\ndef test_b():\n    helper()\n"
                     "def test_c():\n    assert 1\nclass TestX:\n    def test_d(self):\n        self.assertTrue(1)\n")
    files = ["pkg/__init__.py", "pkg/a.py", "pkg/_fast.cpython-311-x86_64-linux-gnu.so", "pkg/sub/__init__.py"]
    by_dir = {"pkg": files[:3], "pkg/sub": files[3:]}
    rel_tree = ast.parse("from . import a\nfrom ._fast import f\nfrom .sub import x\nfrom .gone import y\nfrom ... import z\n")
    project = {"python": ["pkg/__init__.py", "pkg/cli.py"], "files": ["pkg/__init__.py", "pkg/cli.py", "pyproject.toml"],
               "trees": {"pkg/__init__.py": ast.parse(""), "pkg/cli.py": ast.parse("def main():\n    pass\n")},
               "broken": {}, "texts": {"pyproject.toml": '[project.scripts]\nok = "pkg.cli:main"\nbad = "pkg.cli:nope"\n'}}
    codes = sorted((f["code"], f["node"]) for f in check(project))
    checks = [
        ("stdlib_union", {"distutils", "imp", "tomllib", "os"} <= STDLIB),
        ("mapping", import_declared("yaml", {"pyyaml"}) and import_declared("google", {"google-cloud-storage"})
         and import_declared("dotenv", {"python-dotenv"}) and not import_declared("numpy", {"pandas"})),
        ("guards", unresolved_imports("pkg/x.py", guarded, {"mypkg"}, {"pyyaml"}) == [(7, "numpy")]),
        ("test_tools", unresolved_imports("tests/test_x.py", ast.parse("import pytest\n"), set(), set()) == []),
        ("no_assert", test_no_assert("tests/test_x.py", weak) == (3, 4, ["test_a"])),
        ("relative", [ln for ln, _, _ in relative_missing("pkg/m.py", rel_tree, by_dir, {"pkg", "pkg/sub"}, {})] == [4, 5]),
        ("check", codes == [("works.entry_missing", "pyproject.toml:3"), ("works.tests_missing", ".")]),
        ("normalise", normalise("Ruamel.YAML") == "ruamel-yaml" and normalise("typing_extensions") == "typing-extensions"),
    ]
    return summarize("works", checks)


if __name__ == "__main__":
    sys.exit(main())
