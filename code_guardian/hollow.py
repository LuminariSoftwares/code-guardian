"""Hollow tests: test functions that assert, but whose assertions cannot fail.

    works.test_hollow        WARN  a tautology (assert True, assert 1, assert x == x, assertTrue(True)), assertions
                                   only on a mock the test built, or an `except: pass` that swallows the failure

Reported once per test file, with the counts by kind. A test that works.test_no_assert already reports as silent is
left to it. Nothing is imported or run: the test file is read through ast only.

Public contract:
    test_hollow(rel, tree) -> (first hollow line or 0, total test functions,
                               {"tautology"|"mock_only"|"swallowed": [test names]})
    check(project) -> [finding]          # project: see report.scan
"""

import ast
import sys

from .finding import make_finding, summarize
from .orphans import is_test
from .works import ASSERT_CALLS, test_no_assert


MOCK_CTORS = frozenset({"Mock", "MagicMock", "AsyncMock", "NonCallableMock", "NonCallableMagicMock", "PropertyMock",
                        "patch", "create_autospec", "mocker", "monkeypatch"})
PLAIN_CALLS = frozenset({"len", "bool", "str", "int", "float", "list", "tuple", "set", "sorted", "isinstance", "repr"})


def _test_functions(tree):
    """[(name, function node)] for the test functions of one file: the set test_no_assert counts."""

    def fixture(fn):
        return any("fixture" in ast.dump(d) for d in fn.decorator_list)

    top = [s for s in tree.body if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)) and not fixture(s)]
    tests = [(f.name, f) for f in top if f.name.startswith("test")]
    for cls in (s for s in tree.body if isinstance(s, ast.ClassDef)):
        if cls.name.startswith("Test") or cls.bases:
            tests.extend(("%s.%s" % (cls.name, f.name), f) for f in cls.body
                         if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef)) and f.name.startswith("test")
                         and not fixture(f))
    return tests


def _callee(call):
    f = call.func
    return f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")


def _root(node):
    while isinstance(node, (ast.Attribute, ast.Subscript, ast.Call)):
        node = node.func if isinstance(node, ast.Call) else node.value
    return node.id if isinstance(node, ast.Name) else ""


def _is_mock_source(value):
    """True when the expression builds or patches a mock: MagicMock(), patch(...), mocker.patch(...), mock.patch.x."""
    if not isinstance(value, ast.Call):
        return False
    return _callee(value) in MOCK_CTORS or _root(value.func) in ("mocker", "mock")


def _mock_names(fn):
    names = set()
    patches = [d for d in fn.decorator_list if "patch" in ast.dump(d) and not any(
        k.arg == "new" for k in getattr(d, "keywords", []))]
    params = [a.arg for a in fn.args.args if a.arg not in ("self", "cls")]
    names.update(params[:len(patches)])
    for n in ast.walk(fn):
        if isinstance(n, ast.Assign) and _is_mock_source(n.value):
            names.update(t.id for t in n.targets if isinstance(t, ast.Name))
        elif isinstance(n, ast.AnnAssign) and n.value is not None and _is_mock_source(n.value) \
                and isinstance(n.target, ast.Name):
            names.add(n.target.id)
        elif isinstance(n, (ast.With, ast.AsyncWith)):
            for item in n.items:
                if isinstance(item.optional_vars, ast.Name) and _is_mock_source(item.context_expr):
                    names.add(item.optional_vars.id)
    return names


def _is_tautology(n):
    if isinstance(n, ast.Assert):
        t = n.test
        if isinstance(t, ast.Constant) and isinstance(t.value, (bool, int)) and t.value:
            return True
        return isinstance(t, ast.Compare) and len(t.ops) == 1 and isinstance(t.ops[0], ast.Eq) \
            and ast.dump(t.left) == ast.dump(t.comparators[0])
    if isinstance(n, ast.Call) and _callee(n) == "assertTrue" and len(n.args) == 1:
        a = n.args[0]
        return isinstance(a, ast.Constant) and isinstance(a.value, (bool, int)) and bool(a.value)
    return False


def _swallows(n):
    return isinstance(n, ast.ExceptHandler) and all(isinstance(s, ast.Pass) for s in n.body) \
        and (n.type is None or (isinstance(n.type, ast.Name) and n.type.id in ("Exception", "BaseException")))


def _only_mock_names(node, mocks):
    """True when every name in the expression is a mock (calls to len() and the like are looked through)."""
    skip = {id(c.func) for c in ast.walk(node) if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)
            and c.func.id in PLAIN_CALLS}
    seen = [n.id for n in ast.walk(node) if isinstance(n, ast.Name) and id(n) not in skip]
    return bool(seen) and all(name in mocks for name in seen)


def _mock_only(fn):
    mocks = _mock_names(fn)
    if not mocks:
        return False
    found = False
    for n in ast.walk(fn):
        if isinstance(n, ast.Assert):
            found = True
            if not _only_mock_names(n.test, mocks):
                return False
        elif isinstance(n, ast.Raise) and "AssertionError" in ast.dump(n):
            return False
        elif isinstance(n, ast.Call):
            name = _callee(n)
            if name.lower().startswith("assert") or name in ASSERT_CALLS:
                found = True
                targets = [n] if _root(n.func) in mocks else [n.func] + list(n.args)
                if name in ASSERT_CALLS or not all(_only_mock_names(t, mocks) for t in targets):
                    return False
    return found


def test_hollow(rel, tree):
    """(first hollow line, total test functions, {"tautology"|"mock_only"|"swallowed": [test names]}) for one test file.

    A hollow test has assertions that cannot fail or that only check a mock: a tautology (assert True, assert 1,
    assert x == x, assertTrue(True)), asserts only on names bound from unittest.mock / mocker / patch, or an
    `except: pass` / `except Exception: pass` that swallows the failure. One kind per test, in that order. A test
    that test_no_assert already reports as silent is left to it, so nothing is reported twice. Detecting hollow
    tests is an idea from the test-quality reviewers listed on Glama; rewritten from the idea.
    """
    _, total, silent = test_no_assert(rel, tree)
    skip = set(silent)
    kinds = {"tautology": [], "mock_only": [], "swallowed": []}
    lines = []
    for name, fn in _test_functions(tree):
        if name in skip:
            continue
        nodes = list(ast.walk(fn))
        if any(_is_tautology(n) for n in nodes):
            kind = "tautology"
        elif _mock_only(fn):
            kind = "mock_only"
        elif any(_swallows(n) for n in nodes):
            kind = "swallowed"
        else:
            continue
        kinds[kind].append(name)
        lines.append(fn.lineno)
    return (min(lines) if lines else 0), total, kinds


def check(project):
    """One works.test_hollow WARN per test file that has hollow tests."""
    out = []
    trees = project["trees"]
    for rel in sorted(trees):
        if not is_test(rel):
            continue
        first, total, hollow = test_hollow(rel, trees[rel])
        if not first:
            continue
        count = sum(len(v) for v in hollow.values())
        out.append(make_finding(
            "works.test_hollow", "partial", "WARN", "%s:%d" % (rel, first),
            "%d of %d test functions in this file are hollow (tautology %d, mock-only %d, swallowed %d)"
            % (count, total, len(hollow["tautology"]), len(hollow["mock_only"]), len(hollow["swallowed"])),
            evidence=["%s: %s" % (label, ", ".join(hollow[kind])) for kind, label in
                      (("tautology", "tautology"), ("mock_only", "mock-only"), ("swallowed", "swallowed exception"))
                      if hollow[kind]],
            try_=["assert on a value the code under test returns, not on a constant or a mock",
                  "let the exception fail the test, or use pytest.raises for the expected error"]))
    return out


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if "--selftest" in argv:
        return selftest()
    sys.stderr.write("usage: python -m code_guardian.hollow --selftest\n")
    return 2


def selftest():
    sample = ast.parse("def test_t():\n    assert True\ndef test_m():\n    m = MagicMock()\n    m.go()\n"
                       "    assert m.go.called\ndef test_s():\n    try:\n        int('x')\n    except:\n"
                       "        pass\n    assert int('1') == 1\ndef test_n():\n    pass\n"
                       "class TestX:\n    def test_u(self):\n        self.assertTrue(True)\n"
                       "    def test_ok(self):\n        self.assertEqual(int('2'), 2)\n")
    clean = ast.parse("def test_ok():\n    assert int('4') == 4\n")
    found = check({"trees": {"tests/test_x.py": sample, "pkg/a.py": sample}})
    checks = [
        ("hollow", test_hollow("tests/test_x.py", sample) == (
            1, 6, {"tautology": ["test_t", "TestX.test_u"], "mock_only": ["test_m"], "swallowed": ["test_s"]})),
        ("hollow_clean", test_hollow("tests/test_x.py", clean) == (0, 1, {"tautology": [], "mock_only": [],
                                                                         "swallowed": []})),
        ("silent_left_alone", "test_n" not in str(test_hollow("tests/test_x.py", sample)[2])),
        ("finding", [(f["code"], f["level"], f["node"]) for f in found]
         == [("works.test_hollow", "WARN", "tests/test_x.py:1")]),
    ]
    return summarize("hollow", checks)


if __name__ == "__main__":
    sys.exit(main())
