"""Declared layer rules and file-size limits, checked against the goal contract.

    works.layer_import     WARN  a file under a declared layer imports a module prefix the layer forbids
    works.file_too_long    WARN  a file has more lines than its declared size limit

The idea (declare which layers may not import which modules, and a maximum size per file, in a config the project
owns, then check it) comes from architecture linters of the import-linter kind, reviewed on Glama. Rewritten from the
idea: nothing is copied, and no such tool is a dependency.

A forbidden prefix "flask" matches the module "flask" and "flask.x", not "flasky". Path globs are the goal file's
`exclude` globs (fnmatch against the repo-relative path). Pure: the caller reads the files and parses the imports.

Public contract:
    violations(goal, files, import_index) -> [finding]
        goal: the dict goal.load returns (only "layers" and "size_limits" are read; a missing key means none)
        files: {rel path: line count}
        import_index: {rel path: [(module, lineno), ...]}
"""

import fnmatch
import sys

from .finding import make_finding, summarize


def _match(rel, glob):
    return fnmatch.fnmatchcase(rel, glob)


def _forbidden(module, prefixes):
    """The prefix that forbids `module`, or None."""
    for prefix in prefixes:
        if module == prefix or module.startswith(prefix + "."):
            return prefix
    return None


def violations(goal, files, import_index):
    out = []
    if not goal:
        return out
    for layer in goal.get("layers") or []:
        for rel in sorted(files):
            if not _match(rel, layer["path"]):
                continue
            for module, lineno in import_index.get(rel, ()):
                prefix = _forbidden(module, layer["forbidden_imports"])
                if prefix is None:
                    continue
                out.append(make_finding(
                    "works.layer_import", "partial", "WARN", "%s:%d" % (rel, lineno),
                    "%s imports %s, which the layer %s forbids" % (rel, module, layer["path"]),
                    evidence=["layer: %s" % layer["path"], "import: %s" % module, "forbidden prefix: %s" % prefix],
                    try_=["move the call behind a module the layer may import",
                          "or change forbidden_imports in the goal file if the rule is out of date"]))
    for glob, limit in sorted((goal.get("size_limits") or {}).items()):
        for rel in sorted(files):
            if _match(rel, glob) and files[rel] > limit:
                out.append(make_finding(
                    "works.file_too_long", "partial", "WARN", rel,
                    "%s has %d lines; the goal file allows %d for %s" % (rel, files[rel], limit, glob),
                    evidence=["lines: %d" % files[rel], "limit: %d (%s)" % (limit, glob)],
                    try_=["split the file by responsibility",
                          "or raise the limit in [size_limits] if the size is intended"]))
    return out


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if "--selftest" in argv:
        return selftest()
    sys.stderr.write("usage: python -m code_guardian.layers --selftest\n")
    return 2


def selftest():
    goal = {"layers": [{"path": "svc/*", "forbidden_imports": ["flask"]}], "size_limits": {"svc/web.py": 5}}
    files = {"svc/web.py": 9, "svc/db.py": 3, "lib/x.py": 50}
    index = {"svc/web.py": [("os", 1), ("flask", 4), ("flasky", 5), ("flask.views", 6)], "lib/x.py": [("flask", 1)]}
    got = violations(goal, files, index)
    layer = [f for f in got if f["code"] == "works.layer_import"]
    long_ = [f for f in got if f["code"] == "works.file_too_long"]
    checks = [
        ("layer_exact_and_dotted", [f["node"] for f in layer] == ["svc/web.py:4", "svc/web.py:6"]),
        ("prefix_not_substring", not any(f["node"] == "svc/web.py:5" for f in layer)),
        ("outside_layer_untouched", not any(f["node"].startswith("lib/") for f in got)),
        ("too_long_node_is_file", [f["node"] for f in long_] == ["svc/web.py"]),
        ("at_limit_is_fine", not violations({"size_limits": {"a.py": 5}}, {"a.py": 5}, {})),
        ("absent_declarations", violations({}, files, index) == [] and violations({"layers": [], "size_limits": {}},
                                                                                 files, index) == []),
        ("levels_warn", all(f["level"] == "WARN" for f in got)),
    ]
    return summarize("layers", checks)


if __name__ == "__main__":
    sys.exit(main())
