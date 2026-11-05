"""The goal contract: code-guardian.goal.toml at the project root says what the project is for and where it starts.

    goal = "One sentence: what this project is for."
    entry_points = ["pkg.cli:main", "pkg.server:app"]   # module:function, or module:__main__ for its main block
    keep = ["pkg.plugins.*"]                             # loaded dynamically; never reported as orphans
    exclude = ["tests/fixtures/*"]                       # paths (globs) the scan skips; the report counts them

    [[layers]]                                           # files under `path` may not import these module prefixes
    path = "svc/*"
    forbidden_imports = ["flask"]

    [size_limits]                                        # a glob and the most lines a matching file may have
    "svc/web.py" = 300

Public contract:
    FILENAME
    load(path) -> {"goal", "entry_points", "keep", "exclude", "layers", "size_limits", "path"}
                                                                          # raises GoalError on a bad file
    find(root, explicit=None) -> path or None
    render(goal, entry_points, keep=(), exclude=(), layers=(), size_limits=None) -> TOML text
"""

import json
import os
import sys
import tempfile
import tomllib

from .finding import summarize

FILENAME = "code-guardian.goal.toml"
LIST_KEYS = ("entry_points", "keep", "exclude")


class GoalError(ValueError):
    """The goal file is missing, unreadable or the wrong shape."""


def load(path):
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except OSError as exc:
        raise GoalError("cannot read goal file %s: %s" % (path, exc.strerror or exc)) from None
    except tomllib.TOMLDecodeError as exc:
        raise GoalError("goal file %s is not valid TOML: %s" % (path, exc)) from None
    goal = data.get("goal", "")
    if not isinstance(goal, str):
        raise GoalError("goal must be a string")
    out = {"goal": goal.strip(), "path": path}
    for key in LIST_KEYS:
        value = data.get(key, [])
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise GoalError("%s must be a list of strings" % key)
        out[key] = [v.strip() for v in value if v.strip()]
    out["layers"] = _layers(data.get("layers", []))
    out["size_limits"] = _size_limits(data.get("size_limits", {}))
    unknown = sorted(set(data) - {"goal", "layers", "size_limits"} - set(LIST_KEYS))
    out["unknown_keys"] = unknown
    return out


def _layers(value):
    if not isinstance(value, list) or not all(isinstance(v, dict) for v in value):
        raise GoalError("layers must be a list of [[layers]] tables")
    out = []
    for layer in value:
        path = layer.get("path")
        if not isinstance(path, str) or not path.strip():
            raise GoalError("layers: each [[layers]] table needs a string path")
        banned = layer.get("forbidden_imports", [])
        if not isinstance(banned, list) or not all(isinstance(v, str) for v in banned):
            raise GoalError("layers: forbidden_imports must be a list of strings")
        out.append({"path": path.strip(), "forbidden_imports": [v.strip() for v in banned if v.strip()]})
    return out


def _size_limits(value):
    if not isinstance(value, dict):
        raise GoalError("size_limits must be a table of glob = max lines")
    for glob, limit in value.items():
        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            raise GoalError("size_limits: %s must be a positive whole number of lines" % json.dumps(glob))
    return dict(value)


def find(root, explicit=None):
    """The goal file to use: --goal when given (it must exist), else ROOT/code-guardian.goal.toml if present."""
    if explicit:
        if not os.path.isfile(explicit):
            raise GoalError("goal file not found: %s" % explicit)
        return explicit
    path = os.path.join(root, FILENAME)
    return path if os.path.isfile(path) else None


def _toml_list(items):
    if not items:
        return "[]"
    return "[\n" + "".join("  %s,\n" % json.dumps(i) for i in items) + "]"


def render(goal, entry_points, keep=(), exclude=(), layers=(), size_limits=None):
    """A goal file. JSON string escapes are valid TOML basic strings, so json.dumps quotes every value."""
    text = ("# code-guardian goal contract: see https://github.com/LuminariSoftwares/code-guardian#goal-contract\n"
            "goal = %s\n\n"
            "# module:function, or module:__main__ for a module's `if __name__ == \"__main__\":` block\n"
            "entry_points = %s\n\n"
            "# qualified-name globs loaded dynamically (plugins); never reported as orphans\n"
            "keep = %s\n\n"
            "# path globs, relative to this file, that the scan skips\n"
            "exclude = %s\n" % (json.dumps(goal), _toml_list(entry_points), _toml_list(keep), _toml_list(exclude)))
    for layer in layers:
        text += "\n[[layers]]\npath = %s\nforbidden_imports = %s\n" % (
            json.dumps(layer["path"]), _toml_list(layer.get("forbidden_imports", [])))
    if size_limits:
        text += "\n[size_limits]\n" + "".join("%s = %d\n" % (json.dumps(g), n) for g, n in size_limits.items())
    return text


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if "--selftest" in argv:
        return selftest()
    sys.stderr.write("usage: python -m code_guardian.goal --selftest\n")
    return 2


def selftest():
    tmp = tempfile.mkdtemp()
    path = os.path.join(tmp, FILENAME)

    def write(text):
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)

    def raises(text):
        write(text)
        try:
            load(path)
        except GoalError:
            return True
        return False

    try:
        write(render('Say "hi"', ["a.cli:main"], ["a.plugins.*"], ["tests/fixtures/*"]))
        roundtrip = load(path)
        checks = [
            ("roundtrip", roundtrip["goal"] == 'Say "hi"' and roundtrip["entry_points"] == ["a.cli:main"]
             and roundtrip["keep"] == ["a.plugins.*"] and roundtrip["exclude"] == ["tests/fixtures/*"]),
            ("find_default", find(tmp) == path and find(os.path.join(tmp, "nope")) is None),
            ("bad_toml", raises("goal = ")),
            ("bad_list", raises('entry_points = "a:b"')),
            ("bad_goal", raises("goal = 3")),
            ("unknown_keys", (write('goal = "x"\nextra = 1\n'), load(path)["unknown_keys"])[1] == ["extra"]),
            ("empty_ok", (write(""), load(path)["entry_points"])[1] == []),
            ("layers_default", (write('goal = "x"\n'), load(path))[1]["layers"] == []
             and load(path)["size_limits"] == {}),
            ("layers_roundtrip", (write(render("x", [], layers=[{"path": "a/*", "forbidden_imports": ["b"]}],
                                              size_limits={"a/x.py": 9})), load(path))[1]["layers"]
             == [{"path": "a/*", "forbidden_imports": ["b"]}] and load(path)["size_limits"] == {"a/x.py": 9}
             and "layers" not in load(path)["unknown_keys"]),
            ("bad_layers", raises('goal = "x"\nlayers = "a"\n')),
            ("bad_forbidden", raises('[[layers]]\npath = "a"\nforbidden_imports = "b"\n')),
            ("bad_layer_path", raises('[[layers]]\nforbidden_imports = ["b"]\n')),
            ("bad_size_limit", raises('[size_limits]\n"a.py" = "big"\n') and raises('[size_limits]\n"a.py" = 0\n')),
        ]
        try:
            find(tmp, os.path.join(tmp, "missing.toml"))
            checks.append(("explicit_missing", False))
        except GoalError:
            checks.append(("explicit_missing", True))
    finally:
        if os.path.exists(path):
            os.remove(path)
        os.rmdir(tmp)
    return summarize("goal", checks)


if __name__ == "__main__":
    sys.exit(main())
