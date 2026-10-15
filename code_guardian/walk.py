"""Walk a project tree and sort its files into Python, manifests and everything else.

Pure apart from reading the tree: nothing is executed, imported or written. Symlinks are never followed, so a scan
cannot be steered outside PATH.

Public contract:
    SKIP_DIRS, MAX_BYTES
    load_ignore(root) -> list of patterns from PATH/.gitignore
    ignored(relpath, is_dir, patterns) -> bool
    walk(root, exclude=()) -> {"python": [rel], "manifests": [rel], "other": [rel],
                               "skipped": [(rel, reason)], "excluded": int, "ignored": int}
    read(root, rel) -> (bytes, text)
"""

import fnmatch
import os
import shutil
import sys
import tempfile

from .finding import summarize

SKIP_DIRS = frozenset({".git", "venv", ".venv", "node_modules", "__pycache__", "dist", "build",
                       ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".eggs"})
MANIFEST_NAMES = frozenset({"package.json", "setup.py", "setup.cfg", "pyproject.toml"})
MAX_BYTES = 2_000_000
SNIFF_BYTES = 8192


def _compile(line):
    """One .gitignore line -> (glob, dir_only, anchored), or None for blanks, comments and negations."""
    line = line.rstrip("\n").rstrip()
    if not line or line.startswith("#") or line.startswith("!"):
        return None
    dir_only = line.endswith("/")
    line = line.rstrip("/")
    anchored = "/" in line
    line = line.lstrip("/")
    if line.startswith("**/"):
        line, anchored = line[3:], "/" in line[3:]
    return (line, dir_only, anchored) if line else None


def load_ignore(root):
    """Patterns from PATH/.gitignore (root file only); a missing or unreadable file gives none."""
    try:
        with open(os.path.join(root, ".gitignore"), encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return []
    return [p for p in (_compile(ln) for ln in lines) if p]


def ignored(relpath, is_dir, patterns):
    """True when relpath (forward slashes, relative to PATH) matches a pattern. Simple globs only: no negation."""
    name = relpath.rsplit("/", 1)[-1]
    for glob, dir_only, anchored in patterns:
        if dir_only and not is_dir:
            continue
        target = relpath if anchored else name
        if fnmatch.fnmatchcase(target, glob):
            return True
        if anchored and glob.endswith("/**") and fnmatch.fnmatchcase(relpath, glob[:-3]):
            return True
    return False


def _excluded(relpath, globs):
    return any(fnmatch.fnmatchcase(relpath, g) or fnmatch.fnmatchcase(relpath + "/", g) for g in globs)


def _is_manifest(name):
    return name in MANIFEST_NAMES or (name.startswith("requirements") and name.endswith(".txt"))


def walk(root, exclude=()):
    """Sorted, deterministic inventory of the files under root."""
    patterns = load_ignore(root)
    out = {"python": [], "manifests": [], "other": [], "skipped": [], "excluded": 0, "ignored": 0}
    for dirpath, dirnames, filenames in os.walk(root):
        reldir = os.path.relpath(dirpath, root).replace(os.sep, "/")
        reldir = "" if reldir == "." else reldir + "/"
        keep = []
        for d in sorted(dirnames):
            rel = reldir + d
            if d in SKIP_DIRS or os.path.islink(os.path.join(dirpath, d)):
                continue
            if ignored(rel, True, patterns):
                out["ignored"] += 1
                continue
            if _excluded(rel, exclude):
                out["excluded"] += 1
                continue
            keep.append(d)
        dirnames[:] = keep
        for name in sorted(filenames):
            rel = reldir + name
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                out["skipped"].append((rel, "symlink"))
                continue
            if ignored(rel, False, patterns):
                out["ignored"] += 1
                continue
            if _excluded(rel, exclude):
                out["excluded"] += 1
                continue
            try:
                size = os.path.getsize(full)
                with open(full, "rb") as fh:
                    head = fh.read(SNIFF_BYTES)
            except OSError:
                out["skipped"].append((rel, "unreadable"))
                continue
            if b"\0" in head:
                out["skipped"].append((rel, "binary"))
                continue
            if size > MAX_BYTES:
                out["skipped"].append((rel, "larger than %d bytes" % MAX_BYTES))
                continue
            if name.endswith(".py"):
                out["python"].append(rel)
            if _is_manifest(name):
                out["manifests"].append(rel)
            elif not name.endswith(".py"):
                out["other"].append(rel)
    for key in ("python", "manifests", "other", "skipped"):
        out[key].sort()
    return out


def read(root, rel):
    """(raw bytes, text decoded as UTF-8 with replacement) for one walked file."""
    with open(os.path.join(root, *rel.split("/")), "rb") as fh:
        raw = fh.read()
    return raw, raw.decode("utf-8", errors="replace")


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if "--selftest" in argv:
        return selftest()
    sys.stderr.write("usage: python -m code_guardian.walk --selftest\n")
    return 2


def selftest():
    tmp = tempfile.mkdtemp()

    def put(rel, data=b"x = 1\n"):
        full = os.path.join(tmp, *rel.split("/"))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as fh:
            fh.write(data)

    try:
        put(".gitignore", b"# comment\n*.log\nsecret_dir/\n/only_root.py\n!keep.log\n")
        for rel in ("a.py", "pkg/b.py", "pkg/setup.py", "web/app.js", "x.log", "secret_dir/s.py", "only_root.py",
                    "deep/only_root.py", "node_modules/m.js", ".venv/v.py", "pyproject.toml", "requirements-dev.txt",
                    "fixtures/f.py"):
            put(rel)
        put("blob.bin", b"\0\1\2")
        inv = walk(tmp, exclude=("fixtures/*",))
        checks = [
            ("python", inv["python"] == ["a.py", "deep/only_root.py", "pkg/b.py", "pkg/setup.py"]),
            ("manifests", inv["manifests"] == ["pkg/setup.py", "pyproject.toml", "requirements-dev.txt"]),
            ("other", inv["other"] == [".gitignore", "web/app.js"]),
            ("binary_skipped", inv["skipped"] == [("blob.bin", "binary")]),
            ("ignored_count", inv["ignored"] == 3),
            ("excluded_count", inv["excluded"] == 1),
            ("compile", _compile("!x") is None and _compile("# c") is None and _compile("/a/") == ("a", True, True) and _compile("b/") == ("b", True, False)),
            ("anchored_glob", ignored("docs/build/x", False, [("docs/*", False, True)])),
            ("read", read(tmp, "a.py") == (b"x = 1\n", "x = 1\n")),
        ]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return summarize("walk", checks)


if __name__ == "__main__":
    sys.exit(main())
