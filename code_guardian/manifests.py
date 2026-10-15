"""Install hooks and dependency pins, read from manifests without running them.

package.json is read with json, pyproject.toml with tomllib, setup.cfg with configparser, setup.py with ast and
requirements*.txt line by line. setup.py is parsed, never executed.

Public contract:
    scan_manifest(rel, text, pyfile=None) -> [finding]     # install.hook (WARN) and deps.unpinned (INFO)
    bounded_pep508(req) -> bool / bounded_npm(spec) -> bool
    entry_points(rel, text) -> ["module:function"]         # console scripts, for orphan inference
"""

import ast
import configparser
import json
import re
import sys
import tomllib

from .finding import summarize
from .scanners import finding

NPM_HOOKS = ("preinstall", "install", "postinstall")
NPM_DEP_KEYS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
INSTALL_COMMANDS = frozenset({"install", "develop", "egg_info", "build", "build_py", "build_ext", "sdist",
                              "bdist_wheel", "bdist_egg", "easy_install"})
_UPPER_OPS = ("==", "<", "~=")


def line_of(text, needle, default=1):
    """1-based number of the first line containing needle."""
    for i, line in enumerate(text.splitlines(), 1):
        if needle in line:
            return i
    return default


def _name_of(req):
    m = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._\-]*)", req)
    return m.group(1) if m else req.strip()


def bounded_pep508(req):
    """True when a PEP 508 requirement has a pin or an upper bound (==, ===, <, <=, ~=)."""
    spec = req.split(";", 1)[0]
    if "@" in spec:
        return False  # a direct URL reference carries no version bound
    spec = re.sub(r"^\s*[A-Za-z0-9][A-Za-z0-9._\-]*\s*(\[[^\]]*\])?", "", spec)
    return any(op in part for part in spec.split(",") for op in _UPPER_OPS)


def bounded_npm(spec):
    """True when an npm version range has an upper bound (exact, ^, ~, x-ranges, or a < in every alternative)."""
    spec = (spec or "").strip()
    if spec in ("", "*", "x", "X", "latest", "next") or re.match(r"(git|https?|github:|git\+)", spec):
        return False
    for alt in spec.split("||"):
        alt = alt.strip()
        if not alt or alt in ("*", "x") or (">" in alt and "<" not in alt):
            return False
    return True


def _unpinned(rel, text, name, needle, kind):
    return finding("deps.unpinned", "INFO", "%s:%d" % (rel, line_of(text, needle)),
                   "dependency %s has no pin or upper bound" % name,
                   ["manifest: %s" % kind, "requirement: %s" % needle[:120]],
                   ["pin it (==) or cap it (<next major) so an install cannot pull a new release silently"])


def _hook(rel, line, summary, evidence):
    return finding("install.hook", "WARN", "%s:%d" % (rel, line), summary, evidence,
                   ["read what the hook runs before installing", "prefer packages without install-time code"])


def scan_package_json(rel, text):
    try:
        data = json.loads(text)
    except ValueError:
        return []
    if not isinstance(data, dict):
        return []
    out = []
    scripts = data.get("scripts") if isinstance(data.get("scripts"), dict) else {}
    for hook in NPM_HOOKS:
        if hook in scripts:
            out.append(_hook(rel, line_of(text, '"%s"' % hook), "npm %s script runs on install" % hook,
                             ["script: %s" % str(scripts[hook])[:120]]))
    for key in NPM_DEP_KEYS:
        deps = data.get(key) if isinstance(data.get(key), dict) else {}
        for name in sorted(deps):
            spec = str(deps[name])
            if spec.startswith(("file:", "link:", "workspace:")):
                continue
            if not bounded_npm(spec):
                out.append(_unpinned(rel, text, name, '"%s"' % name, "package.json %s" % key))
    return out


def scan_pyproject(rel, text):
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    out = []
    build = data.get("build-system") or {}
    if build.get("backend-path"):
        out.append(_hook(rel, line_of(text, "backend-path"), "in-tree build backend runs project code on install",
                         ["build-system.backend-path: %s" % build.get("backend-path")]))
    cmdclass = ((data.get("tool") or {}).get("setuptools") or {}).get("cmdclass")
    if cmdclass:
        out.append(_hook(rel, line_of(text, "cmdclass"), "setuptools cmdclass overrides build/install commands",
                         ["tool.setuptools.cmdclass: %s" % ", ".join(sorted(cmdclass))]))
    project = data.get("project") or {}
    reqs = list(project.get("dependencies") or [])
    for extra in sorted(project.get("optional-dependencies") or {}):
        reqs.extend(project["optional-dependencies"][extra] or [])
    for req in reqs:
        if isinstance(req, str) and not bounded_pep508(req):
            out.append(_unpinned(rel, text, _name_of(req), req, "pyproject.toml"))
    poetry = ((data.get("tool") or {}).get("poetry") or {}).get("dependencies") or {}
    for name in sorted(poetry):
        spec = poetry[name]
        spec = spec.get("version", "") if isinstance(spec, dict) else str(spec)
        if name != "python" and not bounded_npm(spec):
            out.append(_unpinned(rel, text, name, name, "pyproject.toml [tool.poetry]"))
    return out


def _cfg(text):
    cp = configparser.ConfigParser(interpolation=None)
    try:
        cp.read_string(text)
    except configparser.Error:
        return None
    return cp


def scan_setup_cfg(rel, text):
    cp = _cfg(text)
    if cp is None:
        return []
    out = []
    reqs = []
    if cp.has_option("options", "install_requires"):
        reqs.extend(cp.get("options", "install_requires").splitlines())
    if cp.has_section("options.extras_require"):
        for _, value in sorted(cp.items("options.extras_require")):
            reqs.extend(value.splitlines())
    for req in (r.strip() for r in reqs):
        if req and not req.startswith("#") and not bounded_pep508(req):
            out.append(_unpinned(rel, text, _name_of(req), req, "setup.cfg"))
    return out


def scan_setup_py(rel, text, pf):
    """cmdclass= in setup(), classes that subclass setuptools/distutils install commands, install_requires pins."""
    out = []
    for n in pf.nodes:
        if isinstance(n, ast.Call) and (pf.name(n.func) or "").split(".")[-1] == "setup":
            for kw in n.keywords:
                if kw.arg == "cmdclass":
                    out.append(_hook(rel, kw.value.lineno, "setup() cmdclass overrides build/install commands",
                                     ["setup(cmdclass=...)"]))
                elif kw.arg == "install_requires" and isinstance(kw.value, (ast.List, ast.Tuple)):
                    for e in kw.value.elts:
                        if isinstance(e, ast.Constant) and isinstance(e.value, str) and not bounded_pep508(e.value):
                            out.append(finding("deps.unpinned", "INFO", "%s:%d" % (rel, e.lineno),
                                               "dependency %s has no pin or upper bound" % _name_of(e.value),
                                               ["manifest: setup.py", "requirement: %s" % e.value[:120]],
                                               ["pin it (==) or cap it (<next major)"]))
        elif isinstance(n, ast.ClassDef):
            for base in n.bases:
                name = pf.name(base) or ""
                tail = name.split(".")[-1]
                if tail in INSTALL_COMMANDS and (name.startswith(("setuptools.", "distutils.")) or name == tail):
                    out.append(_hook(rel, n.lineno, "class %s overrides the %s command" % (n.name, tail),
                                     ["class %s(%s)" % (n.name, name)]))
    return out


def scan_requirements(rel, text):
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        req = line.split(" #", 1)[0].strip()
        if not req or req.startswith(("#", "-", "git+", "http", ".", "/")):
            continue
        if not bounded_pep508(req):
            out.append(finding("deps.unpinned", "INFO", "%s:%d" % (rel, i), "dependency %s has no pin or upper bound" % _name_of(req),
                               ["manifest: %s" % rel.rsplit("/", 1)[-1], "requirement: %s" % req[:120]],
                               ["pin it (==) or cap it (<next major)"]))
    return out


def scan_manifest(rel, text, pyfile=None):
    name = rel.rsplit("/", 1)[-1]
    if name == "package.json":
        return scan_package_json(rel, text)
    if name == "pyproject.toml":
        return scan_pyproject(rel, text)
    if name == "setup.cfg":
        return scan_setup_cfg(rel, text)
    if name == "setup.py":
        return scan_setup_py(rel, text, pyfile) if pyfile is not None else []
    if name.startswith("requirements") and name.endswith(".txt"):
        return scan_requirements(rel, text)
    return []


def _clean_entry(value):
    return re.sub(r"\s*\[.*\]\s*$", "", str(value)).strip()


def entry_points(rel, text):
    """Console/GUI script targets ("module:function") a manifest declares; [] when it declares none or is unreadable."""
    name = rel.rsplit("/", 1)[-1]
    out = []
    if name == "pyproject.toml":
        try:
            project = tomllib.loads(text).get("project") or {}
        except tomllib.TOMLDecodeError:
            return []
        for key in ("scripts", "gui-scripts"):
            out.extend(_clean_entry(v) for _, v in sorted((project.get(key) or {}).items()))
    elif name == "setup.cfg":
        cp = _cfg(text)
        if cp is not None and cp.has_option("options.entry_points", "console_scripts"):
            for line in cp.get("options.entry_points", "console_scripts").splitlines():
                if "=" in line:
                    out.append(_clean_entry(line.split("=", 1)[1]))
    return [e for e in out if e]


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if "--selftest" in argv:
        return selftest()
    sys.stderr.write("usage: python -m code_guardian.manifests --selftest\n")
    return 2


def selftest():
    from .scanners import PyFile

    pkg = json.dumps({"scripts": {"postinstall": "node x.js", "test": "jest"},
                      "dependencies": {"a": "*", "b": "^1.2.0", "c": ">=2", "d": "1.0.0"}}, indent=1)
    pyproject = ('[project]\nname = "x"\ndependencies = ["requests>=2", "flask==3.0", "attrs~=23.1", "rich<14"]\n'
                 '[project.scripts]\nx = "x.cli:main"\n')
    setup = ("from setuptools import setup\nfrom setuptools.command.install import install\n"
             "class Post(install):\n    pass\nsetup(install_requires=['numpy'], cmdclass={'install': Post})\n")

    def codes(found):
        return sorted((f["code"], f["node"]) for f in found)

    checks = [
        ("pep508", [bounded_pep508(r) for r in ("a", "a>=1", "a>=1,<2", "a==1", "a~=1.2", "a @ https://x", "a[x]<3")]
         == [False, False, True, True, True, False, True]),
        ("npm", [bounded_npm(s) for s in ("*", "^1", "~1.2", ">=1", ">=1 <2", "1.2.3", "latest", "1 || >=2")]
         == [False, True, True, False, True, True, False, False]),
        ("package_json", codes(scan_manifest("package.json", pkg)) ==
         [("deps.unpinned", "package.json:7"), ("deps.unpinned", "package.json:9"), ("install.hook", "package.json:3")]),
        ("pyproject", codes(scan_manifest("pyproject.toml", pyproject)) == [("deps.unpinned", "pyproject.toml:3")]),
        ("setup_py", codes(scan_manifest("setup.py", setup, PyFile("setup.py", setup.encode(), setup))) ==
         [("deps.unpinned", "setup.py:5"), ("install.hook", "setup.py:3"), ("install.hook", "setup.py:5")]),
        ("setup_cfg", codes(scan_manifest("setup.cfg", "[options]\ninstall_requires =\n    numpy\n    scipy==1.0\n")) ==
         [("deps.unpinned", "setup.cfg:3")]),
        ("requirements", codes(scan_manifest("requirements.txt", "# c\nrequests\n-r other.txt\nflask==3\n")) ==
         [("deps.unpinned", "requirements.txt:2")]),
        ("entry_points", entry_points("pyproject.toml", pyproject) == ["x.cli:main"]),
        ("bad_json_is_empty", scan_manifest("package.json", "{nope") == []),
    ]
    return summarize("manifests", checks)


if __name__ == "__main__":
    sys.exit(main())
