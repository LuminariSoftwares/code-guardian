"""Complete checks: does it have what it needs? File presence plus basic parsing; nothing is run.

    complete.license_missing     WARN  no LICENSE / LICENCE / COPYING file at the root
    complete.license_undeclared  WARN  packaging metadata exists but declares no licence
    complete.readme_missing      WARN  no README at the root
    complete.readme_short        WARN  README under 200 bytes
    complete.readme_sections     WARN  README (200+ bytes) without an install or a usage heading
    complete.ci_missing          WARN  no CI configuration
    complete.metadata            WARN  pyproject [project] without name, version or requires-python
    complete.lockfile            WARN  an application (see APP MARKERS) without a lockfile
    complete.env_example         WARN  the code reads environment variables but there is no .env.example
    deps.declared_unused         INFO  a runtime dependency that nothing imports

Application markers (a library, with [project] and none of these, needs no lockfile): a Dockerfile or
Containerfile; a __main__.py when the project declares no [project.scripts]; a module-level Flask/FastAPI/
Starlette/Quart/Sanic app object or Django get_wsgi_application()/get_asgi_application(). Markers under examples/,
docs/ and tests/ do not count.

Undeclared dependencies are not checked here: works.import_unresolved owns them.

Public contract:
    readme_missing_sections(text) -> ["install", "usage"] subset
    app_markers(project) -> [str]        env_reads(rel, tree) -> [(line, name or None)]
    check(project) -> [finding]
"""

import ast
import re
import sys
import tomllib

from .finding import make_finding, summarize
from .manifests import _cfg, declared as declared_deps, scripts as manifest_scripts
from .orphans import is_test
from .works import import_declared, normalise

README_MIN = 200
LICENSE_NAMES = re.compile(r"(?i)^(licen[cs]e|copying|unlicense)([.-].*)?$")
README_NAMES = re.compile(r"(?i)^readme(\.(md|markdown|rst|txt))?$")
INSTALL_WORDS = re.compile(r"(?i)\b(install|installation|installing|setup|set up|getting started|quick ?start)\b")
USAGE_WORDS = re.compile(r"(?i)\b(usage|use|using|examples?|getting started|quick ?start|tutorial|how to|run|running|"
                         r"commands?|cli)\b")
CI_FILES = (".gitlab-ci.yml", ".travis.yml", "azure-pipelines.yml", "Jenkinsfile", "bitbucket-pipelines.yml",
            ".drone.yml", "appveyor.yml", ".appveyor.yml", ".cirrus.yml", ".woodpecker.yml")
CI_DIRS = (".github/workflows/", ".circleci/", ".woodpecker/", ".buildkite/")
LOCKFILES = ("uv.lock", "poetry.lock", "Pipfile.lock", "pdm.lock", "pixi.lock", "requirements.lock")
ENV_EXAMPLES = (".env.example", ".env.sample", ".env.template", ".env.dist", "example.env", "sample.env", "env.example")
APP_CALLS = ("Flask", "FastAPI", "Starlette", "Quart", "Sanic", "get_wsgi_application", "get_asgi_application")
NOT_PRODUCT = frozenset({"examples", "example", "docs", "doc", "samples", "sample", "demo", "demos", "tutorial",
                         "tests", "test", "testing", "benchmarks", "bench"})
NOT_IMPORTED = frozenset({"gunicorn", "uvicorn", "hypercorn", "waitress", "daphne", "setuptools", "wheel", "pip",
                          "build", "twine", "black", "ruff", "flake8", "mypy", "pylint", "isort", "pre-commit", "tox",
                          "nox", "coverage", "pytest", "ipykernel", "jupyter", "notebook", "certifi"})
NOT_IMPORTED_PREFIXES = ("types-", "pytest-", "flake8-", "sphinx", "mkdocs")
ENV_CALLS = frozenset({"os.getenv", "os.getenvb", "os.environ.get", "os.environ.setdefault", "dotenv.load_dotenv",
                       "dotenv.dotenv_values", "dotenv.find_dotenv"})


def _finding(code, level, node, summary, evidence=(), try_=()):
    return make_finding(code, "partial", level, node, summary, evidence=list(evidence), try_=list(try_))


def _headings(text):
    lines = text.splitlines()
    out = [ln.lstrip("#").strip() for ln in lines if re.match(r"\s{0,3}#{1,6}\s", ln)]
    for prev, line in zip(lines, lines[1:]):
        if prev.strip() and re.fullmatch(r"\s*([=\-~^*+#`'\".:_])\1{0,}\s*", line) and len(line.strip()) >= 1:
            out.append(prev.strip())
    return out


def readme_missing_sections(text):
    heads = _headings(text)
    missing = []
    if not any(INSTALL_WORDS.search(h) for h in heads):
        missing.append("install")
    if not any(USAGE_WORDS.search(h) for h in heads):
        missing.append("usage")
    return missing


def _product(rel):
    return not is_test(rel) and not any(p in NOT_PRODUCT for p in rel.split("/")[:-1])


def _call_name(func):
    return func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")


def app_markers(project):
    files, trees, texts = project["files"], project["trees"], project["texts"]
    out = []
    for rel in files:
        name = rel.rsplit("/", 1)[-1]
        if _product(rel) and (name in ("Dockerfile", "Containerfile") or name.endswith(".Dockerfile")
                              or name.startswith("Dockerfile.")):
            out.append(name if "/" not in rel else rel)
    has_scripts = any(manifest_scripts(rel, text) for rel, text in texts.items())
    if not has_scripts:
        out.extend("%s (no [project.scripts])" % rel for rel in sorted(trees)
                   if rel.rsplit("/", 1)[-1] == "__main__.py" and _product(rel))
    for rel in sorted(trees):
        if not _product(rel):
            continue
        for stmt in trees[rel].body:
            value = getattr(stmt, "value", None)
            if isinstance(stmt, (ast.Assign, ast.AnnAssign)) and isinstance(value, ast.Call) \
                    and _call_name(value.func) in APP_CALLS:
                out.append("%s:%d %s()" % (rel, stmt.lineno, _call_name(value.func)))
    return out


def _is_lockfile(rel, text):
    name = rel.rsplit("/", 1)[-1]
    if name in LOCKFILES:
        return True
    if name.startswith("requirements") and name.endswith(".txt") and text is not None:
        reqs = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith(("#", "-"))]
        return bool(reqs) and ("--hash=" in text or all("==" in r for r in reqs))
    return False


def env_reads(rel, tree):
    """[(line, variable name or None)] for os.environ / os.getenv / dotenv use in one file."""
    aliases = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom) and n.module in ("os", "dotenv"):
            for a in n.names:
                aliases[a.asname or a.name] = "%s.%s" % (n.module, a.name)
    out = []
    for n in ast.walk(tree):
        name, key = None, None
        if isinstance(n, ast.Call):
            target = n.func
            dotted = _dotted(target, aliases)
            if dotted in ENV_CALLS:
                name, key = dotted, n.args[0] if n.args else None
        elif isinstance(n, ast.Subscript) and _dotted(n.value, aliases) in ("os.environ", "os.environb"):
            name, key = "os.environ", n.slice
        if name:
            out.append((n.lineno, key.value if isinstance(key, ast.Constant) and isinstance(key.value, str) else None))
    return sorted(set(out), key=lambda t: (t[0], t[1] or ""))


def _dotted(node, aliases):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return ""
    return ".".join([aliases.get(node.id, node.id)] + parts[::-1])


def _license_declared(texts, trees):
    """None when there is no packaging metadata to declare a licence in; else whether one is declared."""
    has_meta, declared = False, False
    if "pyproject.toml" in texts:
        try:
            data = tomllib.loads(texts["pyproject.toml"])
        except tomllib.TOMLDecodeError:
            data = {}
        project = data.get("project")
        poetry = (data.get("tool") or {}).get("poetry")
        if isinstance(project, dict):
            has_meta = True
            declared |= bool(project.get("license") or project.get("license-files")
                             or any("License ::" in c for c in project.get("classifiers") or []))
        if isinstance(poetry, dict) and poetry.get("name"):
            has_meta = True
            declared |= bool(poetry.get("license"))
    if "setup.cfg" in texts:
        cp = _cfg(texts["setup.cfg"])
        if cp is not None and cp.has_section("metadata"):
            has_meta = True
            declared |= any(cp.has_option("metadata", k) for k in ("license", "license_file", "license_files")) \
                or "License ::" in texts["setup.cfg"]
    if "setup.py" in trees:
        for n in ast.walk(trees["setup.py"]):
            if isinstance(n, ast.Call) and _call_name(n.func) == "setup":
                has_meta = True
                declared |= any(kw.arg in ("license", "license_files") for kw in n.keywords) \
                    or "License ::" in ast.dump(n)
    return declared if has_meta else None


def _project_line(text):
    for i, line in enumerate(text.splitlines(), 1):
        if line.strip() == "[project]":
            return i
    return 1


def check(project):
    files, texts, trees = project["files"], project["texts"], project["trees"]
    root_files = {f for f in files if "/" not in f}
    out = []
    if not any(LICENSE_NAMES.match(f) for f in root_files):
        out.append(_finding("complete.license_missing", "WARN", ".", "no licence file: nobody may legally reuse this code",
                            ["looked for: LICENSE, LICENCE, COPYING, UNLICENSE (any extension)"],
                            ["add a LICENSE file (choosealicense.com helps pick one)"]))
    declared_licence = _license_declared(texts, trees)
    if declared_licence is False:
        where = "pyproject.toml:%d" % _project_line(texts["pyproject.toml"]) if "pyproject.toml" in texts else \
            "setup.cfg:1" if "setup.cfg" in texts else "setup.py:1"
        out.append(_finding("complete.license_undeclared", "WARN", where, "the package metadata declares no licence",
                            ["no license / license-files / License classifier"],
                            ['add license = "MIT" (or your licence) to [project]']))
    readmes = sorted(f for f in root_files if README_NAMES.match(f))
    if not readmes:
        out.append(_finding("complete.readme_missing", "WARN", ".", "no README: nobody can tell what this is or how to run it",
                            ["looked for: README, README.md, README.rst, README.txt"], ["add a README.md"]))
    else:
        text = project["read"](readmes[0])
        size = len(text.encode("utf-8"))
        if size < README_MIN:
            out.append(_finding("complete.readme_short", "WARN", "%s:1" % readmes[0],
                                "README is %d bytes: too short to explain install and usage" % size,
                                ["minimum: %d bytes" % README_MIN], ["describe what it does, how to install, how to use"]))
        else:
            missing = readme_missing_sections(text)
            if missing:
                out.append(_finding("complete.readme_sections", "WARN", "%s:1" % readmes[0],
                                    "README has no %s section" % " or ".join(missing),
                                    ["missing heading: %s" % ", ".join(missing)],
                                    ["add an 'Install' and a 'Usage' heading"]))
    if not any(f in CI_FILES or f.startswith(CI_DIRS) for f in files):
        out.append(_finding("complete.ci_missing", "WARN", ".", "no CI configuration: nothing runs the tests on each change",
                            ["looked for: .github/workflows/, .gitlab-ci.yml, .circleci/, and other CI files"],
                            ["add a CI workflow that runs the tests"]))
    if "pyproject.toml" in texts:
        try:
            meta = tomllib.loads(texts["pyproject.toml"]).get("project")
        except tomllib.TOMLDecodeError:
            meta = None
        if isinstance(meta, dict):
            dynamic = set(meta.get("dynamic") or [])
            missing = [k for k in ("name", "version", "requires-python") if not meta.get(k) and k not in dynamic]
            if missing:
                out.append(_finding("complete.metadata", "WARN", "pyproject.toml:%d" % _project_line(texts["pyproject.toml"]),
                                    "pyproject.toml [project] is missing: %s" % ", ".join(missing),
                                    ["required: name, version (or dynamic), requires-python"],
                                    ["add the missing keys to [project]"]))
    markers = app_markers(project)
    if markers and not any(_is_lockfile(f, texts.get(f)) for f in files):
        out.append(_finding("complete.lockfile", "WARN", ".", "an application without a lockfile: installs can differ run to run",
                            ["application marker: %s" % markers[0],
                             "looked for: %s, a fully pinned requirements.txt" % ", ".join(LOCKFILES)],
                            ["commit a lockfile (uv lock, poetry lock, or pip-compile)"]))
    reads = [(rel, line, key) for rel in sorted(trees) if _product(rel) for line, key in env_reads(rel, trees[rel])]
    if reads and not any(f.rsplit("/", 1)[-1] in ENV_EXAMPLES for f in files):
        names = sorted({k for _, _, k in reads if k})
        out.append(_finding("complete.env_example", "WARN", "%s:%d" % reads[0][:2],
                            "the code reads environment variables but there is no .env.example",
                            ["reads: %s" % (", ".join(names[:10]) or "names built at runtime")],
                            ["add a .env.example listing every variable with a safe placeholder"]))
    out.extend(_declared_unused(texts, trees))
    return out


def _declared_unused(texts, trees):
    imported = set()
    for tree in trees.values():
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                imported.update(a.name.split(".")[0] for a in n.names)
            elif isinstance(n, ast.ImportFrom) and not n.level and n.module:
                imported.add(n.module.split(".")[0])
    out, seen = [], set()
    for rel in sorted(texts):
        runtime = rel.rsplit("/", 1)[-1] in ("pyproject.toml", "setup.py", "setup.cfg", "Pipfile", "requirements.txt")
        if not runtime:
            continue
        for dist, line, kind in declared_deps(rel, texts[rel], trees.get(rel)):
            key = normalise(dist)
            if kind not in ("runtime", "requirements") or key in seen or key in NOT_IMPORTED \
                    or key.startswith(NOT_IMPORTED_PREFIXES) or key.endswith("-stubs"):
                continue
            seen.add(key)
            if not any(import_declared(m, {key}) for m in imported):
                out.append(_finding("deps.declared_unused", "INFO", "%s:%d" % (rel, line),
                                    "dependency %s is declared but never imported" % dist,
                                    ["kind: %s" % kind], ["remove it, or note why it is needed (a plugin or a runner)"]))
    return out


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if "--selftest" in argv:
        return selftest()
    sys.stderr.write("usage: python -m code_guardian.complete --selftest\n")
    return 2


def selftest():
    env = ast.parse("import os\nfrom os import getenv as g\nA = os.environ['A']\nB = g('B')\nC = os.environ.get(x)\n"
                    "from dotenv import load_dotenv\nload_dotenv()\n")
    bare = {"files": ["app.py"], "texts": {}, "trees": {"app.py": ast.parse("x = 1\n")}, "read": lambda rel: ""}
    codes = sorted(f["code"] for f in check(bare))
    app = {"files": ["Dockerfile", "w.py"], "texts": {}, "trees": {"w.py": ast.parse("from flask import Flask\napp = Flask(__name__)\n")}}
    checks = [
        ("sections", readme_missing_sections("# x\n## Install\n## Usage\n") == []
         and readme_missing_sections("# x\n## API\n") == ["install", "usage"]),
        ("setext", readme_missing_sections("Quickstart\n==========\n") == []),
        ("env_reads", [k for _, k in env_reads("a.py", env)] == ["A", "B", None, None]),
        ("bare", codes == ["complete.ci_missing", "complete.license_missing", "complete.readme_missing"]),
        ("markers", app_markers(app) == ["Dockerfile", "w.py:2 Flask()"]),
        ("lockfile", _is_lockfile("requirements.txt", "a==1\nb==2\n") and not _is_lockfile("requirements.txt", "a>=1\n")
         and _is_lockfile("uv.lock", None)),
        ("licence_meta", _license_declared({"pyproject.toml": '[project]\nname="x"\n'}, {}) is False
         and _license_declared({}, {}) is None
         and _license_declared({"pyproject.toml": '[project]\nlicense = "MIT"\n'}, {}) is True),
    ]
    return summarize("complete", checks)


if __name__ == "__main__":
    sys.exit(main())
