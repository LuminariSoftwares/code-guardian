"""P81 S3 acceptance -- code_guardian/works_js.py, the JavaScript / TypeScript Works checks (P81 C3).

Written by the overseer on main (96714b9) BEFORE the build session. The build session adds this file to the PR
byte-for-byte and never edits it. Pure ASCII on purpose; no key-shaped value anywhere.

Contract (C3), with the overseer's precisions marked P:
  P1 works_js.load(root, files, javascript=None) -> {"javascript": [rel], "js_tokens": {rel: tokens},
     "package_json": {rel: dict}, "tsconfig": {rel: dict}, "notes": [str]}: files are root-relative posix paths (what
     report.scan calls project["files"]); javascript defaults to every .js .mjs .cjs .jsx .ts .tsx among them (S4 passes
     the list without generated files); package.json / tsconfig.json / jsconfig.json are read from root; a file that
     does not parse after C3's comment and trailing-comma stripping is left out and named in notes, never raised.
  P2 works_js.check(project) -> [finding] reads only "root", "python", "files" and the five load() keys; S4 merges
     load() into report.scan's dict. Findings use the Works finding shape; node is "rel:line" (a manifest finding
     points at the line of its key; works.tests_missing at ".").
  P3 works.tests_missing (C3 "combined with the Python rule"): works.py is not edited, and it already fires when there
     are Python files and no Python test; so works_js fires it only when the project has JS files, no JS test signal
     and NO Python files. Dropping the Python finding when JS tests exist is S4's (report.py).
  P4 The bracket-balance INFO is skipped for a file that already has an EOF error (that file FAILs instead).
  P5 The S3 row says scripts.build "turns the two FAILs into INFO"; js_broken has one build-output FAIL (main ->
     dist/index.js). That one becomes INFO; ./util and half.js stay FAIL.
  P6 The build-output INFO looks at the first segment of the RESOLVED path, relative to the nearest package.json's
     folder ('../dist/lib' from src/main.js is dist/lib). Scheme specs give one INFO per import, at its line; the
     tsconfig-paths and workspaces INFOs are one per file, at the first unresolved import. A non-default
     scripts.test in any package.json counts as a JS test signal.
  python -m code_guardian.works_js --selftest prints "N checks, N passed", N >= 15.
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
FIXTURES = HERE / "fixtures"
UNCHANGED_LF_MD5 = {"code_guardian/works.py": "689717efa537e72b1bc43ec258cd496e",
                    "code_guardian/scanners.py": "b7012b49f8b94b43c90246aa630c4773"}
FAILS_TO_LOAD = "file does not tokenise: it cannot be loaded"


def _w():
    from code_guardian import works_js
    return works_js


def project(root):
    from code_guardian import walk
    root = Path(root)
    inv = walk.walk(str(root))
    files = sorted(inv["python"] + inv["manifests"] + inv["other"])
    p = {"root": str(root), "python": list(inv["python"]), "files": files, "trees": {}, "texts": {}, "broken": {}}
    p.update(_w().load(str(root), files))
    return p


def got(root):
    out = set()
    for f in _w().check(project(root)):
        assert f["code"] != "check.crashed", f
        out.add((f["code"], f["level"], f["node"]))
    return out


def codes(root):
    return sorted((c, lv) for c, lv, _ in got(root))


def make(tmp_path, files, name="proj"):
    root = tmp_path / name
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text if isinstance(text, str) else json.dumps(text, indent=2), encoding="utf-8")
    return root


def copy_fixture(tmp_path, name):
    dest = tmp_path / name
    shutil.copytree(FIXTURES / name, dest)
    return dest


# ---- the fixtures ------------------------------------------------------------------------------------------------------

JS_BROKEN = {
    ("works.entry_missing", "FAIL", "package.json:5"),
    ("works.import_unresolved", "WARN", "src/index.ts:1"),
    ("works.relative_missing", "FAIL", "src/index.ts:2"),
    ("works.syntax", "FAIL", "src/half.js:2"),
    ("works.tests_missing", "WARN", "."),
}


def test_js_broken_pinned():
    assert got(FIXTURES / "js_broken") == JS_BROKEN
    syntax = [f for f in _w().check(project(FIXTURES / "js_broken")) if f["code"] == "works.syntax"]
    assert syntax[0]["summary"] == FAILS_TO_LOAD


def test_js_clean_has_no_works_finding():
    assert got(FIXTURES / "js_clean") == set()


def test_js_risky_and_jsx_torture():
    assert got(FIXTURES / "js_risky") == {("works.tests_missing", "WARN", ".")}
    assert got(FIXTURES / "jsx_torture") == {("works.import_unresolved", "WARN", "App.jsx:1"),
                                             ("works.tests_missing", "WARN", ".")}


def test_build_script_turns_the_built_output_fail_into_info(tmp_path):
    root = copy_fixture(tmp_path, "js_broken")
    pkg = json.loads((root / "package.json").read_text(encoding="utf-8"))
    pkg["scripts"] = {"build": "tsc"}
    (root / "package.json").write_text(json.dumps(pkg, indent=2), encoding="utf-8")
    g = got(root)
    assert ("works.entry_missing", "INFO") in {(c, lv) for c, lv, _ in g}
    assert not [x for x in g if x[0] == "works.entry_missing" and x[1] == "FAIL"]
    assert ("works.relative_missing", "FAIL", "src/index.ts:2") in g
    assert ("works.syntax", "FAIL", "src/half.js:2") in g


def test_tsconfig_paths_turn_the_warn_into_one_info_per_file(tmp_path):
    root = copy_fixture(tmp_path, "js_broken")
    (root / "tsconfig.json").write_text('{\n  // aliases\n  "compilerOptions": {"baseUrl": ".", "paths": '
                                        '{"@/*": ["src/*"]},},\n}\n', encoding="utf-8")
    (root / "src" / "index.ts").write_text("import leftPad from 'left-pad';\nimport chalk from 'chalk';\n"
                                           "import { helper } from './util';\n", encoding="utf-8")
    g = got(root)
    unresolved = [x for x in g if x[0] == "works.import_unresolved"]
    assert unresolved == [("works.import_unresolved", "INFO", "src/index.ts:1")], unresolved


# ---- imports -----------------------------------------------------------------------------------------------------------

def test_builtins_scopes_subpaths_and_schemes(tmp_path):
    root = make(tmp_path, {
        "package.json": {"name": "p", "version": "1.0.0", "scripts": {"test": "node --test"},
                         "dependencies": {"lodash": "4.17.21", "@scope/pkg": "1.0.0"},
                         "devDependencies": {"vitest": "1.0.0"}},
        "src/a.js": ("import fs from 'fs';\nimport path from 'node:path';\nconst t = require('node:test');\n"
                     "import fp from 'lodash/fp';\nimport x from '@scope/pkg/sub';\nimport v from 'vitest';\n"
                     "import i from '#internal/x';\nimport T from '@types/node';\n"
                     "import u from \"https://example.org/x.js\";\nconst d = import(\"data:text/javascript,1\");\n"
                     "import j from 'jsr:@std/path';\nimport n from 'npm:left-pad';\n"),
    })
    g = got(root)
    assert {(c, lv) for c, lv, _ in g} == {("works.import_unresolved", "INFO")}, g
    assert sorted(int(n.rsplit(":", 1)[1]) for _, _, n in g) == [9, 10, 11, 12]


def test_bare_import_forms_warn(tmp_path):
    root = make(tmp_path, {
        "package.json": {"name": "p", "version": "1.0.0", "scripts": {"test": "node --test"}},
        "src/a.js": ("import a from 'pkg-a';\nconst b = require('pkg-b');\nconst c = import('pkg-c');\n"
                     "export { d } from 'pkg-d';\nimport e from '@scope/pkg-e/deep';\n"),
    })
    assert got(root) == {("works.import_unresolved", "WARN", "src/a.js:%d" % n) for n in range(1, 6)}


def test_nearest_package_json_and_workspaces(tmp_path):
    root = make(tmp_path, {
        "package.json": {"name": "mono", "private": True, "workspaces": ["packages/*"],
                         "scripts": {"test": "node --test"}},
        "packages/a/package.json": {"name": "@demo/a", "version": "1.0.0", "dependencies": {"lodash": "4.17.21"}},
        "packages/a/index.js": "const _ = require('lodash');\nmodule.exports = {};\n",
        "packages/b/package.json": {"name": "@demo/b", "version": "1.0.0"},
        "packages/b/index.js": "const a = require('@demo/a');\nconst x = require('not-listed');\n"
                               "const y = require('also-not-listed');\n",
    })
    assert got(root) == {("works.import_unresolved", "INFO", "packages/b/index.js:2")}


# ---- relative specs ----------------------------------------------------------------------------------------------------

def test_relative_resolution(tmp_path):
    root = make(tmp_path, {
        "package.json": {"name": "p", "version": "1.0.0", "scripts": {"test": "node --test"}},
        "src/a.ts": "export const a = 1;\n",
        "src/b.ts": "export const b = 1;\n",
        "src/dir/index.tsx": "export const d = 1;\n",
        "src/pkgdir/package.json": {"name": "inner", "main": "x.js"},
        "src/pkgdir/x.js": "module.exports = 1;\n",
        "src/data.json": "{}\n",
        "src/main.ts": ("import { a } from './a';\nimport { b } from './b.js';\nimport { d } from './dir';\n"
                        "import p from './pkgdir';\nimport data from './data.json';\nimport g from './gone';\n"
                        "import h from '../nowhere/h';\n"),
    })
    assert got(root) == {("works.relative_missing", "FAIL", "src/main.ts:6"),
                         ("works.relative_missing", "FAIL", "src/main.ts:7")}


def test_relative_built_output_needs_the_build_script(tmp_path):
    files = {"src/main.js": "const lib = require('../dist/lib');\n"}
    no_build = make(tmp_path, dict(files, **{"package.json": {"name": "p", "version": "1.0.0",
                                                              "scripts": {"test": "node --test"}}}), "nobuild")
    assert got(no_build) == {("works.relative_missing", "FAIL", "src/main.js:1")}
    built = make(tmp_path, dict(files, **{"package.json": {"name": "p", "version": "1.0.0",
                                                           "scripts": {"test": "node --test", "build": "tsc"}}}),
                 "built")
    assert got(built) == {("works.relative_missing", "INFO", "src/main.js:1")}


# ---- entry points ------------------------------------------------------------------------------------------------------

def test_entry_points(tmp_path):
    root = make(tmp_path, {
        "package.json": {"name": "p", "version": "1.0.0", "main": "index.js", "module": "esm/index.mjs",
                         "bin": {"tool": "bin/tool.js", "ok": "index.js"},
                         "exports": {".": {"import": "./esm/index.mjs", "require": "./index.js"},
                                     "./util": {"node": {"default": "./lib/util.cjs"}}},
                         "types": "index.d.ts", "scripts": {"test": "node --test"}},
        "index.js": "module.exports = 1;\n",
    })
    assert codes(root) == sorted([("works.entry_missing", "FAIL")] * 4 + [("works.entry_missing", "INFO")])
    assert all(n.startswith("package.json:") for _, _, n in got(root))


# ---- syntax ------------------------------------------------------------------------------------------------------------

def test_stray_backtick_is_jsx_only(tmp_path):
    text = (FIXTURES / "jsx_torture" / "Quote.jsx").read_text(encoding="utf-8")
    pkg = {"name": "p", "version": "1.0.0", "scripts": {"test": "node --test"}}
    jsx = make(tmp_path, {"package.json": pkg, "Quote.jsx": text}, "jsx")
    assert not [x for x in got(jsx) if x[0] == "works.syntax"]
    ts = make(tmp_path, {"package.json": pkg, "Quote.ts": text}, "ts")
    assert [x for x in got(ts) if x[0] == "works.syntax"] == [("works.syntax", "FAIL", "Quote.ts:4")]


def test_block_comment_brackets_and_strings(tmp_path):
    pkg = {"name": "p", "version": "1.0.0", "scripts": {"test": "node --test"}}
    root = make(tmp_path, {
        "package.json": pkg,
        "a.jsx": "export const A = () => <p>hi</p>;\n/* never closed\n",
        "b.js": "function f() { return [1, 2;\n",
        "c.js": "const s = 'unterminated;\nconst t = 1;\n",
    })
    assert got(root) == {("works.syntax", "FAIL", "a.jsx:2"), ("works.syntax", "INFO", "b.js:1")}


def test_tests_signal(tmp_path):
    base = {"package.json": {"name": "p", "version": "1.0.0",
                             "scripts": {"test": "echo \"Error: no test specified\" && exit 1"}},
            "index.js": "module.exports = 1;\n"}
    assert got(make(tmp_path, base, "none")) == {("works.tests_missing", "WARN", ".")}
    for name, extra in (("spec", {"lib/a.spec.ts": "export {};\n"}), ("dunder", {"__tests__/a.js": "1;\n"}),
                        ("e2e", {"e2e/a.js": "1;\n"}), ("pytest", {"tests/test_a.py": "def test_a():\n    assert 1\n"})):
        assert got(make(tmp_path, dict(base, **extra), name)) == set(), name
    script = dict(base, **{"package.json": {"name": "p", "version": "1.0.0", "scripts": {"test": "vitest"}}})
    assert got(make(tmp_path, script, "script")) == set()
    python = dict(base, **{"app.py": "x = 1\n"})
    assert got(make(tmp_path, python, "python")) == set()


def test_broken_tsconfig_is_noted_not_raised(tmp_path):
    root = make(tmp_path, {"package.json": {"name": "p", "version": "1.0.0", "scripts": {"test": "node --test"}},
                           "tsconfig.json": "{ this is not json",
                           "a.ts": "import x from 'nope';\n"})
    p = project(root)
    assert "tsconfig.json" not in p["tsconfig"] and any("tsconfig.json" in n for n in p["notes"])
    assert {(f["code"], f["level"], f["node"]) for f in _w().check(p)} == {
        ("works.import_unresolved", "WARN", "a.ts:1")}


# ---- untouched modules, selftest ---------------------------------------------------------------------------------------

def test_python_modules_unchanged():
    for rel, want in UNCHANGED_LF_MD5.items():
        data = (ROOT / rel).read_bytes().replace(b"\r\n", b"\n")
        assert hashlib.md5(data).hexdigest() == want, rel


def test_selftest_count():
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT)
    p = subprocess.run([sys.executable, "-m", "code_guardian.works_js", "--selftest"], cwd=str(ROOT), env=env,
                       capture_output=True, text=True, encoding="utf-8", timeout=300)
    m = re.search(r"(\d+) checks, (\d+) passed", p.stdout)
    assert p.returncode == 0 and m, (p.returncode, p.stdout[-500:], p.stderr[-500:])
    assert int(m.group(1)) == int(m.group(2)) >= 15, m.group(0)
