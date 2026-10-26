"""works_js.py beyond the overseer's acceptance file: loading, the loose JSON reader, resolution corners, entry lines."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

from code_guardian import works_js
from code_guardian.works_js import check, load

ROOT = Path(__file__).resolve().parent.parent
PKG = {"name": "p", "version": "1.0.0", "scripts": {"test": "node --test"}}


def build(tmp_path, files, name="proj"):
    root = tmp_path / name
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(text, bytes):
            p.write_bytes(text)
        else:
            p.write_text(text if isinstance(text, str) else json.dumps(text, indent=2), encoding="utf-8")
    return root


def project(root, files=None, python=()):
    names = sorted(files if files is not None else
                   (p.relative_to(root).as_posix() for p in Path(root).rglob("*") if p.is_file()))
    p = {"root": str(root), "python": list(python), "files": names}
    p.update(load(str(root), names))
    return p


def got(root, **kw):
    return sorted((f["code"], f["level"], f["node"]) for f in check(project(root, **kw)))


# ---- load --------------------------------------------------------------------------------------------------------------

def test_load_defaults_and_explicit_list(tmp_path):
    root = build(tmp_path, {"a.js": "1;\n", "b.ts": "1;\n", "c.py": "x = 1\n", "d.md": "x\n", "package.json": PKG})
    files = ["a.js", "b.ts", "c.py", "d.md", "package.json"]
    loaded = load(str(root), files)
    assert loaded["javascript"] == ["a.js", "b.ts"] and set(loaded["js_tokens"]) == {"a.js", "b.ts"}
    assert loaded["package_json"] == {"package.json": PKG} and loaded["tsconfig"] == {} and loaded["notes"] == []
    assert load(str(root), files, javascript=["b.ts"])["javascript"] == ["b.ts"]


def test_load_names_unreadable_and_unparseable_files(tmp_path):
    root = build(tmp_path, {"package.json": "[1]", "sub/jsconfig.json": "{,", "tsconfig.json": "{}"})
    loaded = load(str(root), ["package.json", "sub/jsconfig.json", "tsconfig.json", "gone.js"])
    assert loaded["package_json"] == {} and set(loaded["tsconfig"]) == {"tsconfig.json"}
    assert loaded["javascript"] == [] and len(loaded["notes"]) == 3
    assert any("sub/jsconfig.json" in n for n in loaded["notes"]) and any("gone.js" in n for n in loaded["notes"])


def test_loose_json_keeps_strings_and_lines():
    text = '﻿{\n  // comment\n  "url": "http-ish // not a comment", /* a\n b */ "list": [1, 2,],\n  "k": {"x": 1,},\n}\n'
    assert works_js._parse(text) == ({"url": "http-ish // not a comment", "list": [1, 2], "k": {"x": 1}}, None)
    lines = works_js._key_lines(works_js._loose(text))
    assert lines[("url",)] == 3 and lines[("list",)] == 4 and lines[("list", 1)] == 4 and lines[("k", "x")] == 5


def test_loose_json_rejections():
    assert works_js._parse("{ nope")[0] is None
    assert works_js._parse("[]")[1] == "not a JSON object"
    assert works_js._parse('{"a": ' + "[" * 100000)[0] is None


# ---- imports -----------------------------------------------------------------------------------------------------------

def test_unscoped_scoped_and_self_names(tmp_path):
    root = build(tmp_path, {
        "package.json": dict(PKG, name="me", devDependencies={"@types/lodash": "1", "@types/scope__pkg": "1"},
                             peerDependencies={"react": "*"}, optionalDependencies={"fsevents": "*"}),
        "a.ts": ("import _ from 'lodash';\nimport p from '@scope/pkg';\nimport r from 'react/jsx-runtime';\n"
                 "import f from 'fsevents';\nimport m from 'me/sub';\nimport s from '@scope';\nimport a from '@/alias';\n"
                 "import w from '~/x';\nimport l from '!!raw!./x';\nimport k from 'node:sqlite';\nimport e from 'test';\n"),
    })
    assert got(root) == [("works.import_unresolved", "WARN", "a.ts:11")]


def test_no_package_json_means_nothing_is_declared(tmp_path):
    root = build(tmp_path, {"a.js": "require('lodash');\nrequire('fs');\n", "a.test.js": "1;\n"})
    assert got(root) == [("works.import_unresolved", "WARN", "a.js:1")]


def test_alias_applies_below_the_tsconfig_only(tmp_path):
    root = build(tmp_path, {
        "package.json": PKG,
        "web/tsconfig.json": '{"compilerOptions": {"baseUrl": "src"}}',
        "web/a.ts": "import x from 'one';\nimport y from 'two';\n",
        "b.ts": "import z from 'three';\n",
    })
    assert got(root) == [("works.import_unresolved", "INFO", "web/a.ts:1"), ("works.import_unresolved", "WARN", "b.ts:1")]


def test_workspaces_object_form_and_negation(tmp_path):
    root = build(tmp_path, {
        "package.json": dict(PKG, workspaces={"packages": ["libs/*", "!libs/skip"]}),
        "libs/a/package.json": {"name": "lib-a"}, "libs/a/i.js": "require('lib-a');\nrequire('lib-skip');\n",
        "libs/skip/package.json": {"name": "lib-skip"},
    })
    assert got(root) == [("works.import_unresolved", "INFO", "libs/a/i.js:2")]


def test_each_scheme_is_one_info_and_unknown_schemes_are_skipped(tmp_path):
    root = build(tmp_path, {
        "package.json": PKG,
        "a.js": "import a from 'http://x.test/a.js';\nimport b from 'blob:abc';\nimport c from 'virtual:thing';\n"
                "import d from 'bun:test';\nimport e from 'deno:std';\nimport f from 'file:///x.js';\n",
    })
    assert got(root) == [("works.import_unresolved", "INFO", "a.js:1"), ("works.import_unresolved", "INFO", "a.js:2")]


# ---- relative specs ----------------------------------------------------------------------------------------------------

def test_ts_conventions_query_strings_and_disk_only_files(tmp_path):
    root = build(tmp_path, {
        "package.json": PKG,
        "src/a.mts": "export {};\n", "src/b.cts": "export {};\n", "src/c.d.ts": "export {};\n", "src/d.tsx": "export {};\n",
        "src/index.js": "1;\n", "src/logo.png": b"\x89PNG\0\0",
        "src/main.ts": ("import './a.mjs';\nimport './b.cjs';\nimport './c.js';\nimport './d.jsx';\n"
                        "import './logo.png';\nimport './style.css?inline';\nimport '..';\nimport '.';\nimport './';\n"),
    })
    files = [p for p in project(root)["files"] if p != "src/logo.png"]
    assert got(root, files=files) == [("works.relative_missing", "FAIL", "src/main.ts:6")]


def test_extensionless_spec_finds_a_declaration_file(tmp_path):
    root = build(tmp_path, {"package.json": PKG, "types/hooks.d.ts": "export {};\n",
                            "src/main.ts": "import type { H } from '../types/hooks';\n"})
    assert got(root) == []


def test_folder_spec_finds_an_index_declaration_file(tmp_path):
    root = build(tmp_path, {"package.json": PKG, "types/index.d.ts": "export {};\n",
                            "src/main.ts": "import type { T } from '../types';\n"})
    assert got(root) == []


def test_declaration_lookup_still_reports_a_missing_spec(tmp_path):
    root = build(tmp_path, {"package.json": PKG, "types/hooks.d.ts": "export {};\n",
                            "src/main.ts": "import type { G } from '../types/gone';\n"})
    assert got(root) == [("works.relative_missing", "FAIL", "src/main.ts:1")]


def test_outside_the_root_is_not_judged(tmp_path):
    root = build(tmp_path, {"package.json": PKG, "a.js": "require('../shared/x');\nrequire('../../y');\n"})
    assert got(root) == []


def test_build_output_is_relative_to_the_owning_package(tmp_path):
    root = build(tmp_path, {
        "package.json": dict(PKG, scripts={"test": "t", "build": "tsc"}),
        "pkg/package.json": PKG,
        "pkg/a.js": "require('./dist/x');\n",
        "top.js": "require('./out/x');\nrequire('./src/x');\n",
        "other/b.js": "require('../pkg/lib/z');\n",
    })
    assert {n: lv for _, lv, n in got(root)} == {"other/b.js:1": "FAIL", "pkg/a.js:1": "FAIL", "top.js:1": "INFO",
                                                 "top.js:2": "FAIL"}


# ---- entry points ------------------------------------------------------------------------------------------------------

def test_entry_lines_and_forms(tmp_path):
    text = ('{\n  "name": "p",\n  "bin": "cli/run.js",\n  "browser": "web.js",\n  "typings": "t.d.ts",\n'
            '  "exports": {\n    "./a": ["./a1.js", {"types": "./a.d.ts", "default": "./a2.js"}],\n'
            '    "./glob/*": "./src/*.js",\n    "./off": null\n  },\n  "scripts": {"test": "t"}\n}\n')
    root = build(tmp_path, {"sub/package.json": text, "sub/a1.js": "1;\n"})
    levels = sorted((n, lv) for _, lv, n in got(root))
    assert levels == [("sub/package.json:3", "FAIL"), ("sub/package.json:4", "FAIL"), ("sub/package.json:5", "INFO"),
                      ("sub/package.json:7", "FAIL"), ("sub/package.json:7", "INFO")]


def test_entry_resolves_like_a_module_and_from_the_manifest_folder(tmp_path):
    root = build(tmp_path, {"p/package.json": dict(PKG, main="lib", module="./esm", bin="bin/x"),
                            "p/lib/index.js": "1;\n", "p/esm.mjs": "1;\n", "p/bin/x": "#!/usr/bin/env node\n"})
    assert got(root) == []


def test_entry_built_output_uses_the_manifest_folder(tmp_path):
    root = build(tmp_path, {"p/package.json": dict(PKG, main="dist/i.js", scripts={"test": "t", "build": "tsc"})})
    assert got(root) == [("works.entry_missing", "INFO", "p/package.json:8")]


# ---- syntax and tests --------------------------------------------------------------------------------------------------

def test_extra_closing_brackets_and_template_text(tmp_path):
    root = build(tmp_path, {"package.json": PKG, "a.js": "const s = `(${[1].map((x) => x)}`;\n}\n", "b.js": "f(1));\n"})
    assert got(root) == [("works.syntax", "INFO", "a.js:2"), ("works.syntax", "INFO", "b.js:1")]


@pytest.mark.parametrize("script,fires", [("echo \"Error: no test specified\" && exit 1", True), ("", True), ("jest", False)])
def test_test_script_signal(tmp_path, script, fires):
    root = build(tmp_path, {"package.json": {"name": "p", "scripts": {"test": script}}, "a.js": "1;\n"})
    assert (got(root) == [("works.tests_missing", "WARN", ".")]) is fires


def test_a_test_script_in_a_nested_package_counts(tmp_path):
    root = build(tmp_path, {"package.json": {"name": "p"}, "pkg/package.json": PKG, "a.js": "1;\n"})
    assert got(root) == []


def test_no_js_files_no_finding(tmp_path):
    root = build(tmp_path, {"package.json": {"name": "p"}, "README.md": "x\n"})
    assert got(root) == []


def test_a_crashing_check_is_one_warn(tmp_path, monkeypatch):
    root = build(tmp_path, {"package.json": PKG, "a.js": "require('x');\n"})
    monkeypatch.setattr(works_js, "_syntax", lambda rel, tokens: 1 / 0)
    assert got(root) == [("check.crashed", "WARN", "a.js"), ("works.import_unresolved", "WARN", "a.js:1")]


def test_findings_are_works_shaped_and_deterministic(tmp_path):
    root = build(tmp_path, {"package.json": {"name": "p", "main": "x.js"}, "a.js": "require('nope');\nrequire('./gone');\n"})
    first, second = check(project(root)), check(project(root))
    assert first == second
    assert {f["code"] for f in first} == {"works.import_unresolved", "works.relative_missing", "works.entry_missing",
                                          "works.tests_missing"}
    assert all(f["severity"] == "partial" and f["confidence"] == "LIKELY" for f in first)


def test_not_checked_and_selftest():
    assert works_js.NOT_CHECKED == ("works.test_no_assert", "works.todo_stub", "works.commented_code",
                                    "works.dead_flag", "orphan.*")
    r = subprocess.run([sys.executable, "-m", "code_guardian.works_js", "--selftest"], cwd=str(ROOT),
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 0 and "0 failed" in r.stdout, r.stdout + r.stderr
    assert subprocess.run([sys.executable, "-m", "code_guardian.works_js"], cwd=str(ROOT), capture_output=True,
                          text=True, timeout=60).returncode == 2
