"""P81 S1 acceptance -- code_guardian/jsts.py, the JavaScript / TypeScript lexer and its shapes (plan P81 C1).

Written by the overseer on main (ddea508) BEFORE the build session. The build session adds this file to the PR
byte-for-byte and never edits it. Pure ASCII on purpose; no key-shaped value anywhere.

What the build session must provide (C1 verbatim, plus the overseer's precisions marked P):
  tokenize(text, flavour) -> list[Token]; Token = namedtuple("Token", "kind value line col flags");
    kinds name keyword number string template regex punct comment error; error.value in {string, template, comment,
    regex}; flags "" or "relexed". flavour in {js, jsx, ts, tsx}; .mjs/.cjs -> js; a "js" text is lexed with the JSX
    rules when JSX_HINT (module constant, pattern r"</[A-Za-z>]|/>") matches it.
  P1 The EOF error token of an unterminated template, and the re-lex point in a JSX flavour, is the backtick that opened
     the OUTERMOST unterminated template.
  P2 Shapes take the full token list from tokenize and skip comments themselves.
     calls -> [Call(callee, args, line, new)] in source order of the callee; args is a list of token lists.
     imports -> [Import(spec, line, kind)]; assigns(tokens, member) -> [Assign(target, value, line)], value the tokens
     after "=" up to the end of the statement; props(arg) -> {key: value_tokens}; literal(tokens) returns the text
     WITHOUT its quotes / backticks.
  P3 is_source(tokens, roots=None): when roots is None it uses handler_roots(tokens) of the tokens it was given.
  P4 tests/golden/jsts_tokens.json: {fixture-relative path: sha256 hex of json.dumps(tokenize(text, flavour))} for
     every JS/TS file under the four JS fixtures, written by the build session from its own lexer. It is the
     regression lock for S2-S6 (no later section may change a token silently); the plan's "value recorded in the
     acceptance" would need the overseer to own a second lexer whose every column and punct grouping the build must
     copy. Correctness is pinned by the contract values below, not by that file.
  P5 js_broken/src/half.js is the planted unterminated template (S3's works.syntax FAIL): it ends in exactly one
     error("template"). Every other fixture file has no EOF error (the plan's "0 EOF errors" read with that one file
     excepted, as S3 requires).
  python -m code_guardian.jsts --selftest prints "N checks, N passed", N >= 25.

The pinned-repo threshold test runs only when CG_CALIB_DIR names the folder of cached clones (the overseer's run);
it skips everywhere else.
"""
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
FIXTURES = HERE / "fixtures"
JS_FIXTURES = ("js_broken", "js_clean", "js_risky", "jsx_torture")
TOKENS_GOLDEN = HERE / "golden" / "jsts_tokens.json"
FLAVOUR = {".js": "js", ".mjs": "js", ".cjs": "js", ".jsx": "jsx", ".ts": "ts", ".tsx": "tsx"}
EOF_KINDS = {"template", "comment", "regex"}


def _j():
    from code_guardian import jsts
    return jsts


def T(text, flavour="js"):
    return _j().tokenize(text, flavour)


def kinds(toks, kind):
    return [t for t in toks if t.kind == kind]


def errors(toks):
    return [(t.value, t.line) for t in toks if t.kind == "error"]


def js_files():
    out = []
    for fx in JS_FIXTURES:
        for p in sorted((FIXTURES / fx).rglob("*")):
            if p.is_file() and p.suffix in FLAVOUR and "node_modules" not in p.parts:
                out.append(p)
    return out


def rel(p):
    return p.relative_to(FIXTURES).as_posix()


def lex_file(p):
    return T(p.read_bytes().decode("utf-8"), FLAVOUR[p.suffix])


# ---- the token type ---------------------------------------------------------------------------------------------------

def test_token_type_and_hint():
    jsts = _j()
    assert jsts.Token._fields == ("kind", "value", "line", "col", "flags")
    assert jsts.JSX_HINT.pattern == r"</[A-Za-z>]|/>"
    toks = T("var a = 1;\nvar b = 'x';\n")
    assert {t.kind for t in toks} <= {"name", "keyword", "number", "string", "template", "regex", "punct",
                                      "comment", "error"}
    assert all(t.flags == "" for t in toks)
    assert [t.line for t in toks if t.kind == "name"] == [1, 2]


# ---- regex versus division: the twelve cases ---------------------------------------------------------------------------

REGEX_CASES = [
    ("a_div_b_div_c", "x = a / b / c;", "js", []),
    ("escaped_slash", "re = /\\//g;", "js", ["/\\//g"]),
    ("after_return", "function f(s) { return /ab+c/i.test(s); }", "js", ["/ab+c/i"]),
    ("after_paren", "y = f(a) / 2;", "js", []),
    ("after_bracket", "y = arr[0] / 2;", "js", []),
    ("after_typeof", "t = typeof /x/;", "js", ["/x/"]),
    ("ternary", "r = ok ? /a/ : /b/g;", "js", ["/a/", "/b/g"]),
    ("array", "list = [/a/, /b/];", "js", ["/a/", "/b/"]),
    ("divide_assign", "x /= 2; y = x / 3;", "js", []),
    ("after_case", "switch (s) { case /x/: break; }", "js", ["/x/"]),
    ("close_tag_jsx", "const e = <div>a</div>;", "jsx", []),
    ("a_close_b_jsx", "a </b> c", "jsx", []),
]


@pytest.mark.parametrize("text,flavour,want", [c[1:] for c in REGEX_CASES], ids=[c[0] for c in REGEX_CASES])
def test_regex_versus_division(text, flavour, want):
    toks = T(text, flavour)
    assert [t.value for t in kinds(toks, "regex")] == want
    assert not errors(toks)


def test_close_tag_is_one_punct_in_jsx():
    toks = T("const e = <p>hi</p>;\nconst i = <Icon name=\"x\" />;\n", "jsx")
    vals = [t.value for t in kinds(toks, "punct")]
    assert vals.count("</") == 1 and vals.count("/>") == 1
    assert not kinds(toks, "regex") and not errors(toks)


def test_js_with_jsx_hint_uses_jsx_rules():
    toks = T("const e = <p>a</p>;\n", "js")
    assert "</" in [t.value for t in kinds(toks, "punct")] and not kinds(toks, "regex")


def test_url_in_jsx_text_is_not_a_comment():
    toks = T("const a = <a>https://example.org</a>; eval(x);\n", "jsx")
    assert not kinds(toks, "comment")
    assert "eval" in [t.value for t in kinds(toks, "name")]
    plain = T("x = 1; // https://example.org eval(x)\n", "js")
    assert len(kinds(plain, "comment")) == 1 and "eval" not in [t.value for t in kinds(plain, "name")]


# ---- strings, templates, comments, errors -----------------------------------------------------------------------------

def test_string_resync_costs_one_token():
    toks = T("<p>Don't</p>{eval(location.hash)}\n", "jsx")
    assert errors(toks) == [("string", 1)]
    i = [k for k, t in enumerate(toks) if t.kind == "error"][0]
    assert toks[i - 1].value == "Don" and toks[i + 1].value == "t"
    names = [t.value for t in kinds(toks, "name")]
    assert "t" in names and "eval" in names and "location" in names


def test_escaped_quote_is_one_string():
    toks = T("s = 'it\\'s' + \"a\";\n")
    assert len(kinds(toks, "string")) == 2 and not errors(toks)


def test_three_deep_template_is_one_token():
    text = "`one ${`two ${`three ${x}`}`}`"
    toks = T(text)
    assert [(t.kind, t.value) for t in toks] == [("template", text)]


def test_template_braces_nest():
    text = "`a ${ {b: 1}.b } c`"
    assert [(t.kind, t.value) for t in T(text)] == [("template", text)]


def test_multiline_template_and_comment_keep_line_numbers():
    toks = T("t = `a\nb`;\n/* c\nd */ x;\n")
    assert [t.line for t in toks if t.kind == "name" and t.value == "x"] == [4]
    assert not errors(toks)


@pytest.mark.parametrize("text,flavour,want", [
    ("x = `abc\n", "ts", "template"),
    ("x = 1; /* abc\n", "js", "comment"),
    ("x = /abc", "js", "regex"),
], ids=["eof_template", "eof_comment", "eof_regex"])
def test_each_eof_error(text, flavour, want):
    toks = T(text, flavour)
    assert [e[0] for e in errors(toks)] == [want]
    assert toks[-1].kind == "error"


def test_hashbang_is_a_comment():
    toks = T("#!/usr/bin/env node\nx();\n")
    assert toks[0].kind == "comment" and toks[0].value.startswith("#!") and toks[0].line == 1
    assert [t.line for t in kinds(toks, "name")] == [2]


def test_modern_syntax_lexes_without_error():
    text = ("export const id = <T,>(v: T): T => v;\n@sealed\nclass B { #h = 10n; n = 1_000_000;"
            " t() { return this.l?.t ?? 'f'; } }\n")
    toks = T(text, "tsx")
    assert not errors(toks)
    vals = [t.value for t in toks]
    assert "?." in vals and "??" in vals
    assert "10n" in [t.value for t in kinds(toks, "number")] and "1_000_000" in [t.value for t in kinds(toks, "number")]


# ---- stray backticks in JSX --------------------------------------------------------------------------------------------

def test_stray_backtick_relexed_in_jsx_only():
    text = "<p>Press the ` key</p>\n{eval(location.hash)}\n"
    toks = T(text, "jsx")
    assert not errors(toks)
    ticks = [i for i, t in enumerate(toks) if t.kind == "punct" and t.value == "`"]
    assert len(ticks) == 1
    after = toks[ticks[0] + 1:]
    assert after and all(t.flags == "relexed" for t in after)
    assert all(t.flags == "" for t in toks[:ticks[0]])
    assert "eval" in [t.value for t in after if t.kind == "name"]
    ts = T(text, "ts")
    assert errors(ts) == [("template", 1)] and ts[-1].kind == "error"


def test_two_stray_backticks_relex_twice():
    text = "<p>a ` ${ x</p>\n<p>b ` y</p>\n{eval(z)}\n"
    toks = T(text, "jsx")
    assert not errors(toks)
    ticks = [i for i, t in enumerate(toks) if t.kind == "punct" and t.value == "`"]
    assert len(ticks) == 2
    assert all(t.flags == "relexed" for t in toks[ticks[0] + 1:])
    names = [t.value for t in kinds(toks, "name")]
    for n in ("x", "b", "y", "eval", "z"):
        assert n in names, n


# ---- the fixtures ------------------------------------------------------------------------------------------------------

def test_every_fixture_file_lexes_twice_identically_and_crlf_equal():
    files = js_files()
    assert len(files) == 10, [rel(p) for p in files]
    for p in files:
        text = p.read_bytes().decode("utf-8").replace("\r\n", "\n")
        f = FLAVOUR[p.suffix]
        a, b = T(text, f), T(text, f)
        assert a == b, rel(p)
        assert json.dumps(a) == json.dumps(b), rel(p)
        assert T(text.replace("\n", "\r\n"), f) == a, "CRLF differs: %s" % rel(p)
        assert T(text.replace("\n", "\r"), f) == a, "CR differs: %s" % rel(p)


def test_fixture_eof_errors():
    for p in js_files():
        eof = [e for e in errors(lex_file(p)) if e[0] in EOF_KINDS]
        if rel(p) == "js_broken/src/half.js":
            assert eof == [("template", 2)], eof
            assert lex_file(p)[-1].kind == "error"
        else:
            assert eof == [], (rel(p), eof)


def test_app_jsx_pins():
    toks = lex_file(FIXTURES / "jsx_torture" / "App.jsx")
    assert errors(toks) == [("string", 17), ("string", 18), ("string", 23)]
    assert sorted({t.line for t in toks if t.kind == "name" and t.value == "eval"}) == [10, 11, 22, 23, 24]
    assert any(t.kind == "string" and t.line == 25 and "eval(location.hash)" in t.value for t in toks)
    assert [t.line for t in kinds(toks, "comment")] == [4, 5]
    assert [t.line for t in kinds(toks, "regex")] == [9]
    assert [t.line for t in kinds(toks, "template")] == [7, 8]
    assert all(t.flags == "" for t in toks)
    assert not [t for t in kinds(toks, "comment") if t.line == 24]


def test_quote_jsx_pins():
    p = FIXTURES / "jsx_torture" / "Quote.jsx"
    toks = lex_file(p)
    assert not errors(toks)
    ticks = [i for i, t in enumerate(toks) if t.kind == "punct" and t.value == "`"]
    assert len(ticks) == 1 and toks[ticks[0]].line == 4
    assert all(t.flags == "relexed" for t in toks[ticks[0] + 1:])
    assert [t.line for t in toks if t.kind == "name" and t.value == "eval"] == [6]
    ts = T(p.read_bytes().decode("utf-8"), "ts")
    assert errors(ts) == [("template", 4)]


def test_util_tsx_and_bin_mjs_lex_clean():
    util = lex_file(FIXTURES / "jsx_torture" / "util.tsx")
    assert not errors(util)
    bin_ = lex_file(FIXTURES / "jsx_torture" / "bin.mjs")
    assert not errors(bin_)
    assert bin_[0].kind == "comment" and bin_[0].value.startswith("#!")
    assert [t.line for t in kinds(bin_, "comment")] == [1, 2]


def test_tokens_golden_covers_every_fixture_file_and_matches():
    assert TOKENS_GOLDEN.is_file(), "tests/golden/jsts_tokens.json is missing (P4)"
    golden = json.loads(TOKENS_GOLDEN.read_text(encoding="utf-8"))
    files = {rel(p): p for p in js_files()}
    assert sorted(golden) == sorted(files)
    for r, p in files.items():
        got = hashlib.sha256(json.dumps(lex_file(p)).encode("utf-8")).hexdigest()
        assert got == golden[r], "%s tokens changed (%s, golden %s)" % (r, got[:12], golden[r][:12])


# ---- shapes ------------------------------------------------------------------------------------------------------------

def test_calls():
    c = _j().calls(T("a.b?.c(1, f(2,3)); // g(4)\nnew Function('a', 'return a');\nif (x) { obj.eval(y); }\n"))
    got = [(k.callee, len(k.args), k.line, k.new) for k in c]
    assert got == [("a.b?.c", 2, 1, False), ("f", 2, 1, False), ("Function", 2, 2, True), ("obj.eval", 1, 3, False)]
    assert [t.value for t in c[1].args[1]] == ["3"]
    assert _j().calls(T("foo();\n"))[0].args == []


def test_imports():
    text = ("import a from 'x';\nimport { b } from \"y\";\nimport * as c from 'z';\nimport 'side';\n"
            "export { d } from 'w';\nexport * from 'v';\nconst e = require('u');\nconst f = await import('t');\n"
            "const g = require(name);\nconst h = import(name);\n// import n from 'no'\nconst s = \"require('no')\";\n"
            "export const k = 1;\n")
    got = [(i.spec, i.line, i.kind) for i in _j().imports(T(text))]
    assert got == [("x", 1, "import"), ("y", 2, "import"), ("z", 3, "import"), ("side", 4, "import"),
                   ("w", 5, "export_from"), ("v", 6, "export_from"), ("u", 7, "require"), ("t", 8, "dynamic"),
                   (None, 9, "computed"), (None, 10, "computed")]
    ts = _j().imports(T("import type { T } from 'q';\n", "ts"))
    assert [(i.spec, i.kind) for i in ts] == [("q", "import")]


def test_assigns():
    text = "el.innerHTML = post.body;\nel['innerHTML'] = x;\na.innerHTMLx = 1;\nif (el.innerHTML == z) {}\n"
    got = _j().assigns(T(text), "innerHTML")
    assert [a.line for a in got] == [1, 2]
    assert got[0].target == "el.innerHTML"
    assert "innerHTML" in got[1].target
    assert [t.value for t in got[0].value if t.kind == "name"] == ["post", "body"]
    assert all(t.value != ";" for t in got[0].value)


def test_props_and_literal():
    jsts = _j()
    call = jsts.calls(T("spawn('ls', [], { shell: true, \"cwd\": dir, ['env']: e, nested: {a: 1}, ...rest });\n"))[0]
    p = jsts.props(call.args[2])
    assert set(p) == {"shell", "cwd", "env", "nested"}
    assert [t.value for t in p["shell"]] == ["true"]
    assert jsts.literal(call.args[0]) == "ls"
    assert jsts.literal(T("`ls -la`")) == "ls -la"
    assert jsts.literal(T("`ls ${x}`")) is None
    assert jsts.literal(T("x")) is None
    assert jsts.literal(T("'a' + 'b'")) is None


SOURCES = [
    ("q.query.x", True), ("req.body.x", True), ("ctx.request.body.x", True), ("this.query.limit", True),
    ("req.user.name", True), ("document.body.innerHTML", False), ("post.body", False), ("response.body", False),
    ("queryClient.fetch(x)", False), ("config.bodyLimit", False), ("'query'", False), ("q.body.x", False),
    ("process.env.HOME", True), ("process.argv[2]", True), ("location.hash", True), ("document.cookie", True),
    ("window.name", True), ("event.data", True), ("message.data", True), ("searchParams.get('a')", True),
    ("prompt('x')", True), ("requestId.value", False), ("a.params.id", True), ("a.headers.h", True),
    ("a.cookies.c", True),
]


@pytest.mark.parametrize("text,want", SOURCES, ids=["src_%02d" % i for i in range(len(SOURCES))])
def test_is_source_contract_values(text, want):
    assert _j().is_source(T(text)) is want


@pytest.mark.parametrize("text,want", [
    ("app.post('/', (q, r) => { eval(q.body.x); });", True),
    ("router.get('/x', async (q, r) => { use(q.body.y); });", True),
    ("app.use(function (q, r) { use(q.body.z); });", True),
    ("app.post('/', (q, r) => { use(r.body.x); });", False),
    ("const v = q.body.x;", False),
], ids=["arrow", "async_arrow", "function", "second_param", "outside"])
def test_handler_root_body_rule(text, want):
    assert _j().is_source(T(text)) is want


def test_handler_roots_span():
    toks = T("app.post('/', (q, r) => { eval(q.body.x); });\nq.body.y;\n")
    roots = _j().handler_roots(toks)
    assert [r[0] for r in roots] == ["q"]
    inner = [i for i, t in enumerate(toks) if t.value == "q" and t.line == 1][-1]
    outer = [i for i, t in enumerate(toks) if t.value == "q" and t.line == 2][0]
    assert roots[0][1] <= inner <= roots[0][2] < outer


# ---- selftest ----------------------------------------------------------------------------------------------------------

def test_selftest_count():
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT)
    p = subprocess.run([sys.executable, "-m", "code_guardian.jsts", "--selftest"], cwd=str(ROOT), env=env,
                       capture_output=True, text=True, encoding="utf-8", timeout=300)
    m = re.search(r"(\d+) checks, (\d+) passed", p.stdout)
    assert p.returncode == 0 and m, (p.returncode, p.stdout[-500:], p.stderr[-500:])
    assert int(m.group(1)) == int(m.group(2)) >= 25, m.group(0)


# ---- the pinned repos (overseer's run only) ----------------------------------------------------------------------------

CALIB = os.environ.get("CG_CALIB_DIR", "")


@pytest.mark.skipif(not CALIB or not Path(CALIB).is_dir(), reason="CG_CALIB_DIR not set (overseer's run only)")
def test_pinned_repos_eof_error_rate():
    report = []
    for repo in sorted(p for p in Path(CALIB).iterdir() if p.is_dir()):
        groups = {"js_ts": [0, 0], "jsx_tsx": [0, 0]}
        for p in repo.rglob("*"):
            if not p.is_file() or p.suffix not in FLAVOUR or "node_modules" in p.parts or ".git" in p.parts:
                continue
            g = "jsx_tsx" if p.suffix in (".jsx", ".tsx") else "js_ts"
            groups[g][0] += 1
            try:
                text = p.read_bytes().decode("utf-8")
            except UnicodeDecodeError:
                continue
            if any(t.kind == "error" and t.value in EOF_KINDS for t in T(text, FLAVOUR[p.suffix])):
                groups[g][1] += 1
        for g, (n, bad) in groups.items():
            report.append((repo.name, g, n, bad))
    print("pinned repos (repo, group, files, files with an EOF error): %s" % report)
    over = [r for r in report if r[2] and r[3] * 100 > r[2]]
    assert not over, over
