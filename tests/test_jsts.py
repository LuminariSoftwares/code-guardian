"""code_guardian.jsts beyond the overseer's acceptance file: columns, speed, the shapes' edges, and the token golden.

    python tests/test_jsts.py --record     rewrite tests/golden/jsts_tokens.json from the current lexer
"""
import hashlib
import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
FIXTURES = HERE / "fixtures"
GOLDEN = HERE / "golden" / "jsts_tokens.json"
FLAVOUR = {".js": "js", ".mjs": "js", ".cjs": "js", ".jsx": "jsx", ".ts": "ts", ".tsx": "tsx"}

sys.path.insert(0, str(ROOT))
from code_guardian import jsts  # noqa: E402


def T(text, flavour="js"):
    return jsts.tokenize(text, flavour)


def fixture_files():
    out = []
    for fx in ("js_broken", "js_clean", "js_risky", "jsx_torture"):
        for p in sorted((FIXTURES / fx).rglob("*")):
            if p.is_file() and p.suffix in FLAVOUR and "node_modules" not in p.parts:
                out.append(p)
    return out


def token_hashes():
    return {p.relative_to(FIXTURES).as_posix():
            hashlib.sha256(json.dumps(T(p.read_bytes().decode("utf-8"), FLAVOUR[p.suffix])).encode("utf-8")).hexdigest()
            for p in fixture_files()}


def record():
    GOLDEN.write_text(json.dumps(token_hashes(), indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print("wrote %s" % GOLDEN.relative_to(ROOT).as_posix())


def test_columns_are_one_based_and_survive_multiline_tokens():
    toks = T("ab = `x\ny`; cd\n  ef\n", "js")
    got = [(t.value, t.line, t.col) for t in toks if t.kind in ("name", "template")]
    assert got == [("ab", 1, 1), ("`x\ny`", 1, 6), ("cd", 2, 5), ("ef", 3, 3)]


def test_a_three_thousand_character_line_lexes_fast():
    text = "var a=" + "+".join("f(%d)/2" % i for i in range(400)) + ";" + "x" * 3000 + "\n" + "y();\n"
    t0 = time.time()
    toks = T(text, "js")
    assert time.time() - t0 < 2
    assert [t.line for t in toks if t.value == "y"] == [2]


def test_unclosed_regex_mid_file_is_a_division_and_lexing_goes_on():
    toks = T("x = /abc\ny = 1;\n", "js")
    assert not [t for t in toks if t.kind == "error"]
    assert [t.value for t in toks if t.kind == "name"] == ["x", "abc", "y"]


def test_keyword_after_a_dot_is_a_name():
    toks = T("a.delete(b); a?.in(c); of = 1;", "js")
    assert [t.kind for t in toks if t.value in ("delete", "in")] == ["name", "name"]
    assert [t.kind for t in toks if t.value == "of"] == ["keyword"]


def test_regex_inside_a_template_expression_may_hold_a_quote():
    text = "const r = `'${input.replace(/'/g, `'x'`)}'`;\nok();\n"
    toks = T(text, "js")
    assert [t.kind for t in toks if t.kind in ("template", "error")] == ["template"]
    assert [t.line for t in toks if t.value == "ok"] == [2]


def test_calls_edges():
    c = jsts.calls(T("function exec(cmd) {}\nclass A { run(x) { this.exec(x); } }\nrequire('child_process').exec(a)(b);\n"))
    assert [(k.callee, k.line) for k in c] == [("this.exec", 2), ("require", 3), ("exec", 3)]
    assert [k.callee for k in jsts.calls(T("a?.(x); new a.B(y);"))] == ["a", "a.B"]


def test_assigns_stops_at_the_statement_without_a_semicolon():
    got = jsts.assigns(T("el.innerHTML = a +\n  b\nnext(el)\n"), "innerHTML")
    assert [t.value for t in got[0].value] == ["a", "+", "b"]
    got = jsts.assigns(T("document.getElementById('o').innerHTML = x, y;"), "innerHTML")
    assert got[0].target == "document.getElementById('o').innerHTML" and [t.value for t in got[0].value] == ["x"]


def test_imports_ignore_non_import_exports():
    got = jsts.imports(T("export default function f() {}\nexport const a = 1;\nimport x, { y as z } from './m.js';\n"
                         "export * as ns from \"n\";\nmodule.require(q);\nconst w = require(`pkg`);\n"))
    assert [(i.spec, i.kind) for i in got] == [("./m.js", "import"), ("n", "export_from"), ("pkg", "require")]


def test_props_shorthand_method_and_non_object():
    p = jsts.props(jsts.calls(T("f({ a, b() { return 1; }, c: d(1, 2) });"))[0].args[0])
    assert sorted(p) == ["a", "b", "c"] and [t.value for t in p["a"]] == ["a"]
    assert jsts.props(T("opts")) == {}


def test_is_source_inside_a_slice_with_roots_for_that_slice():
    toks = T("app.get('/', async (req2, res) => { run(req2.body.id); });")
    assert jsts.is_source(toks) is True
    assert jsts.is_source(toks, roots=[]) is False
    assert jsts.handler_roots(T("app.get('/', handler); x.put(fn);")) == []


def test_tokens_golden_is_up_to_date():
    assert json.loads(GOLDEN.read_text(encoding="utf-8")) == token_hashes()


if __name__ == "__main__":
    if "--record" in sys.argv[1:]:
        record()
    else:
        sys.exit("usage: python tests/test_jsts.py --record")
