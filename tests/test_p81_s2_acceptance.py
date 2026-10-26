"""P81 S2 acceptance -- code_guardian/scanners_js.py, the JavaScript / TypeScript Safe checks, and dom.html_sink (P81 C2).

Written by the overseer on main (bf5e31e) BEFORE the build session. The build session adds this file to the PR
byte-for-byte and never edits it. Pure ASCII on purpose; no key-shaped value anywhere.

Contract (C2), with the overseer's precisions marked P:
  JS_SCANNERS = [(code, fn)] over the ten C2 codes; scan_js(jf, crashed=None) mirrors scanners.scan_python (a scanner
  that raises gives one check.crashed WARN; with a list, (code, finding) is appended). P1 scan_js reads JS_SCANNERS
  when it is called.
  P2 jf = JsFile(rel, text, flavour, generated=False) builds its own tokens (jsts.tokenize), calls and imports. With
  generated=True only the obfuscation and exec.dynamic rows run and an exec.dynamic WARN is reported as INFO (FAILs
  stay; C2's generated-file rule). node is "rel:line" of the sink.
  P3 net.egress takes the Python rule imported unchanged, URL and IP literals alike (an IP string is inventoried as
  Python does: '127.0.0.1' -> INFO loopback, '0.0.0.0' / '::' never): a URL to a reserved documentation name
  (example.org) is INFO, so js_risky's fetch('http://example.org/x') is INFO, not the WARN C7 wrote. The imported
  rule wins (deviation).
  P4 exec.shell's exec( / execSync( / spawn( ... must be the child_process binding (a destructured name, or a member
  of the module object): pattern.exec(text) never fires, even in a file that imports child_process.
  P5 exec.dynamic fires on eval( / Function( whatever the argument (WARN), FAIL when is_source; C2 has no literal
  exemption (the generated-file case eval("1") -> INFO depends on it).
  P6 jsts gains four source roots: window.location, document.location, globalThis.location, self.location (C1 listed
  location. and window.name only; `el.innerHTML = window.location.hash` must be FAIL like `location.hash`). That
  set is the only change allowed in jsts.py; tests/golden/jsts_tokens.json does not change.
  P7 constants are imported from scanners.py, never copied: scanners_js.py defines none of the names in COPIED below.
  scanners.py and works.py are byte-unchanged (compared with CRLF folded to LF).
  python -m code_guardian.scanners_js --selftest prints "N checks, N passed", N >= 20.
"""
import ast
import hashlib
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
FIXTURES = HERE / "fixtures"
FLAVOUR = {".js": "js", ".mjs": "js", ".cjs": "js", ".jsx": "jsx", ".ts": "ts", ".tsx": "tsx"}
CODES = {"exec.dynamic", "exec.shell", "deser.unsafe", "net.egress", "net.bind_all", "tls.off", "obfuscation",
         "fs.outside", "privacy.pii_log", "dom.html_sink"}
UNCHANGED_LF_MD5 = {"code_guardian/scanners.py": "b7012b49f8b94b43c90246aa630c4773",
                    "code_guardian/works.py": "689717efa537e72b1bc43ec258cd496e"}
COPIED = {"SECRET_NAME", "SECRET_SUFFIX", "BLOB_MIN", "TOKEN_MIN", "TOKEN_ENTROPY", "_B64", "_HEX", "DEVICES", "URL",
          "RESERVED", "RESERVED_SUFFIXES", "LOCAL_SUFFIXES", "NAMESPACE_HOSTS", "_ALL_INTERFACES", "entropy",
          "outside", "classify_host", "_url_host", "_ip", "redact_url"}
JSX_INFO = "code-like text inside JSX text was not analysed"
STRAY = "after a stray backtick in JSX text"


def _m():
    from code_guardian import scanners_js
    return scanners_js


def findings(text, flavour="js", rel="t.js", generated=False):
    m = _m()
    return m.scan_js(m.JsFile(rel, text, flavour, generated=generated))


def got(text, flavour="js", rel="t.js", generated=False):
    """{(code, level, line)} with check.crashed never allowed."""
    out = set()
    for f in findings(text, flavour, rel, generated):
        assert f["code"] != "check.crashed", f
        out.add((f["code"], f["level"], int(f["node"].rsplit(":", 1)[1])))
    return out


def fixture(rel):
    p = FIXTURES / rel
    return p.read_bytes().decode("utf-8"), FLAVOUR[p.suffix]


def fixture_got(rel):
    text, flavour = fixture(rel)
    return got(text, flavour, rel=Path(rel).name)


# ---- the module shape --------------------------------------------------------------------------------------------------

def test_registry_and_node_shape():
    m = _m()
    assert {c for c, _ in m.JS_SCANNERS} == CODES
    fs = findings("eval(x);\n\nconsole.log(password);\n", rel="src/a.js")
    assert sorted(f["node"] for f in fs) == ["src/a.js:1", "src/a.js:3"]
    for f in fs:
        assert f["confidence"] == "LIKELY" and isinstance(f["evidence"], list) and isinstance(f["try"], list)


def test_a_raising_scanner_is_one_crashed_warn(monkeypatch):
    m = _m()

    def boom(_jf):
        raise RuntimeError("planted")
    monkeypatch.setattr(m, "JS_SCANNERS", [("exec.dynamic", boom)])
    crashed = []
    out = m.scan_js(m.JsFile("t.js", "eval(x);\n", "js"), crashed=crashed)
    assert [(f["code"], f["level"]) for f in out] == [("check.crashed", "WARN")]
    assert [c for c, _ in crashed] == ["exec.dynamic"]


# ---- the fixtures ------------------------------------------------------------------------------------------------------

JS_RISKY = {
    ("obfuscation", "WARN", 8), ("tls.off", "FAIL", 11), ("exec.dynamic", "FAIL", 14), ("exec.shell", "FAIL", 15),
    ("net.egress", "INFO", 16), ("exec.dynamic", "WARN", 17), ("obfuscation", "FAIL", 17), ("fs.outside", "WARN", 18),
    ("privacy.pii_log", "WARN", 19), ("dom.html_sink", "FAIL", 21), ("net.bind_all", "WARN", 24),
}


def test_js_risky_pinned():
    assert fixture_got("js_risky/server.js") == JS_RISKY


@pytest.mark.parametrize("rel", ["js_clean/src/index.js", "js_clean/src/util.js", "js_clean/test/index.test.js",
                                 "js_broken/src/index.ts", "js_broken/src/half.js", "jsx_torture/util.tsx",
                                 "jsx_torture/bin.mjs"], ids=lambda r: r.replace("/", "_"))
def test_no_safe_finding(rel):
    assert fixture_got(rel) == set()


def test_jsx_torture_app():
    assert fixture_got("jsx_torture/App.jsx") == {
        ("exec.dynamic", "FAIL", 22), ("exec.dynamic", "FAIL", 23), ("exec.dynamic", "FAIL", 24),
        ("exec.dynamic", "INFO", 25), ("net.egress", "INFO", 24)}
    text, flavour = fixture("jsx_torture/App.jsx")
    info = [f for f in findings(text, flavour, "App.jsx") if f["level"] == "INFO" and f["code"] == "exec.dynamic"]
    assert len(info) == 1 and info[0]["summary"] == JSX_INFO
    assert any("eval" in e for e in info[0]["evidence"])
    assert not any(STRAY in e for f in findings(text, flavour, "App.jsx") for e in f["evidence"])


def test_jsx_torture_quote_after_a_stray_backtick():
    text, flavour = fixture("jsx_torture/Quote.jsx")
    fs = findings(text, flavour, "Quote.jsx")
    assert [(f["code"], f["level"], f["node"]) for f in fs] == [("exec.dynamic", "FAIL", "Quote.jsx:6")]
    assert STRAY in fs[0]["evidence"]


def test_two_apostrophe_info_is_jsx_only():
    line = "<p>Don't</p>{eval(location.hash)}<p>didn't</p>\nexport const k = 1;\n"
    assert got(line, "jsx") == {("exec.dynamic", "INFO", 1)}
    assert got(line, "ts", rel="t.ts") == set()


# ---- each row ----------------------------------------------------------------------------------------------------------

ROWS = [
    # exec.dynamic
    ("eval_input", "app.post('/', (q, r) => { eval(q.body.code); });", "js", {("exec.dynamic", "FAIL", 1)}),
    ("eval_plain", "eval(code);", "js", {("exec.dynamic", "WARN", 1)}),
    ("eval_literal", "eval('1 + 1');", "js", {("exec.dynamic", "WARN", 1)}),
    ("window_eval", "window.eval(code);\nglobalThis.eval(code);", "js",
     {("exec.dynamic", "WARN", 1), ("exec.dynamic", "WARN", 2)}),
    ("function_ctor", "const f = new Function(req.query.f);\nconst g = Function('a', 'return a');", "js",
     {("exec.dynamic", "FAIL", 1), ("exec.dynamic", "WARN", 2)}),
    ("timers", "setTimeout('tick()', 10);\nsetInterval(`run(${n})`, 5);\nsetTimeout(tick, 10);\n"
               "setTimeout(() => run(), 1);", "js", {("exec.dynamic", "WARN", 1), ("exec.dynamic", "WARN", 2)}),
    ("vm_imported", "const vm = require('vm');\nvm.runInNewContext(code);\nvm.runInThisContext(req.body.x);", "js",
     {("exec.dynamic", "WARN", 2), ("exec.dynamic", "FAIL", 3)}),
    ("vm_not_imported", "vm.runInContext(code);", "js", set()),
    # exec.shell
    ("shell_member", "const cp = require('node:child_process');\ncp.exec(cmd);\ncp.execSync('ls ' + dir);\n"
                     "cp.spawn('ls', [], { shell: true });\ncp.spawn('ls', []);\ncp.execFile('ls', ['-l']);", "js",
     {("exec.shell", "WARN", 2), ("exec.shell", "FAIL", 3), ("exec.shell", "WARN", 4)}),
    ("shell_import", "import { exec } from 'child_process';\nexec(req.query.c);\nconst m = pattern.exec(text);",
     "js", {("exec.shell", "FAIL", 2)}),
    ("shell_no_import", "exec(cmd);\nconst m = /a/.exec(s);", "js", set()),
    ("shelljs", "const sh = require('shelljs');\nsh.exec('ls');", "js", {("exec.shell", "WARN", 2)}),
    # deser.unsafe
    ("node_serialize", "const s = require('node-serialize');\ns.unserialize(data);", "js",
     {("deser.unsafe", "WARN", 2)}),
    ("unserialize_no_import", "unserialize(data);", "js", set()),
    # net.egress (the Python rule, imported)
    ("egress_https_reserved", "fetch('https://api.example.com/v1');", "js", {("net.egress", "INFO", 1)}),
    ("egress_plain_http", "axios.get('http://static.cg-fixture.net/x');", "js", {("net.egress", "WARN", 1)}),
    ("egress_runtime", "fetch(url);", "js", {("net.egress", "INFO", 1)}),
    ("egress_socket", "const ws = new WebSocket('wss://feed.example.org/s');\nnavigator.sendBeacon('/log', d);",
     "js", {("net.egress", "INFO", 1), ("net.egress", "INFO", 2)}),
    # net.bind_all
    ("bind_all", "app.listen(80, '0.0.0.0');\napp.listen({ port: 81, host: '::' });\n"
                 "https.createServer({ host: '0.0.0.0' }, h);\napp.listen(82, '127.0.0.1');", "js",
     {("net.bind_all", "WARN", 1), ("net.bind_all", "WARN", 2), ("net.bind_all", "WARN", 3),
      ("net.egress", "INFO", 4)}),
    # tls.off
    ("tls_off", "const a = { strictSSL: false };\nprocess.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n"
                "process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0;\nconst b = { rejectUnauthorized: cfg.verify };\n"
                "const c = { rejectUnauthorized: true };", "js",
     {("tls.off", "FAIL", 1), ("tls.off", "FAIL", 2), ("tls.off", "FAIL", 3), ("tls.off", "WARN", 4)}),
    # obfuscation
    ("obf_buffer", "eval(Buffer.from(p, 'base64').toString());", "js",
     {("obfuscation", "FAIL", 1), ("exec.dynamic", "WARN", 1)}),
    ("obf_charcode_fn", "new Function(String.fromCharCode(97, 98));", "js",
     {("obfuscation", "FAIL", 1), ("exec.dynamic", "WARN", 1)}),
    ("obf_charcode_many", "const s = String.fromCharCode(" + ", ".join(str(97 + i % 20) for i in range(20)) + ");",
     "js", {("obfuscation", "WARN", 1)}),
    ("obf_escapes", 'const s = "\\x61\\x62\\x63\\x64\\x65";', "js", {("obfuscation", "WARN", 1)}),
    # fs.outside
    ("fs_outside", "const fs = require('fs');\nfs.writeFileSync('/etc/motd', 'x');\nfs.unlinkSync('../up.txt');\n"
                   "fs.writeFileSync('out/report.txt', 'x');\nfs.writeFileSync('/dev/null', 'x');\n"
                   "fs.writeFileSync(process.env.HOME + '/x', 'x');\nfs.mkdirSync('%APPDATA%\\\\app');", "js",
     {("fs.outside", "WARN", 2), ("fs.outside", "WARN", 3), ("fs.outside", "WARN", 6), ("fs.outside", "WARN", 7)}),
    ("fs_promises", "const fsp = require('node:fs/promises');\nawait fsp.writeFile('~/notes.txt', d);", "js",
     {("fs.outside", "WARN", 2)}),
    ("fs_no_import", "writeFileSync('/etc/x', 'y');", "js", set()),
    # privacy.pii_log
    ("pii_log", "console.log(password);\nlogger.info(apiKey);\nlog.debug(user.password);\n"
                "console.log('password reset sent');\nconsole.log(userName);", "js",
     {("privacy.pii_log", "WARN", 1), ("privacy.pii_log", "WARN", 2), ("privacy.pii_log", "WARN", 3)}),
    # dom.html_sink
    ("html_assign", "el.innerHTML = post.body;\nel.outerHTML = html;\nel.innerHTML = '<b>hi</b>';\n"
                    "el.innerHTML = location.hash;\nel.innerHTML = window.location.hash;", "js",
     {("dom.html_sink", "WARN", 1), ("dom.html_sink", "WARN", 2), ("dom.html_sink", "FAIL", 4),
      ("dom.html_sink", "FAIL", 5)}),
    ("html_calls", "el.insertAdjacentHTML('beforeend', req.query.x);\ndocument.write(location.search);\n"
                   "document.writeln('<p>');\n$('#out').html(data);\n$('#out').html();", "js",
     {("dom.html_sink", "FAIL", 1), ("dom.html_sink", "FAIL", 2), ("dom.html_sink", "WARN", 4)}),
    ("html_react", "const C = () => <div dangerouslySetInnerHTML={{ __html: post.body }} />;", "jsx",
     {("dom.html_sink", "WARN", 1)}),
    ("html_angular", "this.v = this.sanitizer.bypassSecurityTrustHtml(queryParam);\n"
                     "this.w = this.sanitizer.bypassSecurityTrustHtml(req.query.q);", "ts",
     {("dom.html_sink", "WARN", 1), ("dom.html_sink", "FAIL", 2)}),
]


@pytest.mark.parametrize("text,flavour,want", [r[1:] for r in ROWS], ids=[r[0] for r in ROWS])
def test_rows(text, flavour, want):
    assert got(text + "\n", flavour, rel="t.ts" if flavour == "ts" else "t.js") == want


# ---- negative rules ----------------------------------------------------------------------------------------------------

NEGATIVES = [
    ("in_string", "const s = \"eval(x); el.innerHTML = y; require('child_process').exec(z)\";"),
    ("in_template", "const t = `eval(x); el.innerHTML = y`;"),
    ("in_comment", "// eval(req.query.x); el.innerHTML = location.hash\n/* document.write(location.hash) */"),
    ("in_regex", "const r = /eval\\(x\\)|innerHTML/;"),
    ("method_eval", "holder.eval(x);\nconst o = { eval: 1, innerHTML: 'x' };"),
    ("pii_string", "console.log('password: hidden');"),
]


@pytest.mark.parametrize("text", [n[1] for n in NEGATIVES], ids=[n[0] for n in NEGATIVES])
def test_negative_rules(text):
    assert {g for g in got(text + "\n", "jsx") if g[1] in ("WARN", "FAIL")} == set()
    assert got(text + "\n", "js") == set()


def test_url_evidence_never_carries_a_query_value():
    fs = findings("fetch('https://api.example.com/x?session=zz9placeholder');\n")
    assert fs and not any("zz9placeholder" in str(f) for f in fs)


# ---- generated files ---------------------------------------------------------------------------------------------------

def _bundle(body):
    line = "/*! placeholder bundle, no real library */var a=0;" + body
    return line + "a+=1;" * ((3000 - len(line)) // 5 + 1) + "\n"


def test_generated_file_subset():
    one = _bundle('eval("1");var f=new Function("a","return a");el.innerHTML=x;fetch("http://cdn.cg-fixture.net/x");'
                  'console.log(password);')
    assert len(one.splitlines()[0]) >= 3000
    assert got(one, generated=True, rel="vendor.min.js") == {("exec.dynamic", "INFO", 1)}
    assert len([f for f in findings(one, generated=True, rel="vendor.min.js") if f["code"] == "exec.dynamic"]) == 2
    two = _bundle('eval(atob("Y29uc29sZS5sb2coMSk="));')
    g = got(two, generated=True, rel="app.bundle.js")
    assert ("obfuscation", "FAIL", 1) in g
    assert {x[1] for x in g} <= {"INFO", "FAIL"} and {x[0] for x in g} <= {"obfuscation", "exec.dynamic"}
    src = _bundle("eval(req.query.x);")
    assert ("exec.dynamic", "FAIL", 1) in got(src, generated=True, rel="b.min.js")


# ---- jsts source roots (P6) --------------------------------------------------------------------------------------------

@pytest.mark.parametrize("text,want", [
    ("window.location.hash", True), ("document.location.href", True), ("globalThis.location.search", True),
    ("self.location.hash", True), ("window.locations.x", False), ("window.locale", False),
], ids=["window", "document", "globalthis", "self", "plural", "locale"])
def test_location_roots(text, want):
    from code_guardian import jsts
    assert jsts.is_source(jsts.tokenize(text, "js")) is want


# ---- scoring, catalogue, plain, README ---------------------------------------------------------------------------------

def test_weights_catalogue_why_readme():
    from code_guardian import catalogue, plain, score
    assert score.SAFE_WEIGHTS[("dom.html_sink", "WARN")] == 10
    assert score.SAFE_WEIGHTS[("dom.html_sink", "FAIL")] == 30
    assert score.SAFE_WEIGHTS[("exec.dynamic", "INFO")] == 0
    assert score.dimension_of("dom.html_sink") == "safe"
    entry = catalogue.CATALOGUE["dom.html_sink"]
    assert set(entry) == {"title", "means", "fix", "false_positives"} and all(entry.values())
    assert plain.WHY["dom.html_sink"] == ("This code puts text into the page as HTML. If that text comes from a "
                                          "visitor or a web address, it can run as a script in another visitor's "
                                          "browser.")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert readme.count("`dom.html_sink`") >= 3


# ---- imported, not copied; untouched modules ---------------------------------------------------------------------------

def test_constants_imported_not_copied():
    src = (ROOT / "code_guardian" / "scanners_js.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    defined = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            defined.add(node.name)
        elif isinstance(node, ast.Assign):
            defined.update(t.id for t in node.targets if isinstance(t, ast.Name))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            defined.add(node.target.id)
    assert not (defined & COPIED), sorted(defined & COPIED)
    imports = [n for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
    assert any((n.module or "").endswith("scanners") or any(a.name == "scanners" for a in n.names) for n in imports)


def test_python_modules_unchanged():
    for rel, want in UNCHANGED_LF_MD5.items():
        data = (ROOT / rel).read_bytes().replace(b"\r\n", b"\n")
        assert hashlib.md5(data).hexdigest() == want, rel


# ---- selftest ----------------------------------------------------------------------------------------------------------

def test_selftest_count():
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT)
    p = subprocess.run([sys.executable, "-m", "code_guardian.scanners_js", "--selftest"], cwd=str(ROOT), env=env,
                       capture_output=True, text=True, encoding="utf-8", timeout=300)
    m = re.search(r"(\d+) checks, (\d+) passed", p.stdout)
    assert p.returncode == 0 and m, (p.returncode, p.stdout[-500:], p.stderr[-500:])
    assert int(m.group(1)) == int(m.group(2)) >= 20, m.group(0)
