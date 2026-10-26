"""scanners_js.py beyond the overseer's acceptance file: binding forms, argument shapes, evidence, and a long line."""
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest

from code_guardian import scanners_js
from code_guardian.scanners_js import JsFile, scan_js

ROOT = Path(__file__).resolve().parent.parent


def run(text, flavour="js", generated=False):
    return scan_js(JsFile("t.js", text, flavour, generated=generated))


def got(text, flavour="js", generated=False):
    return sorted({(f["code"], f["level"], int(f["node"].rsplit(":", 1)[1])) for f in run(text, flavour, generated)})


@pytest.mark.parametrize("text,want", [
    ("const { exec: run } = require('node:child_process');\nrun(`ls ${x}`);\n", [("exec.shell", "FAIL", 2)]),
    ("require('child_process').execSync(cmd);\n", [("exec.shell", "WARN", 1)]),
    ("import cp from 'node:child_process';\ncp.exec(a + b);\n", [("exec.shell", "FAIL", 2)]),
    ("import * as cp from 'child_process';\ncp.exec(c);\n", [("exec.shell", "WARN", 2)]),
    ("const cp = await import('child_process');\ncp.exec(c);\n", [("exec.shell", "WARN", 2)]),
    ("const exec = require('child_process').exec;\nexec(c);\n", [("exec.shell", "WARN", 2)]),
    ("const cp = require('child_process');\nget().exec(c);\n/a/.exec(s);\nx.cp.exec(c);\n", []),
    ("import type { exec } from 'child_process';\nexec(c);\n", []),
], ids=["destructure_rename", "inline_require", "default_import", "namespace_import", "dynamic_import",
        "member_of_require", "not_the_binding", "type_import"])
def test_child_process_bindings(text, want):
    assert got(text) == want


def test_a_comment_inside_a_handler_does_not_shift_its_roots():
    assert got("app.post('/', (q, r) => { /* c */ eval(q.body.x); });\n") == [("exec.dynamic", "FAIL", 1)]
    assert got("app.post('/', (q, r) => { setTimeout(`${q.body.x}`, 1); });\n") == [("exec.dynamic", "FAIL", 1)]


def test_template_expressions_are_read_as_code():
    assert got("setTimeout(`go(${req.query.x})`, 1);\n") == [("exec.dynamic", "FAIL", 1)]
    assert got("setTimeout(`go(${n})`, 1);\n") == [("exec.dynamic", "WARN", 1)]


@pytest.mark.parametrize("text,want", [
    ("el.innerHTML += req.query.x;\nel.innerHTML += 'lit';\n", [("dom.html_sink", "FAIL", 1)]),
    ("$el.html(v);\n$('#a').find('b').html(v);\ncheerio.html(v);\nx.html(v);\n",
     [("dom.html_sink", "WARN", 1), ("dom.html_sink", "WARN", 2)]),
    ("<p dangerouslySetInnerHTML={markup()} />;\nReact.createElement('p', { dangerouslySetInnerHTML: { __html: u } });\n"
     "React.createElement('p', { dangerouslySetInnerHTML: { __html: 'x' } });\n",
     [("dom.html_sink", "WARN", 1), ("dom.html_sink", "WARN", 2)]),
    ("document.write('a', req.query.b);\nwindow.document.writeln(x);\nother.write(x);\n",
     [("dom.html_sink", "FAIL", 1), ("dom.html_sink", "WARN", 2)]),
], ids=["append", "jquery", "react_forms", "document_write"])
def test_html_sink_shapes(text, want):
    assert got(text, "jsx") == want


@pytest.mark.parametrize("text,want", [
    ("const xhr = new XMLHttpRequest();\nxhr.open('GET', 'http://static.cg-fixture.net/x');\nother.open('GET', u);\n",
     [("net.egress", "WARN", 2)]),
    ("axios({ url: 'ws://static.cg-fixture.net/x' });\nfetch('/api/x');\nfetch(`https://${h}/z`);\n",
     [("net.egress", "INFO", 2), ("net.egress", "INFO", 3), ("net.egress", "WARN", 1)]),
    ("const a = 'https://example.com/a'; const b = 'https://example.org/b';\n", [("net.egress", "INFO", 1)]),
], ids=["xhr", "url_in_options", "literals"])
def test_egress_shapes(text, want):
    assert got(text) == want


def test_a_call_with_a_url_target_is_listed_once():
    fs = [f for f in run("fetch('http://static.cg-fixture.net/x');\n") if f["code"] == "net.egress"]
    assert len(fs) == 1 and fs[0]["evidence"][0] == "kind: call" and fs[0]["evidence"][1].startswith("target: http://")


def test_tls_forms():
    text = ("interface O { rejectUnauthorized: boolean }\nx.rejectUnauthorized = false;\n"
            "process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = '0';\nconst o = { 'strictSSL': false, rejectUnauthorized };\n")
    assert got(text, "ts") == [("tls.off", "FAIL", 2), ("tls.off", "FAIL", 3), ("tls.off", "FAIL", 4)]


def test_fs_forms():
    text = ("const fs = require('fs');\nfs.promises.writeFile('/x', d);\nfs.renameSync('a', '/etc/b');\n"
            "fs.writeFileSync(path.join(os.homedir(), 'x'), d);\nfs.writeFileSync(`${process.env.HOME}/x`, d);\n"
            "fs.writeFileSync(file, d);\n")
    assert got(text) == [("fs.outside", "WARN", 2), ("fs.outside", "WARN", 3), ("fs.outside", "WARN", 4),
                         ("fs.outside", "WARN", 5)]


def test_pii_log_skips_object_keys_and_other_receivers():
    text = "console.log({ password: '***' });\nMath.log(password);\nthis.logger.warn(token, apiKey);\n"
    assert got(text) == [("privacy.pii_log", "WARN", 3)]


def test_obfuscation_decoders():
    for arg in ("atob(p)", "Buffer.from(p, 'base64').toString()", "String.fromCharCode(1, 2)", "unescape(p)",
                "decodeURIComponent(p)", "zlib.inflateSync(b)", "zlib.gunzipSync(b)", "zlib.brotliDecompressSync(b)"):
        assert ("obfuscation", "FAIL", 1) in got("eval(%s);\n" % arg), arg
    assert ("obfuscation", "FAIL", 1) not in got("eval(Buffer.from(p, 'hex'));\n")
    assert got("setTimeout(atob(p) + 'x', 1);\nsetTimeout('a' + atob(p), 1);\n") == [
        ("exec.dynamic", "WARN", 2), ("obfuscation", "FAIL", 2)]  # a timer runs text only when its first argument starts as text


def test_deser_forms():
    assert got("const s = require('serialize-to-js');\ns.deserialize(d);\nlocal.deserialize(d);\n") == [("deser.unsafe", "WARN", 2)]
    assert got("eval(JSON.parse(d));\n") == [("deser.unsafe", "WARN", 1), ("exec.dynamic", "WARN", 1)]


def test_evidence_never_carries_a_secret_value():
    fs = run("console.log(password);\nfetch('https://user:hunter2x@api.example.com/x?token=abcdef');\n")
    blob = repr(fs)
    assert "hunter2x" not in blob and "abcdef" not in blob


def test_jsx_info_is_one_per_string_and_not_in_generated_files():
    line = "<p>Don't</p>{eval(location.hash)}<p>didn't</p>\n"
    assert len([f for f in run(line, "jsx") if f["level"] == "INFO"]) == 1
    assert got(line, "jsx", generated=True) == []


def test_a_long_minified_line_is_scanned_in_linear_time():
    text = "var a=0;" + "a+=1;f(a,'x');" * 40000 + "eval(atob('Z'));\n"
    start = time.time()
    fs = run(text, generated=True)
    assert time.time() - start < 20
    assert {(f["code"], f["level"]) for f in fs} == {("exec.dynamic", "INFO"), ("obfuscation", "FAIL")}


def test_the_registry_order_matches_the_c2_table():
    assert [c for c, _ in scanners_js.JS_SCANNERS] == [
        "exec.dynamic", "exec.shell", "deser.unsafe", "net.egress", "net.bind_all", "tls.off", "obfuscation",
        "fs.outside", "privacy.pii_log", "dom.html_sink"]


def test_crashed_list_gets_the_finding():
    crashed = []
    saved = list(scanners_js.JS_SCANNERS)
    try:
        scanners_js.JS_SCANNERS[:] = [("tls.off", lambda _jf: 1 / 0)]
        out = scan_js(JsFile("t.js", "x;\n", "js"), crashed=crashed)
    finally:
        scanners_js.JS_SCANNERS[:] = saved
    assert [(c, f["code"]) for c, f in crashed] == [("tls.off", "check.crashed")] and out == [crashed[0][1]]


def test_selftest_prints_the_counted_line():
    p = subprocess.run([sys.executable, "-m", "code_guardian.scanners_js", "--selftest"], cwd=str(ROOT),
                       capture_output=True, text=True, timeout=120)
    assert p.returncode == 0 and re.search(r"scanners_js selftest: (\d+) checks, \1 passed, 0 failed", p.stdout), p.stdout
