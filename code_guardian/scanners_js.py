"""The JavaScript / TypeScript Safe checks: small pure functions over the token list jsts.py cuts. Same input, same
findings, every time.

Nothing here executes, imports or installs the scanned code. The checks read call sites, imports, assignments and
object-literal properties off the tokens, one statement deep (nothing is followed between statements or functions),
and a sink named inside a string, a template, a comment or a regex is never a finding. Every constant and helper that
scanners.py already holds (the secret-name rule, the blob thresholds, the outside-path rule, the egress classifier, URL
redaction) is imported from it, never copied, so the Python and JavaScript sides cannot drift apart.

Public contract:
    JsFile(rel, text, flavour, generated=False)   # tokenizes once: .tokens .calls .imports; flavour in js jsx ts tsx
    JS_SCANNERS = [(code, fn(JsFile) -> [finding])]   # the ten C2 codes
    scan_js(jf, crashed=None) -> [finding]        # every JS_SCANNERS entry; a crashing scanner is one check.crashed WARN
                                                  # (generated=True: only obfuscation and exec.dynamic run, and an
                                                  # exec.dynamic WARN is reported at INFO)

A finding's node is "rel:line" of the sink. A finding whose sink token was lexed again after a stray backtick in JSX
text carries the evidence line STRAY_BACKTICK; a string in a JSX file that names a sink inside braces is one
exec.dynamic INFO, so text the lexer could not tell from code is reported and never dropped.
"""

import re
import sys
from bisect import bisect_left, bisect_right
from collections import namedtuple

from . import jsts
from .finding import run_check, summarize
from .scanners import (BLOB_MIN, SECRET_NAME, TOKEN_ENTROPY, TOKEN_MIN, URL, _ALL_INTERFACES, _B64, _HEX, _ip,
                       _url_host, classify_host, dedupe, entropy, finding, outside, redact_url)

STRAY_BACKTICK = "after a stray backtick in JSX text"
JSX_TEXT_SUMMARY = "code-like text inside JSX text was not analysed"
JSX_CODE = re.compile(r"\{[^}]*\b(eval|Function|setTimeout|setInterval|runInContext|runInNewContext|runInThisContext|"
                      r"exec|execSync|spawn|innerHTML|outerHTML|insertAdjacentHTML|write|writeln|"
                      r"bypassSecurityTrust\w*)\b[^}]*\}")
GENERATED_CODES = frozenset({"obfuscation", "exec.dynamic"})  # the token scans a generated or minified file gets
GLOBAL_PREFIXES = ("window.", "globalThis.", "self.")

Site = namedtuple("Site", "call callee start open spans new member")  # a jsts call site, callee written with "." only
Spec = namedtuple("Spec", "spaces named")  # {local dotted name: module}, {local name: (module, imported name)}


def _literal_text(t):
    """The text of a string token, or of a template with no expression; None for anything else."""
    if t.kind == "string" or (t.kind == "template" and "${" not in t.value):
        return t.value[1:-1]
    return None


def _module(spec):
    return spec[5:] if spec.startswith("node:") else spec


class JsFile:
    """One lexed file plus the lookups every scanner needs. Tokens, calls and imports are built here; the rest is
    built the first time a scanner asks."""

    def __init__(self, rel, text, flavour, generated=False):
        self.rel = rel
        self.text = text
        self.flavour = flavour
        self.generated = generated
        self.tokens = jsts.tokenize(text, flavour)
        self.calls = jsts.calls(self.tokens)
        self.imports = jsts.imports(self.tokens)
        self.jsx = flavour in ("jsx", "tsx") or (flavour == "js" and jsts.JSX_HINT.search(text) is not None)
        self._sig = self._pos = self._mate = self._sites = self._roots = self._index = self._modules = None
        self._lines = None

    @property
    def sig(self):
        if self._sig is None:
            self._sig, self._pos = jsts._significant(self.tokens)
            self._mate = jsts._pairs(self._sig)
        return self._sig

    @property
    def mate(self):
        self.sig
        return self._mate

    @property
    def sites(self):
        if self._sites is None:
            raw = jsts._call_sites(self.sig, self.mate)
            self._sites = [Site(c, s[0].replace("?.", "."), s[1], s[2], s[3], s[4], s[5]) for c, s in zip(self.calls, raw)]
        return self._sites

    @property
    def roots(self):
        if self._roots is None:
            self._roots = jsts.handler_roots(self.tokens)
        return self._roots

    def sink(self, site):
        """The token a finding for this call site is anchored on: the first token of the callee."""
        return self.sig[site.start]

    def token_on(self, line, name):
        """The token on `line` whose text is `name` (quotes aside), else the line's first token: where a finding about
        an assignment, which jsts reports by line only, is anchored."""
        if self._lines is None:
            self._lines = {}
            for t in self.sig:
                self._lines.setdefault(t.line, []).append(t)
        row = self._lines.get(line) or [self.sig[0]]
        return next((t for t in row if t.value.strip("'\"") == name), row[0])

    def is_source(self, arg):
        """jsts.is_source on an argument slice. The file's handler roots are shifted into the slice's index space (the
        slice drops comments, so its indexes are not the token list's), and the `${ }` expressions of a template are
        read as code, after the slice."""
        if not arg:
            return False
        if self._index is None:
            self._index = {id(t): i for i, t in enumerate(self.tokens)}
        base = [self._index[id(t)] for t in arg if id(t) in self._index]
        roots = []
        if len(base) == len(arg):
            for name, a, b in self.roots:
                lo, hi = bisect_left(base, a), bisect_right(base, b) - 1
                if lo <= hi:
                    roots.append([name, lo, hi])
        tokens = list(arg)
        exprs = [e for t in arg if t.kind == "template" and "${" in t.value for e in _template_exprs(t.value)]
        if exprs:
            tokens += jsts.tokenize(";".join(exprs), "js")
            for r in roots:
                if any(t.kind == "template" and "${" in t.value for t in arg[r[1]:r[2] + 1]):
                    r[2] = len(tokens) - 1
        return jsts.is_source(tokens, [tuple(r) for r in roots])

    # ---- imports --------------------------------------------------------------------------------------------------

    def modules(self):
        """Spec(spaces, named): what each import and require binds, by module name with any `node:` prefix removed."""
        if self._modules is None:
            self._modules = _bind_modules(self.sig, self.mate)
        return self._modules

    def module_call(self, site):
        """(module, member) when the call is a member of an imported module: `cp.exec(` for a namespace or default
        binding, `exec(` for a destructured name, `require('child_process').exec(` inline. None otherwise, so
        `pattern.exec(` never counts."""
        spaces, named = self.modules()
        if site.member:
            return _inline_require(self.sig, self.mate, site)
        if "." not in site.callee:
            return named.get(site.callee)
        ns, _, name = site.callee.rpartition(".")
        if ns in spaces:
            return spaces[ns], name
        head, _, tail = ns.rpartition(".")
        if tail == "promises" and spaces.get(head) == "fs":
            return "fs/promises", name
        return None


def _template_exprs(value):
    """The source text of each `${ }` in a template's raw text."""
    out = []
    i, n = 1, len(value) - 1
    while i < n:
        c = value[i]
        if c == "\\":
            i += 2
        elif c == "$" and value.startswith("{", i + 1):
            depth, j = 1, i + 2
            while j < n and depth:
                depth += (value[j] == "{") - (value[j] == "}")
                j += 1
            out.append(value[i + 2:j - 1])
            i = j
        else:
            i += 1
    return out


def _string_at(sig, mate, o):
    """The module name when sig[o] opens `( 'name' )`, else None."""
    if o + 2 < len(sig) and mate[o] == o + 2 and sig[o].value == "(" and sig[o].kind == "punct":
        text = _literal_text(sig[o + 1])
        return None if text is None else _module(text)
    return None


def _inline_require(sig, mate, site):
    """(module, member) for `require('x').member(` as a call site: the receiver is the require call."""
    d = site.start - 1
    if d >= 3 and jsts._punct(sig[d], *jsts._DOTS) and jsts._punct(sig[d - 1], ")") and mate[d - 1] >= 0:
        o = mate[d - 1]
        if o >= 1 and (sig[o - 1].value == "require" or sig[o - 1].value == "import") and "." not in site.callee:
            spec = _string_at(sig, mate, o)
            if spec is not None:
                return spec, site.callee
    return None


def _bind_modules(sig, mate):
    spaces, named = {}, {}
    n = len(sig)
    for k, t in enumerate(sig):
        if t.kind == "keyword" and t.value == "import" and k + 1 < n and not jsts._punct(sig[k + 1], "("):
            _bind_import(sig, mate, k, spaces, named)
        elif (t.value == "require" and t.kind == "name" or t.kind == "keyword" and t.value == "import") \
                and k + 1 < n and jsts._punct(sig[k + 1], "(") and not (k and jsts._punct(sig[k - 1], *jsts._DOTS)):
            spec = _string_at(sig, mate, k + 1)
            if spec is not None:
                _bind_require(sig, mate, k, spec, spaces, named)
    return Spec(spaces, named)


def _target(sig, mate, e):
    """Dotted text of the plain name path ending at sig[e], else None."""
    if not jsts._is_name(sig[e]):
        return None
    start = jsts._target_start(sig, mate, e)
    parts = sig[start:e + 1]
    if all(jsts._is_name(x) or jsts._punct(x, *jsts._DOTS) for x in parts):
        return "".join(x.value for x in parts).replace("?.", ".")
    return None


def _bind_require(sig, mate, k, spec, spaces, named):
    close = mate[k + 1]
    after = close + 1
    member = None
    if after + 1 < len(sig) and jsts._punct(sig[after], *jsts._DOTS) and jsts._is_name(sig[after + 1]) \
            and not (after + 2 < len(sig) and jsts._punct(sig[after + 2], "(")):
        member = sig[after + 1].value
    j = k - 1
    if j >= 0 and sig[j].value == "await":
        j -= 1
    if j < 1 or not jsts._punct(sig[j], "="):
        return
    e = j - 1
    if jsts._punct(sig[e], "}") and mate[e] >= 0 and member is None:
        o = mate[e]
        for a, b in jsts._split(sig, mate, o + 1, e):
            if sig[a].kind in ("name", "string", "keyword"):
                imported = sig[a].value.strip("'\"")
                local = sig[a + 2].value if b - a >= 3 and jsts._punct(sig[a + 1], ":") and sig[a + 2].kind == "name" else imported
                named[local] = (spec, imported)
        return
    target = _target(sig, mate, e)
    if target:
        if member is None:
            spaces[target] = spec
        else:
            named[target] = (spec, member)


def _bind_import(sig, mate, k, spaces, named):
    n = len(sig)
    j = k + 1
    if sig[j].kind == "name" and sig[j].value == "type" and j + 1 < n and (
            jsts._punct(sig[j + 1], "{", "*") or (sig[j + 1].kind == "name" and sig[j + 1].value != "from")):
        return  # `import type`: a type, not a module value
    default = star = None
    members = []
    if sig[j].kind == "name" and not (j + 1 < n and jsts._punct(sig[j + 1], "=")):
        default = sig[j].value
        j += 1
        if j < n and jsts._punct(sig[j], ","):
            j += 1
    if j + 2 < n and jsts._punct(sig[j], "*") and sig[j + 1].value == "as":
        star = sig[j + 2].value
        j += 3
    elif j < n and jsts._punct(sig[j], "{") and mate[j] > j:
        for a, b in jsts._split(sig, mate, j + 1, mate[j]):
            if sig[a].value == "type" and b - a >= 2 and sig[a + 1].value != "as":
                a += 1  # `{ type X }`
            parts = sig[a:b]
            if parts and parts[0].kind in ("name", "keyword", "string"):
                imported = parts[0].value.strip("'\"")
                local = parts[2].value if len(parts) >= 3 and parts[1].value == "as" else imported
                members.append((local, imported))
        j = mate[j] + 1
    if j + 1 < n and sig[j].kind == "name" and sig[j].value == "from" and sig[j + 1].kind == "string":
        spec = _module(sig[j + 1].value[1:-1])
        for local in (default, star):
            if local:
                spaces[local] = spec
        for local, imported in members:
            if imported == "default":
                spaces[local] = spec
            else:
                named[local] = (spec, imported)


# ---- shared helpers --------------------------------------------------------------------------------------------------

def _hit(jf, code, level, tok, summary, evidence=(), try_=()):
    """A finding anchored on tok; the evidence says so when tok was lexed again after a stray backtick."""
    ev = list(evidence)
    if tok.flags == "relexed":
        ev.append(STRAY_BACKTICK)
    return finding(code, level, "%s:%d" % (jf.rel, tok.line), summary, ev, try_)


def _global(callee):
    for prefix in GLOBAL_PREFIXES:
        if callee.startswith(prefix):
            return callee[len(prefix):]
    return callee


def _flat(args):
    return [t for a in args for t in a]


def _is_template_with_expr(t):
    return t.kind == "template" and "${" in t.value


def _concatenated(arg):
    """A `+` at bracket depth 0 in the argument."""
    depth = 0
    for t in arg:
        if t.kind == "punct":
            if t.value in "([{":
                depth += 1
            elif t.value in ")]}":
                depth -= 1
            elif t.value == "+" and depth == 0:
                return True
    return False


# ---- exec.dynamic ----------------------------------------------------------------------------------------------------

EVAL_CALLEES = frozenset({"eval", "window.eval", "globalThis.eval"})
FUNCTION_CALLEES = frozenset({"Function", "window.Function", "globalThis.Function"})
TIMER_CALLEES = frozenset({"setTimeout", "setInterval"})
VM_METHODS = frozenset({"runInThisContext", "runInNewContext", "runInContext", "compileFunction"})


def dynamic_calls(jf):
    """[(site, name, [argument slices that hold the code text])] for every call that runs text as code."""
    out = []
    for s in jf.sites:
        args = s.call.args
        if not args:
            continue
        c = s.callee
        if s.member:
            hit = jf.module_call(s)
            if hit and hit[0] == "vm" and hit[1] in VM_METHODS:
                out.append((s, "vm." + hit[1], [args[0]]))
            continue
        if c in EVAL_CALLEES:
            out.append((s, "eval", [args[0]]))
        elif c in FUNCTION_CALLEES:
            out.append((s, "Function", list(args)))
        elif _global(c) in TIMER_CALLEES:
            if args[0] and args[0][0].kind in ("string", "template"):
                out.append((s, _global(c), [args[0]]))
        else:
            hit = jf.module_call(s)
            if hit and hit[0] == "vm" and hit[1] in VM_METHODS:
                out.append((s, "vm." + hit[1], [args[0]]))
    return out


def scan_exec_dynamic(jf):
    """eval / Function / a string timer / the vm module on anything: WARN, FAIL when the code text is read from a
    request, the environment or the page. There is no literal exemption. In a generated file a WARN is INFO."""
    out = []
    for s, name, code_args in dynamic_calls(jf):
        tok = jf.sink(s)
        literal = len(code_args) == 1 and jsts.literal(code_args[0]) is not None
        if any(jf.is_source(a) for a in code_args):
            out.append(_hit(jf, "exec.dynamic", "FAIL", tok, "%s() runs code typed by the user" % name,
                            ["call: %s(<input>)" % name,
                             "the code text is read from a request, the URL, the environment or a prompt"],
                            ["never run input as code: parse it (JSON.parse for data) or map it to an allow-listed action"]))
            continue
        level, evidence = "WARN", ["call: %s(%s)" % (name, "<literal>" if literal else "<non-literal>")]
        if jf.generated:
            level = "INFO"
            evidence.append("generated or minified file: reported, not scored")
        out.append(_hit(jf, "exec.dynamic", level, tok,
                        "%s() runs a string as code" % name if literal else "%s() runs code built at runtime" % name,
                        evidence, ["replace it with a parser, a lookup table or JSON.parse"]))
    if jf.jsx and not jf.generated:
        for t in jf.tokens:
            if t.kind == "string":
                m = JSX_CODE.search(t.value)
                if m:
                    out.append(finding("exec.dynamic", "INFO", "%s:%d" % (jf.rel, t.line), JSX_TEXT_SUMMARY,
                                       ["name: %s" % m.group(1), "an apostrophe in JSX text can hide code from the lexer"],
                                       ["escape the apostrophe in the text (&apos;) so the code after it is analysed"]))
    return out


# ---- exec.shell ------------------------------------------------------------------------------------------------------

SHELL_ALWAYS = frozenset({"exec", "execSync"})
SHELL_OPTION = frozenset({"spawn", "spawnSync", "execFile", "execFileSync"})


def _shell_true(args):
    for a in args:
        v = jsts.props(a).get("shell")
        if v and len(v) == 1 and v[0].kind == "keyword" and v[0].value == "true":
            return True
    return False


def scan_exec_shell(jf):
    """Commands run through a shell by child_process (exec, execSync, or spawn/execFile with shell: true) or shelljs;
    FAIL when the command is built from input, a template with an expression, or a `+` concatenation."""
    out = []
    for s in jf.sites:
        hit = jf.module_call(s)
        if not hit or not s.call.args:
            continue
        module, name = hit
        if module == "child_process" and (name in SHELL_ALWAYS or (name in SHELL_OPTION and _shell_true(s.call.args))):
            how = name + ("(shell: true)" if name in SHELL_OPTION else "")
        elif module == "shelljs" and name == "exec":
            how = "shelljs.exec"
        else:
            continue
        cmd = s.call.args[0]
        built = jf.is_source(cmd) or any(_is_template_with_expr(t) for t in cmd) or _concatenated(cmd)
        tok = jf.sink(s)
        if built:
            out.append(_hit(jf, "exec.shell", "FAIL", tok, "%s runs a shell command built from input, env or network" % how,
                            ["call: %s" % how,
                             "the command text is read from a request, the URL or the environment, or is built by "
                             "joining text (a template expression or +)"],
                            ["pass an argument list to execFile or spawn without shell: true",
                             "validate the value against an allow-list"]))
        else:
            out.append(_hit(jf, "exec.shell", "WARN", tok, "%s runs a command through the shell" % how,
                            ["call: %s" % how], ["pass an argument list to execFile or spawn without shell: true"]))
    return out


# ---- deser.unsafe ----------------------------------------------------------------------------------------------------

DESERIALISERS = {"node-serialize": frozenset({"unserialize"}), "serialize-to-js": frozenset({"unserialize", "deserialize"})}


def scan_deser(jf):
    """node-serialize / serialize-to-js unserialize (it runs functions hidden in the data); eval(JSON.parse(...))."""
    out = []
    for s in jf.sites:
        hit = jf.module_call(s)
        if hit and hit[1] in DESERIALISERS.get(hit[0], ()):
            out.append(_hit(jf, "deser.unsafe", "WARN", jf.sink(s),
                            "%s.%s can run code hidden in the data" % hit, ["call: %s.%s" % hit],
                            ["load only data you created, or use JSON.parse"]))
        elif not s.member and s.callee in EVAL_CALLEES and s.call.args:
            a = s.call.args[0]
            if len(a) >= 3 and a[0].value == "JSON" and jsts._punct(a[1], ".") and a[2].value == "parse":
                out.append(_hit(jf, "deser.unsafe", "WARN", jf.sink(s), "eval(JSON.parse(...)) runs data as code",
                                ["call: eval(JSON.parse(<data>))"], ["use the value JSON.parse returns; do not eval it"]))
    return out


# ---- net.egress / net.bind_all ---------------------------------------------------------------------------------------

AXIOS_VERBS = frozenset({"get", "post", "put", "patch", "delete", "head", "options", "request"})
EGRESS_CALLS = frozenset({"fetch", "axios", "got", "navigator.sendBeacon", "$.ajax", "jQuery.ajax", "http.request",
                          "http.get", "https.request", "https.get"})
EGRESS_NEW = frozenset({"WebSocket", "EventSource"})


def _xhr_names(jf):
    """Names assigned `new XMLHttpRequest()`."""
    names = set()
    sig = jf.sig
    for s in jf.sites:
        if s.new and s.callee == "XMLHttpRequest" and s.start >= 3 and jsts._punct(sig[s.start - 2], "="):
            target = _target(sig, jf.mate, s.start - 3)
            if target:
                names.add(target)
    return names


def _egress_name(s, xhr):
    if s.member:
        return None
    c = _global(s.callee)
    if s.new:
        return c if c in EGRESS_NEW else None
    if c in EGRESS_CALLS or (c.startswith("axios.") and c[6:] in AXIOS_VERBS):
        return c
    if s.callee.endswith(".open") and s.callee[:-5] in xhr:
        return "XMLHttpRequest.open"
    return None


def _egress_target(args):
    """(url text, token) of the first literal URL among the call's arguments, else (None, None)."""
    for a in args:
        cand = None
        if a and a[0].kind in ("string", "template"):
            cand = a[0]
        elif a and jsts._punct(a[0], "{"):
            u = jsts.props(a).get("url")
            if u and u[0].kind in ("string", "template"):
                cand = u[0]
        if cand is not None:
            m = URL.search(cand.value[1:-1])
            if m:
                return m.group(), cand
    return None, None


def scan_egress(jf):
    """Every URL and IP literal, and every fetch / axios / http(s) / got / XMLHttpRequest / WebSocket / EventSource /
    sendBeacon / $.ajax call site: the egress inventory. The levels are the Python rule (scanners.classify_host); a
    call that names a literal URL is graded by it, and that URL is not listed a second time."""
    out = []
    used = set()
    xhr = _xhr_names(jf)
    for s in jf.sites:
        name = _egress_name(s, xhr)
        if not name:
            continue
        shown = ("new " if s.new else "") + name
        url, tok = _egress_target(s.call.args)
        if url:
            used.add((id(tok), url))
            level, why = classify_host(*_url_host(url))
            target = redact_url(url)
            out.append(_hit(jf, "net.egress", level, jf.sink(s), "network call %s to %s (%s)" % (shown, target[:80], why),
                            ["kind: call", "target: %s" % target[:200], "why: %s" % why, "call: %s" % shown],
                            ["use https", "confirm this destination is expected"] if level == "WARN" else []))
        else:
            first = s.call.args[0] if s.call.args else []
            lit = _literal_text(first[0]) if len(first) == 1 else None
            why = "relative URL (same origin)" if lit and lit.startswith("/") and not lit.startswith("//") \
                else classify_host("", "")[1]
            out.append(_hit(jf, "net.egress", "INFO", jf.sink(s), "network call %s (%s)" % (shown, why),
                            ["kind: call", "target: %s" % shown, "why: %s" % why], []))
    for t in jf.tokens:
        if t.kind not in ("string", "template"):
            continue
        text = t.value[1:-1]
        for url in URL.findall(text):
            if (id(t), url) in used:
                continue
            level, why = classify_host(*_url_host(url))
            url = redact_url(url)  # the report says where, never with what: a URL can be the credential
            out.append(_hit(jf, "net.egress", level, t, "URL literal %s (%s)" % (url[:80], why),
                            ["kind: url", "target: %s" % url[:200], "why: %s" % why],
                            ["use https", "confirm this destination is expected"] if level == "WARN" else []))
        lit = _literal_text(t)
        if lit is None:
            continue
        host = lit.rsplit(":", 1)[0] if lit.count(":") == 1 else lit
        ip = _ip(host) if re.fullmatch(r"[0-9a-fA-F:.\[\]]{3,}(?::\d+)?", lit) and "." in lit else None
        if ip is not None and lit not in _ALL_INTERFACES and str(ip) != "0.0.0.0":
            level, why = classify_host("", host)
            out.append(_hit(jf, "net.egress", level, t, "IP literal %s (%s)" % (lit, why),
                            ["kind: ip", "target: %s" % lit, "why: %s" % why],
                            ["use a hostname from configuration"] if level == "WARN" else []))
    return out


def scan_bind_all(jf):
    """A server bound to every interface (0.0.0.0 or ::) instead of loopback."""
    out = []
    for s in jf.sites:
        last = s.callee.rsplit(".", 1)[-1]
        if not (last == "listen" or last == "createServer" or (s.new and last == "Server")):
            continue
        for a in s.call.args:
            lit = jsts.literal(a) if last == "listen" else None
            host = jsts.props(a).get("host")
            lit = lit if lit is not None else (jsts.literal(host) if host else None)
            if lit in _ALL_INTERFACES:
                out.append(_hit(jf, "net.bind_all", "WARN", jf.sink(s), "binds to all interfaces (%s)" % lit,
                                ["literal: %s" % lit], ["bind to 127.0.0.1 unless other machines must connect"]))
                break
    return dedupe(out)


# ---- tls.off ---------------------------------------------------------------------------------------------------------

TLS_KEYS = ("rejectUnauthorized", "strictSSL")


def _value_span(sig, mate, s):
    """The tokens of the value that starts at sig[s]: up to a `,` `;` or unmatched closer at depth 0."""
    j = s
    while j < len(sig):
        t = sig[j]
        if t.kind == "punct":
            if t.value in jsts._OPEN and mate[j] > j:
                j = mate[j] + 1
                continue
            if t.value in (",", ";") or t.value in jsts._CLOSE:
                break
        j += 1
    return sig[s:j]


def _tls_value(key, value, tok, jf, out):
    flat = [t.value for t in value]
    if flat == ["false"]:
        out.append(_hit(jf, "tls.off", "FAIL", tok, "%s: false switches certificate checks off" % key,
                        ["prop: %s: false" % key], ["remove it; point at a CA bundle if the certificate is private"]))
    elif key == "rejectUnauthorized" and value and flat not in (["true"], ["boolean"]):
        out.append(_hit(jf, "tls.off", "WARN", tok, "rejectUnauthorized is decided at runtime",
                        ["prop: rejectUnauthorized: <non-literal>"],
                        ["make sure it is never false in production; remove the option if it only exists for tests"]))


def scan_tls_off(jf):
    """Certificate checks switched off: rejectUnauthorized: false or strictSSL: false as a property, an assignment of
    either, process.env.NODE_TLS_REJECT_UNAUTHORIZED set to 0. FAIL when hard-coded; rejectUnauthorized set from a
    non-literal is WARN (decided at runtime)."""
    out = []
    sig, mate = jf.sig, jf.mate
    for k, t in enumerate(sig):
        if k == 0 or k + 2 >= len(sig) or not jsts._punct(sig[k + 1], ":") or not jsts._punct(sig[k - 1], "{", ","):
            continue
        key = t.value.strip("'\"") if t.kind in ("name", "string", "keyword") else None
        if key in TLS_KEYS:
            _tls_value(key, _value_span(sig, mate, k + 2), t, jf, out)
    for key in TLS_KEYS:
        for a in jsts.assigns(jf.tokens, key):
            _tls_value(key, a.value, jf.token_on(a.line, key), jf, out)
    for a in jsts.assigns(jf.tokens, "NODE_TLS_REJECT_UNAUTHORIZED"):
        v = a.value
        if len(v) == 1 and (_literal_text(v[0]) == "0" or (v[0].kind == "number" and v[0].value == "0")):
            tok = jf.token_on(a.line, "NODE_TLS_REJECT_UNAUTHORIZED")
            out.append(_hit(jf, "tls.off", "FAIL", tok, "NODE_TLS_REJECT_UNAUTHORIZED=0 switches certificate checks off",
                            ["assign: %s = 0" % a.target.replace("'", "").replace('"', "")],
                            ["remove it; point NODE_EXTRA_CA_CERTS at a CA bundle if the certificate is private"]))
    return dedupe(out)


# ---- obfuscation -----------------------------------------------------------------------------------------------------

ZLIB = re.compile(r"zlib\.\w*(?:inflate|gunzip|brotliDecompress)\w*", re.I)
ESCAPES = re.compile(r"\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}")
CHARCODE_MIN = 20
ESCAPES_MIN = 5
DECODER_CALLEES = frozenset({"atob", "unescape", "decodeURIComponent", "String.fromCharCode"})


def _decoder(arg):
    """The name of the first decoder called inside an argument, else None."""
    for c in jsts.calls(arg):
        callee = _global(c.callee.replace("?.", "."))
        if callee in DECODER_CALLEES:
            return callee
        if callee == "Buffer.from" and any((jsts.literal(a) or "").lower() == "base64" for a in c.args[1:]):
            return "Buffer.from(base64)"
        if ZLIB.fullmatch(callee):
            return callee
    return None


def scan_obfuscation(jf):
    """eval / Function / a string timer of decoded or decompressed data (FAIL); long base64 or hex blobs, high-entropy
    literals, String.fromCharCode with 20 or more numbers, strings made of escapes (WARN)."""
    out = []
    for s, name, code_args in dynamic_calls(jf):
        found = next((d for d in (_decoder(a) for a in code_args) if d), None)
        if found:
            out.append(_hit(jf, "obfuscation", "FAIL", jf.sink(s), "%s() runs decoded or decompressed data" % name,
                            ["chain: %s(<decoder>(...))" % name,
                             "decoders: atob, Buffer.from base64, String.fromCharCode, unescape, decodeURIComponent, zlib"],
                            ["decode the payload offline and read what it does before running this"]))
    for s in jf.sites:
        if _global(s.callee) == "String.fromCharCode" and not s.member:
            numbers = sum(1 for a in s.call.args if len(a) == 1 and a[0].kind == "number")
            if numbers >= CHARCODE_MIN:
                out.append(_hit(jf, "obfuscation", "WARN", jf.sink(s), "String.fromCharCode builds text from %d numbers" % numbers,
                                ["kind: character codes", "count: %d" % numbers], ["decode it and check what it holds"]))
    for t in jf.tokens:
        if t.kind not in ("string", "template"):
            continue
        text = _literal_text(t)
        if text is not None and " " not in text and "\t" not in text:
            compact = text.replace("\n", "").replace("\r", "")
            if len(compact) >= BLOB_MIN and entropy(compact) > 3.0 and (_HEX.fullmatch(compact) or _B64.fullmatch(compact)):
                kind = "hex" if _HEX.fullmatch(compact) else "base64-like"
                out.append(_hit(jf, "obfuscation", "WARN", t, "%s blob of %d characters" % (kind, len(compact)),
                                ["kind: %s blob" % kind, "length: %d" % len(compact)], ["decode it and check what it holds"]))
                continue
            if (len(compact) >= TOKEN_MIN and "://" not in compact and _B64.fullmatch(compact)
                    and entropy(compact) >= TOKEN_ENTROPY and len(set(compact)) < 0.95 * len(compact)):
                out.append(_hit(jf, "obfuscation", "WARN", t, "high-entropy literal of %d characters" % len(compact),
                                ["kind: high-entropy literal", "entropy: %.2f bits/char" % entropy(compact)],
                                ["check whether it is a credential or an encoded payload"]))
                continue
        n = len(ESCAPES.findall(t.value))
        if n >= ESCAPES_MIN:
            out.append(_hit(jf, "obfuscation", "WARN", t, "string written as %d character escapes" % n,
                            ["kind: escaped string", "escapes: %d" % n], ["decode it and check what it holds"]))
    return dedupe(out)


# ---- fs.outside ------------------------------------------------------------------------------------------------------

FS_WRITERS = frozenset({"writeFile", "writeFileSync", "appendFile", "appendFileSync", "createWriteStream", "rm", "rmSync",
                        "rmdir", "rmdirSync", "unlink", "unlinkSync", "mkdir", "mkdirSync", "rename", "renameSync"})
FS_MODULES = frozenset({"fs", "fs/promises"})
HOME_EXPR = re.compile(r"(?:os\.homedir\(\)|process\.env\.(?:HOME|USERPROFILE)(?![\w$]))")
HOME_VARS = re.compile(r"%(?:APPDATA|LOCALAPPDATA|USERPROFILE)%", re.I)
PATH_JOINERS = re.compile(r"(?:path|posix|win32)\.(?:join|resolve|normalize)")


def _path_prefix(arg):
    """The literal start of a path argument, "~" for one that starts at the user's home, None for anything else."""
    sig = [t for t in arg if t.kind != "comment"]
    if not sig:
        return None
    head = "".join(t.value for t in sig[:8])
    if HOME_EXPR.match(head):
        return "~"
    t = sig[0]
    if t.kind == "string":
        return t.value[1:-1]
    if t.kind == "template":
        text = t.value[1:-1]
        if text.startswith("${"):
            exprs = _template_exprs(t.value)
            return "~" if exprs and HOME_EXPR.match(exprs[0].strip()) else None
        return text.split("${", 1)[0]
    m = re.match(r"((?:\w+\.)+\w+)\(", head)
    if m and PATH_JOINERS.fullmatch(m.group(1)):
        mate = jsts._pairs(sig)
        k = len(m.group(1).split(".")) * 2 - 1
        if k < len(sig) and jsts._punct(sig[k], "(") and mate[k] > k:
            spans = jsts._split(sig, mate, k + 1, mate[k])
            if spans:
                return _path_prefix(sig[spans[0][0]:spans[0][1]])
    return None


def _outside_reason(prefix):
    if prefix and HOME_VARS.match(prefix):
        return "home directory"
    return outside(prefix) if prefix else None


def scan_fs_outside(jf):
    """Writes, deletes and moves aimed at absolute paths, ~, the home directory or ..-escapes, through fs / fs/promises."""
    out = []
    for s in jf.sites:
        hit = jf.module_call(s)
        if not hit or hit[0] not in FS_MODULES or hit[1] not in FS_WRITERS or not s.call.args:
            continue
        targets = s.call.args[:2] if hit[1] in ("rename", "renameSync") else s.call.args[:1]
        for arg in targets:
            prefix = _path_prefix(arg)
            why = _outside_reason(prefix)
            if why:
                out.append(_hit(jf, "fs.outside", "WARN", jf.sink(s),
                                "writes outside the project: %s (%s)" % (prefix[:60], why),
                                ["call: fs.%s" % hit[1], "path starts: %s" % prefix[:120]],
                                ["write under the project or a path the user passes in"]))
                break
    return out


# ---- privacy.pii_log -------------------------------------------------------------------------------------------------

LOG_OBJECTS = frozenset({"console", "logger", "log"})


def _secret_name(args):
    """The first name token among the arguments that matches SECRET_NAME, else None."""
    for a in args:
        for k, t in enumerate(a):
            if t.kind != "name" or not SECRET_NAME.search(t.value):
                continue
            if k + 1 < len(a) and jsts._punct(a[k + 1], ":") and (k == 0 or jsts._punct(a[k - 1], "{", ",")):
                continue  # an object key, not a value
            return t.value
    return None


def scan_pii_log(jf):
    """A name that holds a secret (password, api key, token ...) passed to console.* / logger.* / log.*. Only `name`
    tokens count: a string never matches."""
    out = []
    for s in jf.sites:
        parts = s.callee.split(".")
        if s.member or len(parts) < 2 or parts[-2] not in LOG_OBJECTS:
            continue
        name = _secret_name(s.call.args)
        if name:
            sink = ".".join(parts[-2:])
            out.append(_hit(jf, "privacy.pii_log", "WARN", jf.sink(s),
                            "a secret (%s) is written to a log or printed (%s)" % (name, sink),
                            ["name: %s" % name, "sink: %s" % sink],
                            ["log an id or a masked value instead", "logs are copied, shipped and kept far longer than the data itself"]))
    return out


# ---- dom.html_sink ---------------------------------------------------------------------------------------------------

TRUST_BYPASS = frozenset({"bypassSecurityTrustHtml", "bypassSecurityTrustScript", "bypassSecurityTrustResourceUrl",
                          "bypassSecurityTrustUrl"})
HTML_ASSIGN = ("innerHTML", "outerHTML")
JQUERY_ROOTS = frozenset({"$", "jQuery"})


def _html_hit(jf, tok, sink, value):
    """A dom.html_sink finding for `value` reaching `sink`; nothing when the value is a literal."""
    if not value or jsts.literal(value) is not None:
        return None
    if jf.is_source(value):
        return _hit(jf, "dom.html_sink", "FAIL", tok, "%s puts text from the request or the page into the page as HTML" % sink,
                    ["sink: %s" % sink, "value: read from a request, the URL or the page"],
                    ["set textContent instead, or sanitize the text with a library such as DOMPurify first"])
    return _hit(jf, "dom.html_sink", "WARN", tok, "%s puts a non-literal value into the page as HTML" % sink,
                ["sink: %s" % sink, "value: <non-literal>"],
                ["set textContent instead, or sanitize the text with a library such as DOMPurify first"])


def _receiver_root(sig, mate, e):
    """The first name of the call chain that ends at sig[e] (`$('#a').find('b')` -> "$"), else None."""
    j = e
    while j >= 0:
        t = sig[j]
        if jsts._punct(t, ")", "]") and mate[j] >= 0:
            j = mate[j] - 1
        elif jsts._is_name(t):
            if j >= 2 and jsts._punct(sig[j - 1], *jsts._DOTS):
                j -= 2
            else:
                return t.value
        else:
            return None
    return None


def _react_html(sig, mate, j, attribute):
    """The tokens of the __html value of `dangerouslySetInnerHTML={{ __html: v }}` (attribute) or `: { __html: v }`;
    the whole expression of `={v}`. None when there are no braces to read."""
    if not (jsts._punct(sig[j], "{") and mate[j] > j):
        return None
    inner = j + 1 if attribute else j
    if jsts._punct(sig[inner], "{") and mate[inner] > inner:
        return jsts.props(sig[inner:mate[inner] + 1]).get("__html")
    return sig[j + 1:mate[j]] if attribute else None


def scan_html_sink(jf):
    """Text put into the page as HTML: .innerHTML / .outerHTML assignment, insertAdjacentHTML, document.write(ln),
    React dangerouslySetInnerHTML, jQuery $(...).html(v), Angular's bypassSecurityTrust* calls. Nothing for a literal;
    WARN for anything else; FAIL when the value is read from a request, the URL or the page."""
    out = []
    sig, mate = jf.sig, jf.mate
    for member in HTML_ASSIGN:
        for a in jsts.assigns(jf.tokens, member):
            out.append(_html_hit(jf, jf.token_on(a.line, member), "." + member, a.value))
    for k, t in enumerate(sig):
        if jsts._punct(t, "+=") and k >= 2 and sig[k - 1].kind == "name" and sig[k - 1].value in HTML_ASSIGN \
                and jsts._punct(sig[k - 2], *jsts._DOTS):
            out.append(_html_hit(jf, sig[k - 1], "." + sig[k - 1].value, sig[k + 1:jsts._statement_end(sig, mate, k + 1)]))
        elif t.kind == "name" and t.value == "dangerouslySetInnerHTML" and k + 2 < len(sig) \
                and jsts._punct(sig[k + 1], "=", ":"):
            out.append(_html_hit(jf, t, "dangerouslySetInnerHTML", _react_html(sig, mate, k + 2, jsts._punct(sig[k + 1], "="))))
    for s in jf.sites:
        last = s.callee.rsplit(".", 1)[-1]
        args = s.call.args
        tok = jf.sink(s)
        if last == "insertAdjacentHTML" and len(args) >= 2:
            out.append(_html_hit(jf, tok, "insertAdjacentHTML()", args[1]))
        elif last in ("write", "writeln") and not s.member and s.callee.split(".")[-2:-1] == ["document"] and args:
            out.append(_html_hit(jf, tok, "document.%s()" % last, _flat(args) if len(args) > 1 else args[0]))
        elif last == "html" and len(args) == 1:
            root = _receiver_root(sig, mate, s.start - 2) if s.member and s.start >= 2 \
                else s.callee.split(".")[0]
            if root and (root in JQUERY_ROOTS or root.startswith("$")):
                out.append(_html_hit(jf, tok, ".html()", args[0]))
        elif last in TRUST_BYPASS and args:
            out.append(_html_hit(jf, tok, "%s()" % last, args[0]))
    return dedupe([f for f in out if f])


# ---- registry --------------------------------------------------------------------------------------------------------

JS_SCANNERS = [
    ("exec.dynamic", scan_exec_dynamic),
    ("exec.shell", scan_exec_shell),
    ("deser.unsafe", scan_deser),
    ("net.egress", scan_egress),
    ("net.bind_all", scan_bind_all),
    ("tls.off", scan_tls_off),
    ("obfuscation", scan_obfuscation),
    ("fs.outside", scan_fs_outside),
    ("privacy.pii_log", scan_pii_log),
    ("dom.html_sink", scan_html_sink),
]


def scan_js(jf, crashed=None):
    """Every JS scanner over one file. A scanner that raises yields one check.crashed WARN (weight 0), not a crash;
    when crashed is a list, (code, finding) is appended to it. A generated file runs only GENERATED_CODES."""
    out = []
    for code, fn in JS_SCANNERS:
        if jf.generated and code not in GENERATED_CODES:
            continue
        got = run_check(code, lambda _s, _c, fn=fn: fn(jf), None, None, node=jf.rel)
        if isinstance(got, dict) and crashed is not None:
            crashed.append((code, got))
        out.extend(got if isinstance(got, list) else [got])
    return out


# ---- selftest --------------------------------------------------------------------------------------------------------

def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if "--selftest" in argv:
        return selftest()
    sys.stderr.write("usage: python -m code_guardian.scanners_js --selftest\n")
    return 2


def _got(text, flavour="js", generated=False):
    """[(code, level, line)] in line order."""
    fs = scan_js(JsFile("t.js", text, flavour, generated=generated))
    return sorted(((f["code"], f["level"], int(f["node"].rsplit(":", 1)[1])) for f in fs), key=lambda g: (g[2], g[0], g[1]))


def selftest():
    h = "http" + "://"
    blob = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo" * 7
    boom = []
    saved = list(JS_SCANNERS)
    try:
        JS_SCANNERS[:] = [("exec.dynamic", lambda _jf: 1 / 0)]
        crashed = []
        crash = scan_js(JsFile("t.js", "eval(x);\n", "js"), crashed=crashed)
        boom = [(f["code"], f["level"]) for f in crash], [c for c, _ in crashed]
    finally:
        JS_SCANNERS[:] = saved
    checks = [
        ("registry_has_ten_codes", len(JS_SCANNERS) == 10 and len({c for c, _ in JS_SCANNERS}) == 10),
        ("crash_is_one_warn", boom == ([("check.crashed", "WARN")], ["exec.dynamic"])),
        ("eval_levels", _got("eval(code);\neval(req.query.c);\neval('1');\n") ==
         [("exec.dynamic", "WARN", 1), ("exec.dynamic", "FAIL", 2), ("exec.dynamic", "WARN", 3)]),
        ("method_eval_is_not_eval", _got("holder.eval(x);\nconst o = { eval: 1 };\n") == []),
        ("sink_in_string_template_comment_regex", _got("const a = 'eval(x)';\nconst b = `el.innerHTML = y`;\n"
                                                       "// eval(location.hash)\nconst r = /eval\\(x\\)/;\n") == []),
        ("string_timer", _got("setTimeout('go()', 1);\nsetTimeout(go, 1);\n") == [("exec.dynamic", "WARN", 1)]),
        ("vm_needs_import", _got("vm.runInContext(c);\n") == [] and
         _got("const vm = require('node:vm');\nvm.runInContext(c);\n") == [("exec.dynamic", "WARN", 2)]),
        ("shell_is_the_child_process_binding", _got("import { exec } from 'child_process';\nexec(cmd);\nre.exec(s);\n") ==
         [("exec.shell", "WARN", 2)]),
        ("shell_fail_forms", [g[1] for g in _got("const cp = require('child_process');\ncp.exec(`ls ${d}`);\n"
                                                 "cp.execSync('ls ' + d);\ncp.exec(req.query.c);\ncp.exec('ls');\n")] ==
         ["FAIL", "FAIL", "FAIL", "WARN"]),
        ("spawn_shell_true", _got("const cp = require('child_process');\ncp.spawn('a', { shell: true });\n"
                                  "cp.spawn('a', { shell: false });\n") == [("exec.shell", "WARN", 2)]),
        ("deser_needs_import", _got("unserialize(d);\n") == [] and
         _got("const s = require('node-serialize');\ns.unserialize(d);\n") == [("deser.unsafe", "WARN", 2)]),
        ("egress_levels", [g[1] for g in _got("fetch('%sstatic.cg-fixture.net/x');\nfetch('https://example.com/');\n"
                                              "fetch(u);\nconst ip = '8.8.8.8';\n" % h)] == ["WARN", "INFO", "INFO", "WARN"]),
        ("egress_redacts_query", "zz9" not in repr(scan_js(JsFile("t.js", "fetch('https://example.com/x?k=zz9');\n", "js")))),
        ("bind_all", _got("app.listen(80, '0.0.0.0');\nhttps.createServer({ host: '::' }, h);\napp.listen(81, 'localhost');\n") ==
         [("net.bind_all", "WARN", 1), ("net.bind_all", "WARN", 2)]),
        ("tls_off", _got("const a = { rejectUnauthorized: false };\nconst b = { rejectUnauthorized: v };\n"
                         "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n") ==
         [("tls.off", "FAIL", 1), ("tls.off", "WARN", 2), ("tls.off", "FAIL", 3)]),
        ("obfuscation_decoder_chain", _got("eval(atob(p));\n") == [("exec.dynamic", "WARN", 1), ("obfuscation", "FAIL", 1)]),
        ("obfuscation_blob_and_escapes", [g[1] for g in _got("const b = '%s';\nconst e = '\\x61\\x62\\x63\\x64\\x65';\n" % blob)] ==
         ["WARN", "WARN"]),
        ("fs_outside", _got("const fs = require('fs');\nfs.writeFileSync('/etc/x', d);\nfs.rmSync('out/x');\n"
                            "fs.mkdirSync(path.join(os.homedir(), 'x'));\n") ==
         [("fs.outside", "WARN", 2), ("fs.outside", "WARN", 4)]),
        ("pii_log_names_only", _got("console.log(password);\nconsole.log('password');\nconsole.log(userName);\n") ==
         [("privacy.pii_log", "WARN", 1)]),
        ("html_sink_levels", _got("el.innerHTML = body;\nel.innerHTML = location.hash;\nel.innerHTML = '<b>x</b>';\n") ==
         [("dom.html_sink", "WARN", 1), ("dom.html_sink", "FAIL", 2)]),
        ("html_sink_calls", [g[1] for g in _got("el.insertAdjacentHTML('beforeend', x);\ndocument.write(location.search);\n"
                                                "$('#a').html(d);\nthis.s.bypassSecurityTrustHtml(v);\n")] ==
         ["WARN", "FAIL", "WARN", "WARN"]),
        ("html_sink_react", _got("const C = () => <p dangerouslySetInnerHTML={{ __html: post }} />;\n", "jsx") ==
         [("dom.html_sink", "WARN", 1)]),
        ("stray_backtick_evidence", STRAY_BACKTICK in scan_js(JsFile("t.jsx", "<p>a ` b</p>\n{eval(location.hash)}\n", "jsx"))[0]["evidence"]),
        ("jsx_two_apostrophes_info", _got("<p>Don't</p>{eval(location.hash)}<p>didn't</p>\n", "jsx") == [("exec.dynamic", "INFO", 1)]
         and _got("<p>Don't</p>{eval(location.hash)}<p>didn't</p>\n", "ts") == []),
        ("generated_subset", _got("eval('1');el.innerHTML=x;fetch('%sa.cg-fixture.net/');\n" % h, generated=True) ==
         [("exec.dynamic", "INFO", 1)]),
        ("generated_fail_stays", [g[:2] for g in _got("eval(atob(p));eval(req.query.x);\n", generated=True)] ==
         [("exec.dynamic", "FAIL"), ("exec.dynamic", "INFO"), ("obfuscation", "FAIL")]),
        ("handler_root_body_is_source", _got("app.post('/', (q, r) => { eval(q.body.x); });\n") == [("exec.dynamic", "FAIL", 1)]),
        ("comments_do_not_shift_roots", _got("app.post('/', (q, r) => { /* c */ eval(q.body.x); });\n") == [("exec.dynamic", "FAIL", 1)]),
    ]
    return summarize("scanners_js", checks)


if __name__ == "__main__":
    sys.exit(main())
