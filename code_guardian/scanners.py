"""The threat scanners: small pure functions over parsed source. Same input, same findings, every time.

Nothing here executes, imports or installs the scanned code: Python is read with ast, everything else with regular
expressions. Every finding is confidence LIKELY (the parse proves the code is there, not that it runs).

Public contract:
    PyFile(rel, raw, text)                     # parses once; raises SyntaxError/ValueError on unparseable source
    scan_secret_text(rel, text, python) -> [finding]   # every text file
    PY_SCANNERS = [(code, fn(PyFile) -> [finding])]    # Python files only
    scan_python(pf, crashed=None) -> [finding]         # every PY_SCANNERS entry; a crashing scanner is one WARN
    redact(text, strict=False) -> text                 # key shapes and email addresses masked (every output path)
    redact_url(url) -> url                             # credentials inside a URL literal masked
    key_values(line) -> [str]                          # the FAIL-level key-shaped values on a line (history scan)
    redact_report(obj) -> a redacted deep copy         # what every output path (JSON, text, Markdown, SARIF, MCP) uses
"""

import ast
import hashlib
import ipaddress
import math
import posixpath
import re
import sys
import warnings
from urllib.parse import urlsplit

from .finding import make_finding, run_check, summarize

# --------------------------------------------------------------------------- shared helpers


class PyFile:
    """One parsed Python file plus the lookups every scanner needs."""

    def __init__(self, rel, raw, text):
        self.rel = rel
        self.text = text
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            self.tree = ast.parse(raw, filename=rel)
        self.aliases = import_aliases(self.tree)
        self.parents = {}
        self.nodes = []
        for node in ast.walk(self.tree):
            self.nodes.append(node)
            for child in ast.iter_child_nodes(node):
                self.parents[child] = node
        self.bare_strings = {id(s.value) for s in self.nodes
                             if isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant)
                             and isinstance(s.value.value, str)}
        self._taint = {}

    def calls(self):
        return [n for n in self.nodes if isinstance(n, ast.Call)]

    def name(self, node):
        return dotted(node, self.aliases)

    def scope(self, node):
        while node is not None and not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.Module)):
            node = self.parents.get(node)
        return node

    def strings(self):
        """(node, text) for every str/bytes literal that is code, not a docstring or a bare string statement.
        An f-string is one literal, with {} where its expressions go."""
        out = []
        for n in self.nodes:
            if isinstance(n, ast.JoinedStr):
                out.append((n, "".join(v.value if isinstance(v, ast.Constant) else "{}" for v in n.values)))
            elif isinstance(n, ast.Constant) and isinstance(n.value, (str, bytes)):
                if id(n) in self.bare_strings or isinstance(self.parents.get(n), (ast.JoinedStr, ast.FormattedValue)):
                    continue
                out.append((n, n.value if isinstance(n.value, str) else n.value.decode("latin-1")))
        return out


def import_aliases(tree):
    """{local name: dotted target} for every import in the file (absolute imports only)."""
    out = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.asname:
                    out[a.asname] = a.name
                else:
                    head = a.name.split(".")[0]
                    out[head] = head
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for a in node.names:
                if a.name != "*":
                    out[a.asname or a.name] = node.module + "." + a.name
    return out


def dotted(node, aliases):
    """'subprocess.run' for sp.run(...) after `import subprocess as sp`; None when the base is not a plain name."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        return ".".join([aliases.get(node.id, node.id)] + parts[::-1])
    if isinstance(node, ast.Call) and parts:
        inner = dotted(node.func, aliases)
        return inner + "()." + ".".join(parts[::-1]) if inner else None
    return None


def is_builtin(pf, call, names):
    """call is a bare call to one of the builtins in names (not shadowed by an import)."""
    f = call.func
    return isinstance(f, ast.Name) and f.id in names and f.id not in pf.aliases


def literal(node):
    return isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes))


def arg(call, index, keyword=None):
    """Positional arg `index` or keyword `keyword` of a call, else None."""
    if keyword:
        for kw in call.keywords:
            if kw.arg == keyword:
                return kw.value
    return call.args[index] if len(call.args) > index else None


def kw_const(call, name):
    """(True, value) when the call passes name=<constant>, else (False, None)."""
    for kw in call.keywords:
        if kw.arg == name and isinstance(kw.value, ast.Constant):
            return True, kw.value.value
    return False, None


def entropy(s):
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


def node_of(pf, node):
    return "%s:%d" % (pf.rel, getattr(node, "lineno", 0))


def finding(code, level, where, summary, evidence=(), try_=()):
    return make_finding(code, "partial", level, where, summary, evidence=list(evidence), try_=list(try_))


def dedupe(findings):
    """One finding per (code, node, summary), first one kept."""
    seen = set()
    out = []
    for f in findings:
        key = (f["code"], f["node"], f["summary"])
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def tainted_names(pf, scope, is_source):
    """Names assigned (directly or through other tainted names) from an expression is_source accepts, in one scope."""
    key = (id(scope), is_source)
    if key in pf._taint:
        return pf._taint[key]
    names = set()
    assigns = [n for n in ast.walk(scope) if isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr))]
    for _ in range(8):
        before = len(names)
        for a in assigns:
            if a.value is not None and expr_tainted(pf, a.value, names, is_source):
                targets = a.targets if isinstance(a, ast.Assign) else [a.target]
                for t in targets:
                    names.update(n.id for n in ast.walk(t) if isinstance(n, ast.Name))
        if len(names) == before:
            break
    pf._taint[key] = names
    return names


def expr_tainted(pf, expr, names, is_source):
    return any(is_source(pf, n) or (isinstance(n, ast.Name) and n.id in names) for n in ast.walk(expr))


def flows_from(pf, expr, is_source):
    """expr is built from a source, directly or through names assigned from one in the same scope."""
    return expr_tainted(pf, expr, tainted_names(pf, pf.scope(expr), is_source), is_source)


# --------------------------------------------------------------------------- secret.key

KEY = r"[A-Za-z0-9_\-]{12,}"
# Numbered as in .github/workflows/privacy.yml's built-in list (patterns 5-12), so a hit names the same rule.
_KEY_PREFIXES = ((5, "sk- key", "sk-"), (6, "OpenRouter key", "sk-or-"), (7, "Tavily key", "tvly-"),
                 (8, "GitHub token", "ghp_"), (9, "GitHub fine-grained token", "github_pat_"),
                 (10, "NVIDIA key", "nvapi-"), (11, "Groq key", "gsk_"), (12, "Google API key", "AIza"))
KEY_PATTERNS = [(n, label, re.compile(r"(?<![A-Za-z0-9_\-])" + re.escape(prefix) + KEY))
                for n, label, prefix in _KEY_PREFIXES]
# Provider formats beyond the privacy list: (label, level, pattern with the body in group 1).
PROVIDER_PATTERNS = [(label, level, re.compile(rx)) for label, level, rx in (
    ("AWS access key ID", "FAIL", r"(?<![A-Za-z0-9])(?:AKIA|ASIA)([0-9A-Z]{16})(?![A-Za-z0-9])"),
    ("Stripe live key", "FAIL", r"(?<![A-Za-z0-9_\-])[sr]k_live_([A-Za-z0-9]{16,})"),
    ("Stripe test key", "INFO", r"(?<![A-Za-z0-9_\-])sk_test_([A-Za-z0-9]{16,})"),
    ("Slack token", "FAIL", r"(?<![A-Za-z0-9_\-])xox[abprs]-([A-Za-z0-9\-]{10,})"),
    ("Hugging Face token", "FAIL", r"(?<![A-Za-z0-9_\-])hf_([A-Za-z]{30,})(?![A-Za-z0-9_])"))]
# A 40-character AWS secret access key assigned to a name that contains both "aws" and "secret".
AWS_SECRET = re.compile(r"(?i)(?<![A-Za-z0-9_.\-])([A-Za-z0-9_.\-]*(?:aws[A-Za-z0-9_.\-]*secret|secret[A-Za-z0-9_.\-]*aws)"
                        r"[A-Za-z0-9_.\-]*)[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=])")
KEY_SHAPE = "kind: provider key shape"  # evidence marker: these stay as they are in test code (see report.py)
PRIVATE_KEY = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")
SECRET_NAME = re.compile(r"(?i)(?:^|_)(?:password|passwd|pwd|passphrase|secret|api_?key|secret_?key|access_?key|"
                         r"private_?key|client_?secret|auth_?token|access_?token)$")
# Any *_KEY / *_TOKEN name counts too, but only with a long, high-entropy value (CACHE_KEY = "users" is not a secret).
SECRET_SUFFIX = re.compile(r"(?i)_(?:key|token)$")
SECRET_TEXT = re.compile(r"(?i)\b(?:password|passwd|pwd|passphrase|secret|api_?key|client_?secret|auth_?token|"
                         r"access_?token)\b[\"']?\s*[:=]\s*[\"']([^\"'\s]{4,})[\"']")
_ENV_NAME = re.compile(r"[A-Z][A-Z0-9_]+")


EMAIL = re.compile(r"(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}")
_STRICT_TOKEN = re.compile(r"[A-Za-z0-9_\-+/=]{20,}")


def _token_like(value):
    """Letters and digits mixed, high entropy: reads like a generated credential (strict redaction only)."""
    return entropy(value) >= 3.5 and any(c.isdigit() for c in value) and any(c.isalpha() for c in value)


def redact(text, strict=False):
    """text with every API-key shape, AWS secret, private-key header and email address masked. strict=True (the
    evidence of secret and privacy findings) also masks any long high-entropy token. Idempotent; every output path
    goes through it (report.redact_report)."""
    text = str(text)
    for _n, _label, rx in KEY_PATTERNS:
        text = rx.sub("<redacted key>", text)
    for _label, _level, rx in PROVIDER_PATTERNS:
        text = rx.sub("<redacted key>", text)
    text = AWS_SECRET.sub(lambda m: m.group(0).replace(m.group(2), "<redacted key>"), text)
    text = PRIVATE_KEY.sub("<redacted key>", text)
    text = EMAIL.sub("<redacted email>", text)
    if strict:
        text = _STRICT_TOKEN.sub(lambda m: "<redacted value>" if _token_like(m.group(0)) else m.group(0), text)
    return text


REDACTED = "<redacted>"
# A URL can itself be the credential. Webhook hosts whose path is the secret: the prefix stays, the rest goes.
WEBHOOK_PREFIXES = (("hooks.slack.com", "/services/"), ("discord.com", "/api/webhooks/"),
                    ("ptb.discord.com", "/api/webhooks/"), ("canary.discord.com", "/api/webhooks/"),
                    ("discordapp.com", "/api/webhooks/"))


def _redact_query(query):
    """Every parameter value masked, the names kept: api_key, token, sig and X-Amz-Signature are the point, but a
    value is masked whatever it is called -- a report never needs one."""
    out = []
    for part in query.split("&"):
        name, sep, _value = part.partition("=")
        out.append(name + sep + REDACTED if sep else part)
    return "&".join(out)


def redact_url(url):
    """url with the credentials a URL can carry masked: the userinfo (`user:password@`), every query parameter
    value, the fragment, and the secret part of a known webhook path. Scheme, host, port, path and parameter names
    stay, so the egress inventory still says where the code talks to. Idempotent; not a scheme-aware parser --
    anything it cannot split comes back unchanged."""
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
    except ValueError:
        return url
    if not parts.scheme or not parts.netloc:
        return url
    netloc = parts.netloc
    if "@" in netloc:
        netloc = REDACTED + "@" + netloc.rsplit("@", 1)[1]
    path = parts.path
    for webhook_host, prefix in WEBHOOK_PREFIXES:
        if host == webhook_host and path.startswith(prefix) and path != prefix + REDACTED:
            path = prefix + REDACTED
            break
    out = "%s://%s%s" % (parts.scheme, netloc, path)
    if parts.query:
        out += "?" + _redact_query(parts.query)
    if parts.fragment:
        out += "#" + REDACTED
    return out


SENSITIVE_PREFIXES = ("secret.", "privacy.")  # their evidence is redacted strictly, in every format


def redact_report(obj):
    """A redacted deep copy of a report (or any JSON value): every string through redact(); the evidence of secret
    and privacy findings through redact(strict=True). Dict keys are left alone. The input is not modified."""
    if isinstance(obj, dict):
        out = {k: redact_report(v) for k, v in obj.items()}
        if str(obj.get("code", "")).startswith(SENSITIVE_PREFIXES) and isinstance(obj.get("evidence"), list):
            out["evidence"] = [redact(e, strict=True) for e in obj["evidence"]]
        return out
    if isinstance(obj, (list, tuple)):
        return [redact_report(v) for v in obj]
    return redact(obj) if isinstance(obj, str) else obj


SELF_NAMED = frozenset({"secret", "password", "passwd", "pass", "pwd", "token", "apikey", "api_key", "username", "user"})
PLACEHOLDER_WORDS = frozenset({"mock", "fake", "dummy", "example", "placeholder", "sample", "redacted", "test",
                               "testing", "notreal", "changeit"})
PLACEHOLDER_MARKS = ("<", ">", "{", "}", "$", "%s", "***", "xxx", "XXX", "...")


def _real_secret(value):
    """A literal that reads like a credential, not a placeholder, an env-var name or an empty default. A value that
    calls itself fake ("sk-ant-mock", "dummy-password") is not reported."""
    if len(value) < 4 or any(c.isspace() for c in value) or _ENV_NAME.fullmatch(value):
        return False
    if any(m in value for m in PLACEHOLDER_MARKS):
        return False
    if PLACEHOLDER_WORDS & set(re.split(r"[^a-z]+", value.lower())) or value.lower() in SELF_NAMED:
        return False
    return len(set(value)) > 1


def _calls_itself_fake(body):
    """A provider-shaped body that spells out a placeholder word anywhere (AKIAIOSFODNN7EXAMPLE) or is masked."""
    low = body.lower()
    return any(m in body for m in PLACEHOLDER_MARKS) or any(w in low for w in PLACEHOLDER_WORDS if len(w) >= 4)


def _high_entropy(value):
    """Long, mixed letters and digits, high entropy, and not an alphabet: reads like a generated token."""
    return (len(value) >= 20 and entropy(value) >= 4.0 and "://" not in value and not any(c.isspace() for c in value)
            and any(c.isdigit() for c in value) and any(c.isalpha() for c in value) and len(set(value)) < len(value))


TEST_VALUE = "looks like a test value"  # evidence prefix of a key-shaped value graded INFO by test_value_reason
_RUN = re.compile(r"(.)\1{5}")  # six or more of one character in a row


def test_value_reason(prefix, body):
    """Why a key-shaped value reads like a test value, or None when it reads like a real one. `body` is what follows
    the key's prefix; a value that has a reason is reported at INFO instead of FAIL. Pure: the value is only looked at.

    V1: the body spells out a placeholder word of four or more letters (any case): "spells out fake".
    V2: the body is low-variety: at most 4 distinct characters ("is mostly one character"), a run of 6 or more of one
    character ("repeats one character"), or 8 characters in a row each one code point above the last, like 12345678
    or abcdefgh ("counts up"). A generated key is mixed, so none of these fire on one by chance.

    `prefix` is the key's own prefix. GitHub's classic tokens ("ghp_") end in a CRC32 checksum in Base62, but GitHub's
    own description of the format
    (https://github.blog/engineering/platform-security/behind-githubs-new-authentication-token-formats/)
    does not fix the Base62 alphabet or the characters the checksum covers, so no checksum exemption is written:
    every prefix is graded by its body alone."""
    low = body.lower()
    for word in sorted(w for w in PLACEHOLDER_WORDS if len(w) >= 4):
        if word in low:
            return "spells out %s" % word
    if len(set(body)) <= 4:
        return "is mostly one character"
    if _RUN.search(body):
        return "repeats one character"
    up = 1
    for a, b in zip(body, body[1:]):
        up = up + 1 if ord(b) == ord(a) + 1 else 1
        if up >= 8:
            return "counts up"
    return None


def _key_reason(value):
    """test_value_reason for a KEY_PATTERNS match: the longest known prefix is split off (sk-or-... is an OpenRouter
    key, whichever of the two patterns matched it)."""
    prefix = max((p for _n, _l, p in _KEY_PREFIXES if value.startswith(p)), key=len)
    return test_value_reason(prefix, value[len(prefix):])


def _secret(where, label, length, level="FAIL", shape=False, reason=None):
    evidence = ["matched: %s" % label, "length: %d characters" % length] + ([KEY_SHAPE] if shape else [])
    if reason:
        return finding("secret.key", "INFO", where, "%s in the source (%s; value redacted)" % (label, TEST_VALUE),
                       evidence + ["%s: %s" % (TEST_VALUE, reason)],
                       ["keep test values out of the source too, or make them obviously fake"])
    if level == "INFO":
        return finding("secret.key", "INFO", where, "%s in the source (a test-mode key; value redacted)" % label,
                       evidence, ["keep test keys out of the source too; they still identify the account"])
    return finding("secret.key", level, where, "%s in the source; value redacted" % label, evidence,
                   ["move it to an environment variable or a secret store",
                    "rotate it: it is in this file's history"])


def scan_secret_text(rel, text, python):
    """API-key shapes and private-key blocks in any text file; quoted password literals outside Python."""
    out = []
    for lineno, line in enumerate(text.splitlines(), 1):
        where = "%s:%d" % (rel, lineno)
        hits = []
        for n, label, rx in KEY_PATTERNS:
            for m in rx.finditer(line):
                reason = _key_reason(m.group(0))
                hits.append(("%s shape (privacy pattern %d)" % (label, n), len(m.group(0)),
                             "INFO" if reason else "FAIL", True, reason))
        for label, level, rx in PROVIDER_PATTERNS:
            for m in rx.finditer(line):
                if not _calls_itself_fake(m.group(1)):
                    reason = test_value_reason("", m.group(1)) if level == "FAIL" else None
                    hits.append(("%s shape" % label, len(m.group(0)), "INFO" if reason else level, level == "FAIL",
                                 reason))
        for m in AWS_SECRET.finditer(line):
            if not _calls_itself_fake(m.group(2)):
                hits.append(("AWS secret access key assigned to %r" % m.group(1), 40, "FAIL", False, None))
        if PRIVATE_KEY.search(line):
            hits.append(("private-key block", len(line.strip()), "FAIL", False, None))
        if not python:
            for m in SECRET_TEXT.finditer(line):
                if _real_secret(m.group(1)):
                    hits.append(("password-like literal", len(m.group(1)), "FAIL", False, None))
        if hits:
            hits.sort(key=lambda h: h[2] != "FAIL")  # a FAIL on the line wins over a test-mode INFO
            out.append(_secret(where, *hits[0]))
    return out


def key_values(line):
    """The key-shaped values on one line that secret.key reports at FAIL (for the history scan, which compares them
    with the working tree and never prints them)."""
    out = [m.group(0) for _n, _label, rx in KEY_PATTERNS for m in rx.finditer(line)]
    out += [m.group(0) for _label, level, rx in PROVIDER_PATTERNS for m in rx.finditer(line)
            if level == "FAIL" and not _calls_itself_fake(m.group(1))]
    out += [m.group(2) for m in AWS_SECRET.finditer(line) if not _calls_itself_fake(m.group(2))]
    out += [m.group(0) for m in PRIVATE_KEY.finditer(line)]
    return out


def scan_password_literals(pf):
    """`password = "<literal>"`, password="<literal>" keyword args and {"password": "<literal>"} in Python; any
    *_KEY / *_TOKEN name when the literal is long and high-entropy."""
    out = []
    for n in pf.nodes:
        pairs = []
        if isinstance(n, (ast.Assign, ast.AnnAssign)) and n.value is not None:
            for t in (n.targets if isinstance(n, ast.Assign) else [n.target]):
                name = t.id if isinstance(t, ast.Name) else t.attr if isinstance(t, ast.Attribute) else None
                pairs.append((name, n.value))
        elif isinstance(n, ast.keyword) and n.arg:
            pairs.append((n.arg, n.value))
        elif isinstance(n, ast.Dict):
            pairs.extend((k.value, v) for k, v in zip(n.keys, n.values) if isinstance(k, ast.Constant) and isinstance(k.value, str))
        for name, value in pairs:
            if not (name and isinstance(value, ast.Constant) and isinstance(value.value, str) and _real_secret(value.value)):
                continue
            if SECRET_NAME.search(name):
                out.append(_secret(node_of(pf, value), "password-like literal assigned to %r" % name, len(value.value)))
            elif SECRET_SUFFIX.search(name) and _high_entropy(value.value) and not _calls_itself_fake(value.value):
                out.append(_secret(node_of(pf, value), "high-entropy literal assigned to %r" % name, len(value.value)))
    return out


# --------------------------------------------------------------------------- exec.dynamic

def _code_text(pf, expr):
    """The expression that holds the code text: exec(compile(src, filename, mode)) runs src, not the filename."""
    while isinstance(expr, ast.Call) and is_builtin(pf, expr, ("compile",)) and expr.args:
        expr = expr.args[0]
    return expr


def scan_exec_dynamic(pf):
    """eval/exec/compile on anything but a literal (FAIL when eval/exec run input, argv, request data or the
    environment); __import__ with a computed name."""
    out = []
    for c in pf.calls():
        if is_builtin(pf, c, ("eval", "exec", "compile")) and c.args and not literal(c.args[0]):
            name = c.func.id
            if name != "compile" and flows_from(pf, _code_text(pf, c.args[0]), is_input_source):
                out.append(finding("exec.dynamic", "FAIL", node_of(pf, c), "%s() runs code typed by the user" % name,
                                   ["call: %s(<input>)" % name,
                                    "the code text flows from input(), sys.argv, request data, os.environ or a network read"],
                                   ["never run input as code: parse it (ast.literal_eval for data) or map it to an "
                                    "allow-listed action"]))
            else:
                out.append(finding("exec.dynamic", "WARN", node_of(pf, c), "%s() runs code built at runtime" % name,
                                   ["call: %s(<non-literal>)" % name],
                                   ["replace it with a parser or a lookup table (ast.literal_eval for data)"]))
        elif is_builtin(pf, c, ("__import__",)) and c.args and not literal(c.args[0]):
            out.append(finding("exec.dynamic", "WARN", node_of(pf, c), "__import__() loads a module named at runtime",
                               ["call: __import__(<non-literal>)"], ["import the module by name, or check it against an allow-list"]))
    return out


# --------------------------------------------------------------------------- exec.shell

SHELL_ALWAYS = frozenset({"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput",
                          "commands.getoutput", "commands.getstatusoutput", "asyncio.create_subprocess_shell"})
SUBPROCESS = frozenset({"subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output",
                        "subprocess.Popen"})
SOURCE_CALLS = frozenset({"input", "os.getenv", "os.environ.get", "os.getenvb", "sys.stdin.read", "sys.stdin.readline"})
SOURCE_PREFIXES = ("os.environ", "sys.argv", "sys.stdin", "flask.request", "requests.", "httpx.", "urllib.request.",
                   "socket.", "aiohttp.")
REQUEST_ATTRS = frozenset({"args", "form", "GET", "POST", "json", "data", "values", "files", "cookies", "headers",
                           "query_params", "body"})


def is_input_source(pf, n):
    """User input, the environment or the network."""
    if isinstance(n, ast.Call):
        name = pf.name(n.func) or ""
        if name in SOURCE_CALLS and (name != "input" or "input" not in pf.aliases):
            return True
        return name.startswith(SOURCE_PREFIXES) or (isinstance(n.func, ast.Attribute) and n.func.attr in ("recv", "recvfrom"))
    if isinstance(n, ast.Attribute):
        name = pf.name(n) or ""
        if name.startswith(("os.environ", "sys.argv", "flask.request")):
            return True
        return isinstance(n.value, ast.Name) and n.value.id == "request" and n.attr in REQUEST_ATTRS
    return False


def scan_exec_shell(pf):
    """Commands run through a shell; FAIL when the command is built from input, the environment or the network."""
    out = []
    for c in pf.calls():
        name = pf.name(c.func) or ""
        if name in SHELL_ALWAYS:
            how = name
        elif name in SUBPROCESS and kw_const(c, "shell") == (True, True):
            how = name + "(shell=True)"
        else:
            continue
        cmd = arg(c, 0, "args") or arg(c, 0, "cmd") or arg(c, 0, "command")
        if cmd is not None and flows_from(pf, cmd, is_input_source):
            out.append(finding("exec.shell", "FAIL", node_of(pf, c), "%s runs a shell command built from input, env or network" % how,
                               ["call: %s" % how, "the command text flows from input(), os.environ, sys.argv or a network read"],
                               ["pass an argument list without shell=True", "validate the value against an allow-list"]))
        else:
            out.append(finding("exec.shell", "WARN", node_of(pf, c), "%s runs a command through the shell" % how,
                               ["call: %s" % how], ["pass an argument list without shell=True"]))
    return out


# --------------------------------------------------------------------------- deser.unsafe

PICKLE_LIKE = frozenset({"pickle.load", "pickle.loads", "pickle.Unpickler", "cPickle.load", "cPickle.loads",
                         "_pickle.load", "_pickle.loads", "marshal.load", "marshal.loads"})
SAFE_LOADERS = ("SafeLoader", "CSafeLoader", "BaseLoader", "CBaseLoader")


def scan_deser(pf):
    """Deserialisers that can run code from the data: pickle, marshal, yaml.load without SafeLoader, torch.load."""
    out = []
    for c in pf.calls():
        name = pf.name(c.func) or ""
        why = None
        if name in PICKLE_LIKE:
            why = "%s can run code hidden in the data" % name
        elif name in ("yaml.unsafe_load", "yaml.unsafe_load_all"):
            why = "%s can build arbitrary Python objects" % name
        elif name in ("yaml.load", "yaml.load_all"):
            loader = arg(c, 1, "Loader")
            if loader is None or not (pf.name(loader) or "").endswith(SAFE_LOADERS):
                why = "%s without SafeLoader can build arbitrary Python objects" % name
        elif name == "torch.load" and kw_const(c, "weights_only") != (True, True):
            why = "torch.load without weights_only=True unpickles the file"
        if why:
            out.append(finding("deser.unsafe", "WARN", node_of(pf, c), why, ["call: %s" % name],
                               ["load only files you created, or use a data-only format (json, safetensors, yaml.safe_load)"]))
    return out


# --------------------------------------------------------------------------- net.egress / net.bind_all

URL = re.compile(r"\b(?:https?|wss?|ftp)://[^\s'\"<>)\]`]+")
EGRESS_EXACT = frozenset({"urllib.request.urlopen", "urllib.urlopen", "urllib2.urlopen", "http.client.HTTPConnection",
                          "http.client.HTTPSConnection", "socket.create_connection", "ftplib.FTP", "smtplib.SMTP",
                          "smtplib.SMTP_SSL", "aiohttp.ClientSession", "urllib3.PoolManager"})
EGRESS_VERBS = frozenset({"get", "post", "put", "patch", "delete", "head", "options", "request", "stream", "Session",
                          "Client", "AsyncClient"})
_ALL_INTERFACES = frozenset({"0.0.0.0", "::", "[::]"})
_HOST_WORDS = ("host", "bind", "addr", "listen")


def _ip(text):
    try:
        return ipaddress.ip_address(text.strip("[]"))
    except ValueError:
        return None


LOCAL_SUFFIXES = (".local", ".lan", ".internal", ".home.arpa", ".localdomain")
# RFC 2606 / RFC 6761 names: documentation and testing only, never a real third party.
RESERVED = ("example.com", "example.net", "example.org")
# XML namespace identifiers look like URLs but are never fetched.
NAMESPACE_HOSTS = frozenset({"www.w3.org", "w3.org", "schemas.xmlsoap.org", "schemas.openxmlformats.org", "purl.org",
                             "ns.adobe.com", "schemas.microsoft.com", "xmlns.com", "www.opengis.net"})
RESERVED_SUFFIXES = (".example.com", ".example.net", ".example.org", ".test", ".example", ".invalid", ".localhost")


def classify_host(scheme, host):
    """(level, reason) for one egress target. WARN: a publicly routable IP, or plain http/ws/ftp to a public name or
    to a host chosen at runtime. INFO: https, loopback, the local network (non-global IPs such as 10/8, 192.168/16
    and 100.64/10, single-label names, .local/.lan/.internal/.home.arpa) and reserved documentation names
    (example.com, .test, .invalid): inventoried, not scored."""
    plain = bool(scheme) and scheme not in ("https", "wss")
    if not host or any(c in host for c in "{}%"):
        return ("WARN", "not https; host set at runtime") if plain else ("INFO", "host set at runtime")
    ip = _ip(host)
    if host == "localhost" or (ip is not None and ip.is_loopback):
        return "INFO", "loopback"
    if host.lower() in NAMESPACE_HOSTS:
        return "INFO", "XML namespace identifier"
    if ip is not None:
        return ("WARN", "public IP address") if ip.is_global else ("INFO", "local-network address")
    if "." not in host or host.lower().endswith(LOCAL_SUFFIXES):
        return "INFO", "local-network name"
    if host.lower() in RESERVED or host.lower().endswith(RESERVED_SUFFIXES):
        return "INFO", "reserved documentation name"
    if plain:
        return "WARN", "not https"
    return "INFO", "https" if scheme else "host"


def _url_host(url):
    try:
        parts = urlsplit(url)
        return parts.scheme.lower(), (parts.hostname or "")
    except ValueError:
        return url.split(":", 1)[0].lower(), ""


def _socket_names(pf):
    names = set()
    for n in pf.nodes:
        if isinstance(n, ast.Assign) and isinstance(n.value, ast.Call) and pf.name(n.value.func) == "socket.socket":
            names.update(pf.name(t) for t in n.targets)
    names.discard(None)
    return names


def scan_egress(pf):
    """Every URL and raw IP literal, and every urllib/requests/httpx/socket call site: the egress inventory."""
    out = []
    for node, text in pf.strings():
        for url in URL.findall(text):
            level, why = classify_host(*_url_host(url))
            url = redact_url(url)  # the report says where, never with what: a URL can be the credential
            out.append(finding("net.egress", level, node_of(pf, node), "URL literal %s (%s)" % (url[:80], why),
                               ["kind: url", "target: %s" % url[:200], "why: %s" % why],
                               ["use https", "confirm this destination is expected"] if level == "WARN" else []))
        host = text.rsplit(":", 1)[0] if text.count(":") == 1 else text
        ip = _ip(host) if re.fullmatch(r"[0-9a-fA-F:.\[\]]{3,}(?::\d+)?", text) and "." in text else None
        if ip is not None and text not in _ALL_INTERFACES and str(ip) != "0.0.0.0":
            level, why = classify_host("", host)
            out.append(finding("net.egress", level, node_of(pf, node), "IP literal %s (%s)" % (text, why),
                               ["kind: ip", "target: %s" % text, "why: %s" % why],
                               ["use a hostname from configuration"] if level == "WARN" else []))
    sockets = _socket_names(pf)
    for c in pf.calls():
        name = pf.name(c.func) or ""
        head, _, verb = name.rpartition(".")
        hit = name in EGRESS_EXACT or (head in ("requests", "httpx") and verb in EGRESS_VERBS)
        if not hit and isinstance(c.func, ast.Attribute) and c.func.attr in ("connect", "connect_ex", "sendto"):
            recv = pf.name(c.func.value)
            hit = recv in sockets or (recv or "").startswith("socket.socket()")
            name = "socket.%s" % c.func.attr if hit else name
        if hit:
            out.append(finding("net.egress", "INFO", node_of(pf, c), "network call %s" % name,
                               ["kind: call", "target: %s" % name], []))
    return out


def scan_bind_all(pf):
    """A server bound to every interface (0.0.0.0 or ::) instead of loopback."""
    out = []

    def hit(node, how):
        out.append(finding("net.bind_all", "WARN", node_of(pf, node), "binds to all interfaces (%s)" % how,
                           ["literal: %s" % how], ["bind to 127.0.0.1 unless other machines must connect"]))

    for n in pf.nodes:
        if isinstance(n, ast.Call):
            candidates = list(n.args) + [e for a in n.args if isinstance(a, ast.Tuple) for e in a.elts]
            candidates += [kw.value for kw in n.keywords if kw.arg and any(w in kw.arg.lower() for w in _HOST_WORDS)]
            for v in candidates:
                if isinstance(v, ast.Constant) and v.value in _ALL_INTERFACES:
                    hit(v, v.value)
        elif isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant) and n.value.value in _ALL_INTERFACES:
            names = [(pf.name(t) or "").lower() for t in n.targets]
            if any(w in name for name in names for w in _HOST_WORDS):
                hit(n.value, n.value.value)
    return dedupe(out)


# --------------------------------------------------------------------------- tls.off

VERIFY_KWARGS = ("verify", "verify_ssl", "ssl_verify")


def caller_controlled(pf, node):
    """node sits under an `if` whose test reads a parameter of the enclosing function: it runs only when asked."""
    scope = pf.scope(node)
    if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        return False
    a = scope.args
    params = {x.arg for x in a.posonlyargs + a.args + a.kwonlyargs + [a.vararg, a.kwarg] if x}
    cur = pf.parents.get(node)
    while cur is not None and cur is not scope:
        if isinstance(cur, (ast.If, ast.IfExp)) and any(isinstance(n, ast.Name) and n.id in params for n in ast.walk(cur.test)):
            return True
        cur = pf.parents.get(cur)
    return False


def scan_tls_off(pf):
    """Certificate checks switched off: verify=False, ssl._create_unverified_context, CERT_NONE, check_hostname=False.
    FAIL when hard-coded; WARN when it happens only under an `if` on a function parameter (the caller opts out)."""
    out = []

    def hit(node, how):
        if caller_controlled(pf, node):
            out.append(finding("tls.off", "WARN", node_of(pf, node),
                               "TLS certificate checking can be switched off by the caller (%s)" % how,
                               ["code: %s" % how, "runs only under an if on a function parameter"],
                               ["make sure callers cannot pass it by accident; keep it out of defaults"]))
            return
        out.append(finding("tls.off", "FAIL", node_of(pf, node), "TLS certificate checking is switched off (%s)" % how,
                           ["code: %s" % how], ["remove it; point at a CA bundle instead if the certificate is private"]))

    for n in pf.nodes:
        if isinstance(n, ast.Call):
            for kw in n.keywords:
                if kw.arg in VERIFY_KWARGS and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    hit(kw.value, "%s=False" % kw.arg)
        elif isinstance(n, (ast.Attribute, ast.Name)) and not isinstance(pf.parents.get(n), ast.Attribute):
            name = pf.name(n) or ""
            if name.endswith("ssl._create_unverified_context") or name == "ssl.CERT_NONE":
                hit(n, name)
        elif isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant) and n.value.value is False:
            if any(isinstance(t, ast.Attribute) and t.attr == "check_hostname" for t in n.targets):
                hit(n, "check_hostname = False")
    return dedupe(out)


# --------------------------------------------------------------------------- install.hook lives in manifests.py

# --------------------------------------------------------------------------- obfuscation

DECODERS = frozenset({"base64.b64decode", "base64.b32decode", "base64.b16decode", "base64.b85decode",
                      "base64.a85decode", "base64.decodebytes", "base64.urlsafe_b64decode",
                      "base64.standard_b64decode", "zlib.decompress", "gzip.decompress", "bz2.decompress",
                      "lzma.decompress", "marshal.loads", "binascii.unhexlify", "binascii.a2b_base64",
                      "binascii.a2b_hex", "codecs.decode", "bytes.fromhex"})
BLOB_MIN = 200
TOKEN_MIN = 40
TOKEN_ENTROPY = 4.5
_B64 = re.compile(r"[A-Za-z0-9+/=_\-]+")
_HEX = re.compile(r"[0-9a-fA-F]+")


def is_decoder(pf, n):
    return isinstance(n, ast.Call) and (pf.name(n.func) or "") in DECODERS


def scan_obfuscation(pf):
    """exec/eval of decoded or decompressed data (FAIL); long base64/hex blobs and high-entropy literals (WARN)."""
    out = []
    for c in pf.calls():
        if is_builtin(pf, c, ("exec", "eval", "compile")) and c.args and flows_from(pf, c.args[0], is_decoder):
            out.append(finding("obfuscation", "FAIL", node_of(pf, c), "%s() runs decoded or decompressed data" % c.func.id,
                               ["chain: %s(<decoder>(...))" % c.func.id, "decoders: base64, zlib, marshal, hex, codecs"],
                               ["decode the payload offline and read what it does before running this"]))
    for node, text in pf.strings():
        if " " in text or "\t" in text:
            continue
        compact = text.replace("\n", "").replace("\r", "")
        if len(compact) >= BLOB_MIN and entropy(compact) > 3.0 and (_HEX.fullmatch(compact) or _B64.fullmatch(compact)):
            kind = "hex" if _HEX.fullmatch(compact) else "base64-like"
            out.append(finding("obfuscation", "WARN", node_of(pf, node), "%s blob of %d characters" % (kind, len(compact)),
                               ["kind: %s blob" % kind, "length: %d" % len(compact)], ["decode it and check what it holds"]))
        elif (len(compact) >= TOKEN_MIN and "://" not in compact and _B64.fullmatch(compact)
              and entropy(compact) >= TOKEN_ENTROPY and len(set(compact)) < 0.95 * len(compact)):
            # all-distinct characters is an alphabet (A-Za-z0-9...), not a token: random strings repeat characters
            out.append(finding("obfuscation", "WARN", node_of(pf, node), "high-entropy literal of %d characters" % len(compact),
                               ["kind: high-entropy literal", "entropy: %.2f bits/char" % entropy(compact)],
                               ["check whether it is a credential or an encoded payload"]))
    return dedupe(out)


# --------------------------------------------------------------------------- fs.outside

OPENERS = frozenset({"open", "io.open", "codecs.open", "os.open"})
FS_FIRST = frozenset({"os.remove", "os.unlink", "os.rmdir", "os.removedirs", "os.makedirs", "os.mkdir", "os.chmod",
                      "os.chown", "os.truncate", "shutil.rmtree"})
FS_DEST = frozenset({"os.rename", "os.replace", "os.symlink", "os.link", "shutil.copy", "shutil.copy2",
                     "shutil.copyfile", "shutil.copytree", "shutil.move"})
PATH_WRITERS = frozenset({"write_text", "write_bytes", "mkdir", "touch", "unlink", "rmdir", "symlink_to"})
DEVICES = ("/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty")


def path_prefix(pf, node):
    """The literal start of a path expression, or None when it does not start with a literal."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr) and node.values and isinstance(node.values[0], ast.Constant):
        return node.values[0].value
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Div, ast.Add)):
        return path_prefix(pf, node.left)
    if isinstance(node, ast.Call) and node.args:
        name = pf.name(node.func) or ""
        if name in ("os.path.join", "os.path.expanduser", "os.path.abspath", "pathlib.Path", "Path", "pathlib.PurePath"):
            return path_prefix(pf, node.args[0])
    return None


def outside(path):
    """Absolute, home-relative or ..-escaping (a device file such as /dev/null is fine)."""
    if path.startswith(DEVICES):
        return None
    if path.startswith("~"):
        return "home directory"
    if path.startswith(("/", "\\")) or re.match(r"[A-Za-z]:[\\/]", path):
        return "absolute path"
    norm = posixpath.normpath(path.replace("\\", "/"))
    if norm == ".." or norm.startswith("../"):
        return "escapes the project with .."
    return None


def scan_fs_outside(pf):
    """Writes, deletes and moves aimed at absolute paths, ~ or ..-escapes."""
    out = []
    for c in pf.calls():
        name = pf.name(c.func) or ""
        target = None
        if name in OPENERS and (name != "open" or "open" not in pf.aliases):
            mode = arg(c, 1, "mode") if name != "os.open" else arg(c, 1, "flags")
            if isinstance(mode, ast.Constant) and isinstance(mode.value, str) and set(mode.value) & set("wax+"):
                target = arg(c, 0, "file")
            elif name == "os.open" and mode is not None and re.search(r"O_(?:WRONLY|RDWR|CREAT|APPEND)", ast.dump(mode)):
                target = arg(c, 0, "path")
        elif name in FS_FIRST:
            target = arg(c, 0)
        elif name in FS_DEST:
            target = arg(c, 1, "dst")
        elif isinstance(c.func, ast.Attribute) and c.func.attr in PATH_WRITERS:
            target = c.func.value
        if target is None:
            continue
        prefix = path_prefix(pf, target)
        why = outside(prefix) if prefix else None
        if why:
            out.append(finding("fs.outside", "WARN", node_of(pf, c), "writes outside the project: %s (%s)" % (prefix[:60], why),
                               ["call: %s" % (name or c.func.attr), "path starts: %s" % prefix[:120]],
                               ["write under the project or a path the user passes in"]))
    return out


# --------------------------------------------------------------------------- privacy.pii_log / privacy.pii_prompt

PII_WORDS = frozenset({"email", "phone", "ssn", "dob", "birth", "birthday", "birthdate", "address", "passport",
                       "iban", "creditcard", "cardnumber", "ipaddress"})
PII_PAIRS = frozenset({("credit", "card"), ("card", "number"), ("ip", "address")})
# "address" next to these words is a network or memory address, not where a person lives
NOT_A_PERSON = frozenset({"server", "bind", "host", "mac", "listen", "remote", "local", "socket", "peer", "proxy",
                          "broadcast", "gateway", "bluetooth", "memory", "base", "start", "end", "return", "web",
                          "url", "contract", "wallet", "node", "multicast", "src", "dst", "dest", "source", "target"})
LOG_METHODS = frozenset({"debug", "info", "warning", "warn", "error", "exception", "critical", "log", "fatal"})
PROMPT_KEYWORDS = frozenset({"messages", "prompt"})
PROMPT_METHODS = frozenset({"chat", "complete", "generate"})


def _words(name):
    return [w for w in re.split(r"_+|(?<=[a-z0-9])(?=[A-Z])", str(name)) if w]


def pii_name(name):
    """An identifier that names personal data: email, phone, ssn, dob/birth, a person's address, passport,
    credit_card/card_number, iban or ip_address (as whole words: emails_sent and server_address do not count)."""
    words = [w.lower() for w in _words(name)]
    for i, w in enumerate(words):
        if w in PII_WORDS and not (w == "address" and i > 0 and words[i - 1] in NOT_A_PERSON):
            return True
        if i and (words[i - 1], w) in PII_PAIRS:
            return True
    return False


def is_pii_source(pf, n):
    """A Name or attribute that names personal data (an imported module such as `email` does not count)."""
    if isinstance(n, ast.Name):
        return n.id not in pf.aliases and pii_name(n.id)
    return isinstance(n, ast.Attribute) and pii_name(n.attr)


def _pii_in(pf, exprs):
    """The first personal-data name that flows into any of exprs (directly or through names assigned from one in
    the same function), or None."""
    for e in exprs:
        if e is None or not flows_from(pf, e, is_pii_source):
            continue
        names = tainted_names(pf, pf.scope(e), is_pii_source)
        for n in ast.walk(e):
            if is_pii_source(pf, n):
                return n.id if isinstance(n, ast.Name) else n.attr
            if isinstance(n, ast.Name) and n.id in names:
                return n.id
    return None


def _log_sink(pf, c):
    name = pf.name(c.func) or ""
    if is_builtin(pf, c, ("print",)):
        return "print"
    if name.startswith("logging.") and name.rsplit(".", 1)[1] in LOG_METHODS:
        return name
    f = c.func
    if isinstance(f, ast.Attribute) and f.attr in LOG_METHODS:
        recv = (pf.name(f.value) or "").lower()
        if "log" in recv.rsplit(".", 1)[-1]:
            return "%s.%s" % (pf.name(f.value), f.attr)
    return None


def scan_pii_log(pf):
    """Personal data (email, phone, ssn, dob, address, passport, card number, iban, ip address) written to a log or
    printed. One function deep, like the exec.shell taint rule."""
    out = []
    for c in pf.calls():
        sink = _log_sink(pf, c)
        if not sink:
            continue
        name = _pii_in(pf, list(c.args) + [k.value for k in c.keywords])
        if name:
            out.append(finding("privacy.pii_log", "WARN", node_of(pf, c),
                               "personal data (%s) is written to a log or printed (%s)" % (name, sink),
                               ["name: %s" % name, "sink: %s" % sink],
                               ["log an id or a masked value instead (user 42, a***@example.com)",
                                "logs are copied, shipped and kept far longer than the data itself"]))
    return out


def scan_pii_prompt(pf):
    """Personal data sent into an LLM prompt: a messages= or prompt= argument, or .chat( / .complete( / .generate(."""
    out = []
    for c in pf.calls():
        f = c.func
        method = f.attr if isinstance(f, ast.Attribute) and f.attr in PROMPT_METHODS else None
        keyword = [k for k in c.keywords if k.arg in PROMPT_KEYWORDS]
        if not (method or keyword):
            continue
        exprs = (list(c.args) + [k.value for k in c.keywords]) if method else [k.value for k in keyword]
        name = _pii_in(pf, exprs)
        if name:
            via = ".%s(" % method if method else "%s=" % keyword[0].arg
            out.append(finding("privacy.pii_prompt", "WARN", node_of(pf, c),
                               "personal data (%s) is sent into an LLM prompt (%s)" % (name, via),
                               ["name: %s" % name, "sink: %s" % via],
                               ["send an id or a redacted value; the model provider stores prompts",
                                "check the provider's data terms before sending personal data at all"]))
    return out


# --------------------------------------------------------------------------- registry

PY_SCANNERS = [
    ("secret.key", scan_password_literals),
    ("exec.dynamic", scan_exec_dynamic),
    ("exec.shell", scan_exec_shell),
    ("deser.unsafe", scan_deser),
    ("net.egress", scan_egress),
    ("net.bind_all", scan_bind_all),
    ("tls.off", scan_tls_off),
    ("obfuscation", scan_obfuscation),
    ("fs.outside", scan_fs_outside),
    ("privacy.pii_log", scan_pii_log),
    ("privacy.pii_prompt", scan_pii_prompt),
]


def scan_python(pf, table=None, crashed=None):
    """Every Python scanner (or the given table) over one parsed file. A scanner that raises yields one
    check.crashed WARN (weight 0), not a crash; when crashed is a list, (code, finding) is appended to it."""
    out = []
    for code, fn in table or PY_SCANNERS:
        got = run_check(code, lambda _s, _c, fn=fn: fn(pf), None, None, node=pf.rel)
        if isinstance(got, dict) and crashed is not None:
            crashed.append((code, got))
        out.extend(got if isinstance(got, list) else [got])
    return out


# --------------------------------------------------------------------------- selftest

def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if "--selftest" in argv:
        return selftest()
    sys.stderr.write("usage: python -m code_guardian.scanners --selftest\n")
    return 2


def _codes(src, fn):
    pf = PyFile("t.py", src.encode("utf-8"), src)
    return sorted(((f["code"], f["level"], f["node"]) for f in fn(pf)), key=lambda t: int(t[2].rsplit(":", 1)[1]))


def selftest():
    h = "http" + "://"
    mixed = hashlib.sha256(b"code-guardian selftest").hexdigest()[:24]  # a mixed, real-shaped body, built here
    key = "sk-" + mixed
    pem = "-----BEGIN " + "RSA PRIVATE KEY-----"

    def one(text, rel="a.js"):
        found = scan_secret_text(rel, text, False)
        return (found[0]["level"], found[0]["evidence"][-1]) if len(found) == 1 else None

    blob = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo" * 7
    crashed = []
    checks = [
        ("secret_key_text", [f["level"] for f in scan_secret_text("a.js", "const k = '%s';\n" % key, False)] == ["FAIL"]),
        ("secret_redacted", key not in repr(scan_secret_text("a.js", key, False))),
        ("secret_placeholder", scan_secret_text("a.yml", 'password: "<your password>"\n', False) == []),
        ("secret_password_py", _codes('password = "%s"\n' % ("hunter" + "22"), scan_password_literals) == [("secret.key", "FAIL", "t.py:1")]),
        ("secret_provider_shapes", [f["level"] for f in scan_secret_text(
            "a.env", "A=%s\nB=%s\nC=%s\nD=%s\nE=%s\n" % ("AKIA" + "Q7XZ4M9RK2T8W5BN", "sk_" + "live_" + "a1B2c3D4e5F6g7H8",
                                                       "sk_" + "test_" + "a1B2c3D4e5F6g7H8", "xox" + "b-" + "4829r6037x24",
                                                       "hf" + "_" + "KpLdGtHsRfWqZrWnJtXcBvQmXkPlRtYu"), False)]
         == ["FAIL", "FAIL", "INFO", "FAIL", "FAIL"]),
        ("secret_aws_example_is_fake", scan_secret_text("c", "k = %s\n" % ("AKIA" + "IOSFODNN7" + "EXAMPLE"), False) == []),
        ("secret_key_suffix_entropy", [len(_codes('%s = "%s"\n' % (name, value), scan_password_literals)) for name, value in
                                      (("AWS_KEY", "aZ3kP9mQ2vR7tY5wX1bN8cL4dF6gH0jSaZ3k"), ("CACHE_KEY", "user_profile_cache_v2"))]
         == [1, 0]),
        ("exec_dynamic", _codes("eval(x)\neval('1')\n__import__(name)\n", scan_exec_dynamic) ==
         [("exec.dynamic", "WARN", "t.py:1"), ("exec.dynamic", "WARN", "t.py:3")]),
        ("exec_dynamic_tainted", _codes("import sys\neval(input())\nc = sys.argv[1]\nexec(c)\n", scan_exec_dynamic) ==
         [("exec.dynamic", "FAIL", "t.py:2"), ("exec.dynamic", "FAIL", "t.py:4")]),
        ("exec_shell_levels", _codes("import os, subprocess as sp\nsp.run('ls', shell=True)\nc = input()\nos.system(c)\n",
                                     scan_exec_shell) == [("exec.shell", "WARN", "t.py:2"), ("exec.shell", "FAIL", "t.py:4")]),
        ("exec_shell_list_ok", _codes("import subprocess\nsubprocess.run(['ls'])\n", scan_exec_shell) == []),
        ("deser", [c for c, _, _ in _codes("import pickle, yaml, torch\npickle.loads(b)\nyaml.load(s)\n"
                                           "yaml.load(s, Loader=yaml.SafeLoader)\ntorch.load(p)\ntorch.load(p, weights_only=True)\n",
                                           scan_deser)] == ["deser.unsafe"] * 3),
        ("egress_levels", [lv for _, lv, _ in _codes("a = '%spypi.org/x'\nb = 'https://example.com'\nc = '%s127.0.0.1:1'\n"
                                                    "d = '100.64.0.5'\ne = '%sgpu-box:11434'\nf = '%s%%s:%%d'\n" % (h, h, h, h),
                                                    scan_egress)] == ["WARN", "INFO", "INFO", "INFO", "INFO", "WARN"]),
        ("egress_calls", _codes("import requests\nrequests.get(u)\n", scan_egress) == [("net.egress", "INFO", "t.py:2")]),
        ("docstring_ignored", _codes('"""see %sexample.com"""\n' % h, scan_egress) == []),
        ("bind_all", _codes("srv.bind(('0.0.0.0', 80))\nHOST = '::'\nx = '0.0.0.0'\n", scan_bind_all) ==
         [("net.bind_all", "WARN", "t.py:1"), ("net.bind_all", "WARN", "t.py:2")]),
        ("tls_off", len(_codes("import ssl, requests\nrequests.get(u, verify=False)\nctx = ssl._create_unverified_context()\n"
                               "m = ssl.CERT_NONE\nctx.check_hostname = False\n", scan_tls_off)) == 4),
        ("obfuscation", sorted(lv for _, lv, _ in _codes("import base64\nexec(base64.b64decode(p))\nb = '%s'\n" % blob,
                                                       scan_obfuscation)) == ["FAIL", "WARN"]),
        ("fs_outside", _codes("open('/etc/x', 'w')\nopen('/etc/x')\nopen('../../x', 'a')\nopen('out/x', 'w')\n"
                              "import shutil\nshutil.rmtree('~/data')\nopen('/dev/null', 'w')\n", scan_fs_outside) ==
         [("fs.outside", "WARN", "t.py:1"), ("fs.outside", "WARN", "t.py:3"), ("fs.outside", "WARN", "t.py:6")]),
        ("clean_file_no_findings", scan_python(PyFile("t.py", b"x = 1\n", "x = 1\n")) == []),
        ("crash_is_one_warn", [(f["code"], f["level"], f["node"]) for f in
                               scan_python(PyFile("t.py", b"x = 1\n", "x = 1\n"), [("boom", lambda pf: 1 / 0)], crashed)]
         == [("check.crashed", "WARN", "t.py")] and [c for c, _ in crashed] == ["boom"]),
        ("redact", redact("k=%s mail a.b@%s" % (key, "x.org")) == "k=<redacted key> mail <redacted email>"
         and redact("plain text") == "plain text"
         and redact("v: aZ3kP9mQ2vR7tY5wX1bN8c", strict=True) == "v: <redacted value>"),
        ("key_values", key_values("a = '%s' b = 'plain'" % key) == [key] and key_values("nothing here") == []),
        ("pii_log", _codes("import logging\ndef f(email):\n    logging.info(email)\n    print(len('x'))\n", scan_pii_log)
         == [("privacy.pii_log", "WARN", "t.py:3")]),
        ("pii_prompt", _codes("def f(c, phone):\n    c.generate('call ' + phone)\n", scan_pii_prompt)
         == [("privacy.pii_prompt", "WARN", "t.py:2")]),
        ("pii_name", pii_name("user_email") and pii_name("clientIpAddress") and not pii_name("server_address")
         and not pii_name("emails_sent")),
        ("aliases", dotted(ast.parse("sp.run").body[0].value, {"sp": "subprocess"}) == "subprocess.run"),
        ("testkey_word_info", one("k = '%s'\n" % ("sk-" + "fake" + mixed[:12])) ==
         ("INFO", "looks like a test value: spells out fake")),
        ("testkey_lowvar_info", one("k = '%s'\n" % ("sk-" + "Hq4" * 10)) ==
         ("INFO", "looks like a test value: is mostly one character")),
        ("testkey_run_info", one("k = '%s'\n" % ("sk-" + "Qm7xK2" + "0" * 8 + "pL9wR3")) ==
         ("INFO", "looks like a test value: repeats one character")),
        ("testkey_sequence_info", one("k = '%s'\n" % ("sk-" + "Qm7xK2" + "12345678" + "pL9wR3")) ==
         ("INFO", "looks like a test value: counts up")),
        ("realkey_stays_fail", [(f["level"], f["evidence"]) for f in scan_secret_text("a.js", "k = '%s'\n" % key, False)]
         == [("FAIL", ["matched: sk- key shape (privacy pattern 5)", "length: 27 characters", KEY_SHAPE])]),
        ("pem_never_info", [f["level"] for f in scan_secret_text("a", pem + " fake\n", False)] == ["FAIL"]
         and [f["level"] for f in scan_secret_text("a", "%s %s\n" % (pem, "sk-" + "Hq4" * 10), False)] == ["FAIL"]),
        ("fail_wins_the_line", [f["level"] for f in scan_secret_text(
            "a.js", "a = '%s'; b = '%s'\n" % ("sk-" + "Hq4" * 10, key), False)] == ["FAIL"]),
        ("provider_lowvar_info", one("A=%s\n" % ("AK" + "IA" + "Q" * 16), "a.env") ==
         ("INFO", "looks like a test value: is mostly one character")),
        ("classic_token_lowvar_info", one("t = '%s'\n" % ("gh" + "p_" + "A" * 36)) ==
         ("INFO", "looks like a test value: is mostly one character")),  # no checksum exemption: graded by the body
        ("classic_token_mixed_stays_fail", (one("t = '%s'\n" % ("gh" + "p_" + mixed + "Kp2Ld9Gt7Hs3")) or ("",))[0]
         == "FAIL"),
        ("reason_none_for_mixed", test_value_reason("sk-", mixed) is None
         and test_value_reason("sk-", "Hq4" * 10) == "is mostly one character"),
    ]
    return summarize("scanners", checks)


if __name__ == "__main__":
    sys.exit(main())
