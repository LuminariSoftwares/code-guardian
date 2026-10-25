"""A JavaScript / TypeScript lexer and six small shape helpers for the checks built on it. Standard library only.

It reads text and never runs or imports anything. It is a lexer, not a parser: it cuts the text into tokens well enough
that a keyword inside a string, a comment, a template or a regex is never mistaken for code, and the shapes read call
sites, imports, assignments and request-derived values off the token list.

Public contract:
    tokenize(text, flavour) -> [Token]     flavour in {"js", "jsx", "ts", "tsx"}; Token(kind, value, line, col, flags)
        kinds: name keyword number string template regex punct comment error
        error.value in {"string", "template", "comment", "regex"}; flags "" or "relexed" (after a stray backtick)
    calls(tokens) -> [Call(callee, args, line, new)]     imports(tokens) -> [Import(spec, line, kind)]
    assigns(tokens, member) -> [Assign(target, value, line)]     props(arg) -> {key: value_tokens}
    literal(tokens) -> str | None     handler_roots(tokens) -> [(name, start_index, end_index)]
    is_source(tokens, roots=None) -> bool

Lines and columns are 1-based and counted on the text after "\\r\\n" and "\\r" become "\\n", so the same bytes give the same
tokens on every platform. The shapes take the full token list from tokenize and skip comments themselves.
"""

import json
import re
import sys
from collections import namedtuple

Token = namedtuple("Token", "kind value line col flags")
Call = namedtuple("Call", "callee args line new")
Import = namedtuple("Import", "spec line kind")
Assign = namedtuple("Assign", "target value line")

FLAVOURS = frozenset({"js", "jsx", "ts", "tsx"})
JSX_HINT = re.compile(r"</[A-Za-z>]|/>")

KEYWORDS = frozenset(
    "break case catch class const continue debugger default delete do else enum export extends false finally for "
    "function if import in instanceof let new null return super switch this throw true try typeof var void while with "
    "yield await of".split())
# A "/" after one of these starts a regex; after any other keyword, name, number, string or ") ] } </" it divides.
REGEX_AFTER_KEYWORD = frozenset("return typeof instanceof in of new delete void throw case do else yield await".split())
DIVIDES_AFTER_PUNCT = frozenset({")", "]", "}", "</"})

_WS = re.compile(r"(?:[^\S\n]|﻿)+")
_NAME = re.compile(r"#?(?:[^\W\d]|\$)[\w$]*")
_NUMBER = re.compile(r"0[xX][0-9a-fA-F_]+n?|0[bB][01_]+n?|0[oO][0-7_]+n?"
                     r"|(?:\d[\d_]*(?:\.[\d_]*)?|\.\d[\d_]*)(?:[eE][+-]?\d[\d_]*)?n?")
_PUNCT = re.compile(r">>>=|\.\.\.|===|!==|\*\*=|<<=|>>=|>>>|&&=|\|\|=|\?\?=|=>|==|!=|<=|>=|&&|\|\||\?\?|\?\.(?!\d)"
                    r"|\+\+|--|\+=|-=|\*=|%=|&=|\|=|\^=|<<|>>|\*\*|.", re.S)
_SQ = re.compile(r"'(?:[^'\\\n]|\\[\s\S])*+'")
_DQ = re.compile(r'"(?:[^"\\\n]|\\[\s\S])*+"')
_REGEX = re.compile(r"/(?:[^/\\\[\n]|\\[^\n]|\[(?:[^\]\\\n]|\\[^\n])*+\])++/[A-Za-z]*+")
_WS_END = re.compile(r"\s*\Z")
_TEMPLATE_TEXT = re.compile(r"[\\`$]")
_TEMPLATE_CODE = re.compile(r"""[{}`'"/]""")
_DIGITS = "0123456789"


def _regex_may_start(text, i):
    """True when the "/" at text[i], inside a template's `${ }`, follows an operator or opener rather than a value."""
    j = i - 1
    while j >= 0 and text[j] in " \t\n":
        j -= 1
    return j < 0 or text[j] in "(,=:[!&|?{};+-*%<>~^"


def _scan_template(text, start):
    """End index (exclusive) of the template whose backtick is at `start`, or -1 when it never closes. `${ }` nests
    through a stack: 0 is template text, a positive number is code with that many open braces."""
    n = len(text)
    stack = [0]
    i = start + 1
    while i < n:
        if stack[-1] == 0:
            m = _TEMPLATE_TEXT.search(text, i)
            if not m:
                return -1
            i = m.start()
            c = text[i]
            if c == "\\":
                i += 2
            elif c == "`":
                stack.pop()
                i += 1
                if not stack:
                    return i
            elif text.startswith("{", i + 1):
                stack.append(1)
                i += 2
            else:
                i += 1
        else:
            m = _TEMPLATE_CODE.search(text, i)
            if not m:
                return -1
            i = m.start()
            c = text[i]
            if c == "{":
                stack[-1] += 1
                i += 1
            elif c == "}":
                stack[-1] -= 1
                i += 1
                if stack[-1] == 0:
                    stack.pop()
            elif c == "`":
                stack.append(0)
                i += 1
            elif c == "/":
                nx = text[i + 1:i + 2]
                if nx == "/":
                    i = text.find("\n", i)
                    if i < 0:
                        return -1
                elif nx == "*":
                    i = text.find("*/", i + 2)
                    if i < 0:
                        return -1
                    i += 2
                else:
                    m = _REGEX.match(text, i) if _regex_may_start(text, i) else None
                    i = m.end() if m else i + 1
            else:
                m = (_SQ if c == "'" else _DQ).match(text, i)
                i = m.end() if m else i + 1
    return -1


def _lex(text, i, line, ls, jsx, flag, out):
    """Lex text[i:] onto `out`. Returns None when done (an EOF error token has been appended and ends the stream), or
    (index, line, line_start) of a backtick whose template never closes, in a JSX flavour, for the caller to re-lex."""
    n = len(text)
    append = out.append
    lk = lv = None
    for t in reversed(out):
        if t.kind != "comment":
            lk, lv = t.kind, t.value
            break
    while i < n:
        c = text[i]
        if c == "\n":
            line += 1
            i += 1
            ls = i
            continue
        if c == " " or c == "\t" or c.isspace() or c == "﻿":
            i = _WS.match(text, i).end()
            continue
        if c.isalpha() or c == "_" or c == "$" or c == "#":
            m = _NAME.match(text, i)
            if m:
                w = m.group()
                kind = "keyword" if w in KEYWORDS and not (lk == "punct" and (lv == "." or lv == "?.")) else "name"
                append(Token(kind, w, line, i - ls + 1, flag))
                lk, lv = kind, w
                i = m.end()
                continue
        elif c in _DIGITS or (c == "." and text[i + 1:i + 2] and text[i + 1] in _DIGITS):
            m = _NUMBER.match(text, i)
            append(Token("number", m.group(), line, i - ls + 1, flag))
            lk, lv = "number", m.group()
            i = m.end()
            continue
        if c == "'" or c == '"':
            m = (_SQ if c == "'" else _DQ).match(text, i)
            if m:
                v = m.group()
                append(Token("string", v, line, i - ls + 1, flag))
                lk, lv = "string", v
                if "\n" in v:
                    line += v.count("\n")
                    ls = i + v.rfind("\n") + 1
                i = m.end()
            else:
                append(Token("error", "string", line, i - ls + 1, flag))
                lk, lv = "error", "string"
                i += 1
            continue
        if c == "`":
            end = _scan_template(text, i)
            if end < 0:
                if jsx:
                    return i, line, ls
                append(Token("error", "template", line, i - ls + 1, flag))
                return None
            v = text[i:end]
            append(Token("template", v, line, i - ls + 1, flag))
            lk, lv = "template", v
            if "\n" in v:
                line += v.count("\n")
                ls = i + v.rfind("\n") + 1
            i = end
            continue
        nx = text[i + 1:i + 2]
        if c == "/":
            if nx == "/":
                if jsx and i and text[i - 1] == ":":
                    append(Token("punct", "/", line, i - ls + 1, flag))
                    append(Token("punct", "/", line, i - ls + 2, flag))
                    lk, lv = "punct", "/"
                    i += 2
                    continue
                e = text.find("\n", i)
                if e < 0:
                    e = n
                append(Token("comment", text[i:e], line, i - ls + 1, flag))
                i = e
                continue
            if nx == "*":
                e = text.find("*/", i + 2)
                if e < 0:
                    append(Token("error", "comment", line, i - ls + 1, flag))
                    return None
                v = text[i:e + 2]
                append(Token("comment", v, line, i - ls + 1, flag))
                if "\n" in v:
                    line += v.count("\n")
                    ls = i + v.rfind("\n") + 1
                i = e + 2
                continue
            if jsx and nx == ">":
                append(Token("punct", "/>", line, i - ls + 1, flag))
                lk, lv = "punct", "/>"
                i += 2
                continue
            if lk is None or (lk == "punct" and lv not in DIVIDES_AFTER_PUNCT) or (lk == "keyword" and lv in REGEX_AFTER_KEYWORD):
                m = _REGEX.match(text, i)
                if m:
                    append(Token("regex", m.group(), line, i - ls + 1, flag))
                    lk, lv = "regex", m.group()
                    i = m.end()
                    continue
                e = text.find("\n", i)
                if _WS_END.match(text, n if e < 0 else e):
                    append(Token("error", "regex", line, i - ls + 1, flag))
                    return None
                # an unclosed regex mid-file is a division the heuristic got wrong: fall through to the punct
            v = "/=" if nx == "=" else "/"
        elif jsx and c == "<" and nx == "/":
            v = "</"
        else:
            v = _PUNCT.match(text, i).group()
        append(Token("punct", v, line, i - ls + 1, flag))
        lk, lv = "punct", v
        i += len(v)
    return None


def tokenize(text, flavour):
    """Cut `text` into tokens. In a JSX flavour (and a "js" text that matches JSX_HINT) a backtick whose template never
    closes is a stray backtick in JSX text: it becomes a punct and the rest is lexed again, marked "relexed"."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    jsx = flavour in ("jsx", "tsx") or (flavour == "js" and JSX_HINT.search(text) is not None)
    out = []
    pos = ls = 0
    line = 1
    flag = ""
    if text.startswith("#!"):
        pos = text.find("\n")
        if pos < 0:
            pos = len(text)
        out.append(Token("comment", text[:pos], 1, 1, ""))
    while True:
        stray = _lex(text, pos, line, ls, jsx, flag, out)
        if stray is None:
            return out
        pos, line, ls = stray
        out.append(Token("punct", "`", line, pos - ls + 1, flag))
        pos += 1
        flag = "relexed"


# ---- shapes -----------------------------------------------------------------------------------------------------------

_OPEN = {"(": ")", "[": "]", "{": "}"}
_CLOSE = {")": "(", "]": "[", "}": "{"}
_DOTS = frozenset({".", "?."})


def _significant(tokens):
    sig, pos = [], []
    for k, t in enumerate(tokens):
        if t.kind != "comment":
            sig.append(t)
            pos.append(k)
    return sig, pos


def _pairs(sig):
    """mate[i] is the index of the bracket that closes (or opens) sig[i], -1 when it has no partner. A closer that does
    not match the innermost opener closes the nearest matching one, so one stray brace does not unbalance the rest."""
    mate = [-1] * len(sig)
    stack = []
    for k, t in enumerate(sig):
        if t.kind != "punct":
            continue
        v = t.value
        if v in _OPEN:
            stack.append(k)
        elif v in _CLOSE:
            j = len(stack) - 1
            while j >= 0 and sig[stack[j]].value != _CLOSE[v]:
                j -= 1
            if j >= 0:
                o = stack[j]
                del stack[j:]
                mate[o] = k
                mate[k] = o
    return mate


def _punct(t, *values):
    return t.kind == "punct" and t.value in values


def _is_name(t):
    return t.kind == "name" or (t.kind == "keyword" and t.value in ("this", "super"))


def _text(t):
    """The text of a string token, or of a template with no expression; None for anything else."""
    if t.kind == "string" or (t.kind == "template" and "${" not in t.value):
        return t.value[1:-1]
    return None


def _split(sig, mate, lo, hi):
    """(start, end) index spans of the depth-0 comma-separated parts of sig[lo:hi]; an empty last part is dropped."""
    spans = []
    start = j = lo
    while j < hi:
        t = sig[j]
        if t.kind == "punct":
            if t.value in _OPEN and mate[j] > j:
                j = mate[j] + 1
                continue
            if t.value == ",":
                spans.append((start, j))
                start = j + 1
        j += 1
    if start < hi:
        spans.append((start, hi))
    return spans


def _call_sites(sig, mate):
    """[(callee, name_start, open_index, spans, new, member)] for every `name(` and `a.b?.c(`, in source order."""
    n = len(sig)
    out = []
    for k, t in enumerate(sig):
        if t.kind != "punct" or t.value != "(":
            continue
        j = k - 1
        if j >= 0 and _punct(sig[j], "?."):
            j -= 1
        if j < 0 or not _is_name(sig[j]):
            continue
        start = j
        while start >= 2 and _punct(sig[start - 1], *_DOTS) and _is_name(sig[start - 2]):
            start -= 2
        if start >= 1 and sig[start - 1].kind == "keyword" and sig[start - 1].value == "function":
            continue
        close = mate[k] if mate[k] > k else n
        if close < n and close + 1 < n and _punct(sig[close + 1], "{") and sig[close + 1].line == sig[close].line:
            continue  # `name(...) {` is a method or function definition
        callee = "".join(x.value for x in sig[start:j + 1])
        new = start >= 1 and sig[start - 1].kind == "keyword" and sig[start - 1].value == "new"
        member = start >= 1 and _punct(sig[start - 1], *_DOTS)
        out.append((callee, start, k, _split(sig, mate, k + 1, close), new, member))
    return out


def calls(tokens):
    sig, _ = _significant(tokens)
    mate = _pairs(sig)
    return [Call(callee, [sig[a:b] for a, b in spans], sig[start].line, new)
            for callee, start, _, spans, new, _ in _call_sites(sig, mate)]


def imports(tokens):
    sig, _ = _significant(tokens)
    mate = _pairs(sig)
    n = len(sig)
    out = []
    for k, t in enumerate(sig):
        nxt = sig[k + 1] if k + 1 < n else None
        if nxt is None:
            break
        if t.kind == "keyword" and t.value == "import":
            if _punct(nxt, "("):
                close = mate[k + 1] if mate[k + 1] > k + 1 else n
                spans = _split(sig, mate, k + 2, close)
                spec = _text(sig[spans[0][0]]) if spans and spans[0][1] - spans[0][0] == 1 else None
                out.append(Import(spec, t.line, "dynamic" if spec is not None else "computed"))
                continue
            j = k + 1
            while j < n:
                u = sig[j]
                if u.kind == "string":
                    if j == k + 1 or (sig[j - 1].kind == "name" and sig[j - 1].value == "from"):
                        out.append(Import(u.value[1:-1], t.line, "import"))
                    break
                if u.kind == "name" or _punct(u, "{", "}", ",", "*") or (u.kind == "keyword" and u.value == "default"):
                    j += 1
                    continue
                break
        elif t.kind == "keyword" and t.value == "export":
            j = k + 1
            if sig[j].kind == "name" and sig[j].value == "type" and j + 1 < n and _punct(sig[j + 1], "{", "*"):
                j += 1
            if _punct(sig[j], "*"):
                j += 1
                if j + 1 < n and sig[j].kind == "name" and sig[j].value == "as":
                    j += 2
            elif _punct(sig[j], "{") and mate[j] > j:
                j = mate[j] + 1
            else:
                continue
            if j + 1 < n and sig[j].kind == "name" and sig[j].value == "from" and sig[j + 1].kind == "string":
                out.append(Import(sig[j + 1].value[1:-1], t.line, "export_from"))
        elif t.kind == "name" and t.value == "require" and _punct(nxt, "(") and not (k and _punct(sig[k - 1], *_DOTS)):
            close = mate[k + 1] if mate[k + 1] > k + 1 else n
            spans = _split(sig, mate, k + 2, close)
            spec = _text(sig[spans[0][0]]) if spans and spans[0][1] - spans[0][0] == 1 else None
            out.append(Import(spec, t.line, "require" if spec is not None else "computed"))
    return out


def _target_start(sig, mate, e):
    """Index where the member-access expression ending at sig[e] begins."""
    j = e
    while True:
        t = sig[j]
        if _is_name(t):
            if j >= 2 and _punct(sig[j - 1], *_DOTS):
                j -= 2
                continue
            return j
        if t.kind == "punct" and t.value in (")", "]") and mate[j] >= 0:
            o = mate[j]
            if o >= 1 and (_is_name(sig[o - 1]) or _punct(sig[o - 1], ")", "]")):
                j = o - 1
                continue
            return o
        return j + 1


_VALUE_END_KEYWORDS = frozenset({"this", "super", "null", "true", "false"})
_NOT_A_NEW_STATEMENT = frozenset({"in", "instanceof", "of"})


def _statement_end(sig, mate, s):
    """Index where the statement whose expression starts at sig[s] ends: a `;`, a `,` or an unmatched closer at depth
    0, or a line break after a complete value when the next line starts something that cannot continue it."""
    n = len(sig)
    j = s
    while j < n:
        t = sig[j]
        if j > s:
            p = sig[j - 1]
            if t.line > p.line + (p.value.count("\n") if p.kind == "template" else 0):
                ends = p.kind in ("name", "number", "string", "template", "regex") \
                    or (p.kind == "keyword" and p.value in _VALUE_END_KEYWORDS) or _punct(p, ")", "]", "}")
                starts = t.kind in ("name", "number", "string") \
                    or (t.kind == "keyword" and t.value not in _NOT_A_NEW_STATEMENT) or _punct(t, "!", "~")
                if ends and starts:
                    return j
        if t.kind == "punct":
            if t.value in _OPEN and mate[j] > j:
                j = mate[j] + 1
                continue
            if t.value in (";", ",") or t.value in _CLOSE:
                return j
        j += 1
    return n


def assigns(tokens, member):
    sig, _ = _significant(tokens)
    mate = _pairs(sig)
    out = []
    for k, t in enumerate(sig):
        if t.kind != "punct" or t.value != "=" or k < 2:
            continue
        e = k - 1
        last = sig[e]
        if last.kind == "name" and last.value == member and _punct(sig[e - 1], *_DOTS):
            pass
        elif _punct(last, "]") and mate[e] >= 0 and mate[e] == e - 2 and _text(sig[e - 1]) == member:
            pass
        else:
            continue
        start = _target_start(sig, mate, e)
        out.append(Assign("".join(x.value for x in sig[start:k]), sig[k + 1:_statement_end(sig, mate, k + 1)],
                          sig[start].line))
    return out


def props(arg):
    """Top-level keys of an object-literal argument and the tokens of each value. Spreads and computed keys that are
    not a plain string are skipped; a shorthand `{ key }` has the key token as its value."""
    sig, _ = _significant(arg)
    mate = _pairs(sig)
    if not sig or not _punct(sig[0], "{") or mate[0] < 0:
        return {}
    out = {}
    for a, b in _split(sig, mate, 1, mate[0]):
        t = sig[a]
        if _punct(t, "..."):
            continue
        if _punct(t, "["):
            c = mate[a]
            if c < 0 or c > b or c - a != 2 or _text(sig[a + 1]) is None:
                continue
            key, rest = _text(sig[a + 1]), a + 3
        elif t.kind == "string":
            key, rest = t.value[1:-1], a + 1
        elif t.kind in ("name", "keyword", "number"):
            key, rest = t.value, a + 1
        else:
            continue
        if rest < b and _punct(sig[rest], ":"):
            out[key] = sig[rest + 1:b]
        elif rest >= b:
            out[key] = [t]
        else:
            out[key] = sig[rest:b]
    return out


def literal(tokens):
    sig, _ = _significant(tokens)
    return _text(sig[0]) if len(sig) == 1 else None


# ---- request-derived values -------------------------------------------------------------------------------------------

_HANDLER_METHODS = frozenset({"get", "post", "put", "patch", "delete", "all", "use"})
_REQUEST_LIKE = frozenset({"req", "request", "ctx", "event"})
_ROOT_PREFIXES = frozenset({("process", "argv"), ("process", "env"), ("ctx", "request"), ("document", "cookie"),
                            ("window", "name"), ("event", "data"), ("message", "data")})
_ROOT_NAMES = frozenset({"req", "request", "location"})
_SOURCE_SEGMENTS = frozenset({"query", "params", "headers", "cookies"})


def _first_param(sig, mate, a, b):
    """Name of the first parameter when sig[a:b] is a function literal `(q, r) =>`, `async (q, r) =>`, `q =>` or
    `function (q, r) {`; None otherwise."""
    j = a
    if sig[j].kind == "name" and sig[j].value == "async" and j + 1 < b:
        j += 1
    t = sig[j]
    if t.kind == "keyword" and t.value == "function":
        j += 1
        if j < b and _punct(sig[j], "*"):
            j += 1
        if j < b and sig[j].kind == "name":
            j += 1
        if j >= b or not _punct(sig[j], "("):
            return None
    elif _punct(t, "("):
        close = mate[j]
        if close < 0 or not any(_punct(x, "=>") for x in sig[close + 1:b]):
            return None
    elif t.kind == "name" and j + 1 < b and _punct(sig[j + 1], "=>"):
        return t.value
    else:
        return None
    return sig[j + 1].value if j + 1 < b and sig[j + 1].kind == "name" else None


def handler_roots(tokens):
    """[(name, start_index, end_index)]: the function literal passed last to `x.get(` `.post(` `.put(` `.patch(`
    `.delete(` `.all(` `.use(` names its first parameter a request; the span is that function, parameters and body,
    as indexes into `tokens`."""
    sig, pos = _significant(tokens)
    mate = _pairs(sig)
    roots = []
    for callee, _, _, spans, _, member in _call_sites(sig, mate):
        if not (member or "." in callee) or callee.rsplit(".", 1)[-1] not in _HANDLER_METHODS or not spans:
            continue
        a, b = spans[-1]
        name = _first_param(sig, mate, a, b) if b > a else None
        if name:
            roots.append((name, pos[a], pos[b - 1]))
    return roots


def _segments(sig, mate, k):
    """Name path starting at sig[k]: its segments and the index just past it. `a[0]` and `a[x]` are the segment "[]";
    `a['b']` is the segment "b"."""
    n = len(sig)
    segs = [sig[k].value]
    j = k + 1
    while j < n:
        u = sig[j]
        if _punct(u, *_DOTS) and j + 1 < n and _is_name(sig[j + 1]):
            segs.append(sig[j + 1].value)
            j += 2
        elif _punct(u, "[") and mate[j] > j:
            inner = sig[j + 1:mate[j]]
            seg = _text(inner[0]) if len(inner) == 1 else None
            segs.append(seg if seg else "[]")
            j = mate[j] + 1
        else:
            break
    return segs, j


def is_source(tokens, roots=None):
    """True when any name path in `tokens` is read from a request, the environment or the page: a source root
    (process.argv, req., location., prompt( ...), a `query` / `params` / `headers` / `cookies` segment, or a `body`
    segment on a request-like root or a handler's first parameter. Names only, and nothing is followed across
    statements."""
    sig, pos = _significant(tokens)
    mate = _pairs(sig)
    if roots is None:
        roots = handler_roots(tokens)
    for k, t in enumerate(sig):
        if not _is_name(t) or (k and _punct(sig[k - 1], *_DOTS)):
            continue
        segs, end = _segments(sig, mate, k)
        root = segs[0]
        if len(segs) == 1:
            if root == "searchParams" or (root == "prompt" and end < len(sig) and _punct(sig[end], "(")):
                return True
            continue
        if root in _ROOT_NAMES or root == "searchParams" or tuple(segs[:2]) in _ROOT_PREFIXES:
            return True
        for s in segs[1:]:
            if s in _SOURCE_SEGMENTS:
                return True
            if s == "body" and (root in _REQUEST_LIKE or any(name == root and a <= pos[k] <= b for name, a, b in roots)):
                return True
    return False


# ---- selftest ---------------------------------------------------------------------------------------------------------

def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if "--selftest" in argv:
        return selftest()
    sys.stderr.write("usage: python -m code_guardian.jsts --selftest\n")
    return 2


def selftest():
    from .finding import summarize

    def regexes(text, flavour="js"):
        return [t.value for t in tokenize(text, flavour) if t.kind == "regex"]

    def errs(text, flavour="js"):
        return [t.value for t in tokenize(text, flavour) if t.kind == "error"]

    def src(text):
        return is_source(tokenize(text, "js"))

    deep = "`one ${`two ${`three ${x}`}`}`"
    stray = tokenize("<p>Press the ` key</p>\n{eval(location.hash)}\n", "jsx")
    tick = [i for i, t in enumerate(stray) if t.value == "`" and t.kind == "punct"]
    sample = "var a = `x\n${b}`;\nf(/re/g, 'it\\'s');\n/* c */ g();\n"
    resync = tokenize("<p>Don't</p>{eval(location.hash)}\n", "jsx")
    call = calls(tokenize("spawn('ls', [], { shell: true, cwd: d });", "js"))[0]
    handler = tokenize("app.post('/', (q, r) => { eval(q.body.x); });\nq.body.y;\n", "js")
    checks = [
        ("regex_division_chain", regexes("x = a / b / c;") == []),
        ("regex_escaped_slash", regexes("re = /\\//g;") == ["/\\//g"]),
        ("regex_after_return", regexes("function f(s) { return /ab+c/i.test(s); }") == ["/ab+c/i"]),
        ("division_after_paren", regexes("y = f(a) / 2;") == []),
        ("division_after_bracket", regexes("y = arr[0] / 2;") == []),
        ("regex_after_typeof", regexes("t = typeof /x/;") == ["/x/"]),
        ("regex_in_ternary", regexes("r = ok ? /a/ : /b/g;") == ["/a/", "/b/g"]),
        ("regex_in_array", regexes("list = [/a/, /b/];") == ["/a/", "/b/"]),
        ("divide_assign", regexes("x /= 2; y = x / 3;") == []),
        ("regex_after_case", regexes("switch (s) { case /x/: break; }") == ["/x/"]),
        ("jsx_close_tag", regexes("const e = <div>a</div>;", "jsx") == [] and not errs("const e = <div>a</div>;", "jsx")),
        ("jsx_a_close_b", regexes("a </b> c", "jsx") == [] and not errs("a </b> c", "jsx")),
        ("regex_class_holds_slash", regexes("x = /[/]a/;") == ["/[/]a/"]),
        ("jsx_url_is_not_a_comment", not [t for t in tokenize("<a>https://example.org</a>; eval(x);", "jsx") if t.kind == "comment"]),
        ("template_three_deep", [(t.kind, t.value) for t in tokenize(deep, "js")] == [("template", deep)]),
        ("string_resync_one_token", [t.value for t in resync if t.kind == "error"] == ["string"]
         and [t.value for t in resync if t.kind == "name" and t.value != "p"] == ["Don", "t", "eval", "location", "hash"]),
        ("eof_template", errs("x = `abc\n", "ts") == ["template"]),
        ("eof_comment", errs("x = 1; /* abc\n") == ["comment"]),
        ("eof_regex", errs("x = /abc") == ["regex"]),
        ("stray_backtick_relexed", not [t for t in stray if t.kind == "error"] and len(tick) == 1
         and all(t.flags == "relexed" for t in stray[tick[0] + 1:]) and all(t.flags == "" for t in stray[:tick[0]])),
        ("stray_backtick_ts_fails", errs("<p>Press the ` key</p>\n", "ts") == ["template"]),
        ("crlf_equals_lf", tokenize(sample.replace("\n", "\r\n"), "js") == tokenize(sample, "js")
         and tokenize(sample.replace("\n", "\r"), "js") == tokenize(sample, "js")),
        ("pure", tokenize(sample, "js") == tokenize(sample, "js")),
        ("line_numbers", [(t.value, t.line) for t in tokenize(sample, "js") if t.value in (";", "f", "g")]
         == [(";", 2), ("f", 3), (";", 3), ("g", 4), (";", 4)]),
        ("hashbang", tokenize("#!/usr/bin/env node\nx();\n", "js")[0].kind == "comment"),
        ("modern_syntax", not errs("class B { #h = 10n; n = 1_000_000; t() { return this.l?.t ?? 'f'; } }\n@sealed\nx = <T,>(v: T) => v;", "tsx")),
        ("shape_calls", [(c.callee, len(c.args), c.line, c.new) for c in calls(tokenize("a.b?.c(1, f(2,3));\nnew Function('a');", "js"))]
         == [("a.b?.c", 2, 1, False), ("f", 2, 1, False), ("Function", 1, 2, True)]),
        ("shape_imports", [(i.spec, i.kind) for i in imports(tokenize("import a from 'x';\nexport * from 'v';\nrequire('u');\nimport(n);", "js"))]
         == [("x", "import"), ("v", "export_from"), ("u", "require"), (None, "computed")]),
        ("shape_assigns", [(a.target, a.line) for a in assigns(tokenize("el.innerHTML = post.body;\na.innerHTMLx = 1;", "js"), "innerHTML")]
         == [("el.innerHTML", 1)]),
        ("shape_props", sorted(props(call.args[2])) == ["cwd", "shell"]),
        ("shape_literal", literal(call.args[0]) == "ls" and literal(tokenize("`ls ${x}`", "js")) is None),
        ("source_segment", src("q.query.x") is True and src("this.query.limit") is True and src("queryClient.fetch(x)") is False),
        ("source_roots", src("req.user.name") is True and src("process.argv[2]") is True and src("prompt('x')") is True
         and src("'query'") is False),
        ("source_body", src("ctx.request.body.x") is True and src("document.body.innerHTML") is False
         and src("post.body") is False and src("q.body.x") is False),
        ("source_handler_root", is_source(handler) is True and [r[0] for r in handler_roots(handler)] == ["q"]),
        ("tokens_json_stable", json.dumps(tokenize(sample, "js")) == json.dumps(tokenize(sample, "js"))),
        ("long_line_is_linear", len(tokenize("x = [" + ", ".join("a%d / b" % i for i in range(20000)) + "];", "js")) > 60000),
    ]
    return summarize("jsts", checks)


if __name__ == "__main__":
    sys.exit(main())
