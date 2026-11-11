"""Repo intake, hidden code: ways to bury a payload where a reader scrolling the file will not see it. Text only.

    hidden.long_line        a code line of 2,000 or more characters (minified files get low confidence)
    hidden.whitespace_pad   code pushed far to the right behind 150+ spaces or tabs
    hidden.oversized_file   a single source file over 1 MB
    hidden.high_entropy     a long base64 or hex blob that looks packed (random-looking) inside a source file
    hidden.blob_to_exec     encoded data fed to exec / eval / iex in the same statement
"""

import re

from . import intake_rules as R
from .intake_rules import check, finding

R.RULES.update({
    "hidden.long_line": {
        "title": "Very long line of code",
        "means": "A source file has a line of thousands of characters. A reader sees the start of the line and the "
                 "scrollbar, not what is far to the right, which is where payloads get hidden.",
        "false_positives": "Minified or generated code, embedded data tables and bundled assets all look like this "
                           "(minified names get low confidence).",
    },
    "hidden.whitespace_pad": {
        "title": "Code pushed far right behind whitespace",
        "means": "A line has 150 or more spaces or tabs and then more code. In an editor the line looks empty or short, "
                 "and the code only shows if you scroll right.",
        "false_positives": "Rare in honest code. Aligned data tables and very deep indentation can trip it (medium).",
    },
    "hidden.oversized_file": {
        "title": "Single source file over 1 MB",
        "means": "One source file is unusually large. Big files are hard to read through and are a common place to "
                 "hide a small payload among a lot of normal-looking code.",
        "false_positives": "Generated code, vendored libraries and data-as-code files are often this big.",
    },
    "hidden.high_entropy": {
        "title": "Packed-looking blob inside source code",
        "means": "A string of 300 or more base64 or hex characters whose letters look random, the way compressed or "
                 "encrypted data does. Packed payloads are stored like this and decoded when the program runs.",
        "false_positives": "Embedded fonts, images, certificates and test vectors look identical to this check.",
    },
    "hidden.blob_to_exec": {
        "title": "Encoded data is decoded and executed",
        "means": "In one statement, base64, hex or compressed data is decoded and passed to exec, eval or Invoke-"
                 "Expression. Honest code almost never hides what it runs; this is how packed payloads start.",
        "false_positives": "Rare. A plugin loader that decodes bundled code on purpose can look the same. Medium "
                           "confidence means the data came from a variable, not a literal in the line.",
    },
})

LONG_LINE = 2000
PAD = re.compile(r"[ \t]{150,}(?=\S)")
OVERSIZED = 1_000_000
B64_BLOB = re.compile(r"[A-Za-z0-9+/]{300,}={0,2}")
HEX_BLOB = re.compile(r"(?<![0-9A-Za-z])[0-9a-fA-F]{300,}(?![0-9A-Za-z])")
EXEC_TOKEN = re.compile(r"(?i)\b(?:exec|eval|execfile)\s*\(|\bnew\s+Function\b|\bFunction\s*\(|\biex\b|\binvoke-expression\b|"
                        r"\bos\.system\s*\(|\bsubprocess\.\w+\s*\(")
DECODE_TOKEN = re.compile(r"(?i)b64decode|\batob\s*\(|fromhex|unhexlify|FromBase64String|decompress|base64|marshal\.loads|"
                          r"codecs\.decode|(?:\\x[0-9a-f]{2}){8,}")
LITERAL_BLOB = re.compile(r"""['"][A-Za-z0-9+/=_\-]{40,}['"]""")


@check("hidden.long_line")
def long_line(ctx):
    out = []
    for rel in ctx.files:
        if not R.is_code(rel):
            continue
        for i, line in enumerate(ctx.lines(rel), 1):
            if len(line) >= LONG_LINE:
                out.append(finding("hidden.long_line", "low" if R.MINIFIED.search(rel) else "medium", rel, i,
                                   "(%d characters) %s" % (len(line), line.strip()),
                                   "line %d is %d characters long" % (i, len(line))))
                break  # one per file: the first is enough to look at
    return out


@check("hidden.whitespace_pad")
def whitespace_pad(ctx):
    out = []
    for rel in ctx.files:
        if not R.is_code(rel):
            continue
        for i, line in enumerate(ctx.lines(rel), 1):
            m = PAD.search(line)
            if not m:
                continue
            before, after = line[:m.start()].strip(), line[m.end():].strip()
            conf = "high" if before and EXEC_TOKEN.search(after) else "medium"
            out.append(finding("hidden.whitespace_pad", conf, rel, i,
                               "%s [%d whitespace characters] %s" % (before[:80], m.end() - m.start(), after[:120]),
                               "code sits %d whitespace characters to the right" % (m.end() - m.start())))
            break
    return out


@check("hidden.oversized_file")
def oversized_file(ctx):
    return [finding("hidden.oversized_file", "medium", rel, 0, "%.1f MB" % (info["size"] / 1e6),
                    "source file is %.1f MB" % (info["size"] / 1e6))
            for rel, info in ctx.manifest.items() if R.is_code(rel) and info["size"] > OVERSIZED and not R.MINIFIED.search(rel)]


@check("hidden.high_entropy")
def high_entropy(ctx):
    out = []
    for rel in ctx.files:
        if not R.is_code(rel) or R.MINIFIED.search(rel):
            continue
        n = 0
        for i, line in enumerate(ctx.lines(rel), 1):
            if len(line) < 300:
                continue
            for rx, floor in ((B64_BLOB, 4.8), (HEX_BLOB, 3.5)):
                for m in rx.finditer(line):
                    if "data:" in line[max(0, m.start() - 60):m.start()]:
                        continue
                    e = R.entropy(m.group(0))
                    if e >= floor:
                        n += 1
                        if n == 1:
                            out.append(finding("hidden.high_entropy", "medium" if rx is B64_BLOB else "low", rel, i,
                                               "%s... (%d chars, entropy %.2f bits/char)" % (m.group(0)[:60], len(m.group(0)), e),
                                               "random-looking blob of %d characters" % len(m.group(0))))
    return out


@check("hidden.blob_to_exec")
def blob_to_exec(ctx):
    out = []
    for rel in ctx.files:
        if not R.is_code(rel):
            continue
        lines = ctx.lines(rel)
        for i, line in enumerate(lines):
            if not EXEC_TOKEN.search(line):
                continue
            window = " ".join(lines[i:i + 3])
            if not DECODE_TOKEN.search(window):
                continue
            conf = "high" if LITERAL_BLOB.search(window) or re.search(r"(?:\\x[0-9a-f]{2}){8,}", window) else "medium"
            out.append(finding("hidden.blob_to_exec", conf, rel, i + 1, line.strip(),
                               "decoded data is passed to exec/eval%s" % (" (the data is in the line)" if conf == "high" else "")))
    return out
