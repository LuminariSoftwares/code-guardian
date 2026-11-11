"""Repo intake, executables: a Windows or other native executable is not source code, and one that sits under an image
or document name is how a payload gets past a reader.

    binary.disguised_executable   file starts like a PE (MZ), ELF or Mach-O program but is named like an image, text,
                                  document or data file (or has a document extension before .exe)
    binary.embedded_executable    a program of that kind shipped in the repo under an executable name, or a program
                                  written out as base64 or hex text inside another file

Read from file headers only (the first bytes); the file is never run, loaded or opened by anything but this reader.
"""

import base64
import re
import struct

from . import intake_rules as R
from .intake_rules import check, finding

R.RULES.update({
    "binary.disguised_executable": {
        "title": "Program file with a harmless-looking name",
        "means": "The first bytes of this file are those of a Windows (MZ/PE), Linux (ELF) or macOS (Mach-O) program, "
                 "but its name says image, text, document or data. Nothing legitimate is stored like that; it is how "
                 "a program is smuggled past someone skimming the file list.",
        "false_positives": "Very rare. A mislabelled build artifact is the usual honest explanation.",
    },
    "binary.embedded_executable": {
        "title": "Executable shipped inside the repo",
        "means": "The repo contains a compiled program, or a program written out as base64 or hex text. Source "
                 "repositories normally ship source; a binary cannot be read to see what it does.",
        "false_positives": "Some projects vendor tools, drivers or native libraries on purpose (.dll / .so files are "
                           "low confidence, an .exe is medium).",
    },
})

EXEC_STRONG = frozenset({".exe", ".scr", ".com", ".cpl", ".msi"})
EXEC_LIB = frozenset({".dll", ".sys", ".ocx", ".drv", ".efi", ".so", ".dylib", ".o", ".a", ".pyd", ".node", ".elf", ".out", ".ko", ".bundle"})
NEUTRAL = frozenset({".bin", ".exe~", ""})
DOC_EXT = frozenset({".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf", ".jpg", ".jpeg", ".png", ".gif", ".bmp",
                     ".ico", ".mp3", ".mp4", ".zip", ".csv", ".md"})
MACHO_MAGIC = {bytes.fromhex(h) for h in ("feedface", "feedfacf", "cefaedfe", "cffaedfe")}
B64_PE = re.compile(r"TV[pqroABCDEFGH][A-Za-z0-9+/]{200,}")
HEX_PE = re.compile(r"(?i)4d5a[0-9a-f]{4}(?:00|03|01)[0-9a-f]{200,}")


def _kind(ctx, rel):
    """"Windows executable (PE)", "Linux executable (ELF)", "macOS executable (Mach-O)" or None, from the first bytes."""
    head = ctx.head(rel, 4096)
    if head[:2] == b"MZ" and len(head) >= 0x40:
        off = struct.unpack("<I", head[0x3C:0x40])[0]
        sig = head[off:off + 4] if off + 4 <= len(head) else (ctx.head(rel, off + 4)[off:off + 4] if off < 1_000_000 else b"")
        if sig == b"PE\0\0":
            return "Windows executable (PE)"
    if head[:4] == b"\x7fELF":
        return "Linux executable (ELF)"
    if head[:4] in MACHO_MAGIC:
        return "macOS executable (Mach-O)"
    if head[:4] == bytes.fromhex("cafebabe") and len(head) >= 8 and struct.unpack(">I", head[4:8])[0] < 20:
        return "macOS universal executable (Mach-O)"  # a Java .class file has a version number of 45 or more here
    return None


def _disguised(rel):
    ext = R.ext(rel)
    if ext in EXEC_STRONG and len(rel.rsplit("/", 1)[-1].rsplit(".", 2)) == 3:
        return R.ext(rel[:-len(ext)]) in DOC_EXT  # invoice.pdf.exe
    return ext not in EXEC_STRONG | EXEC_LIB | NEUTRAL


@check("binary.executables")
def executables(ctx):
    out = []
    for rel in ctx.files:
        kind = _kind(ctx, rel)
        if not kind:
            continue
        head = ctx.head(rel, 16).hex()
        if _disguised(rel):
            out.append(finding("binary.disguised_executable", "high", rel, 0, "%s  %s" % (head, kind),
                               "%s named like a %s file" % (kind, R.ext(rel).lstrip(".") or "plain")))
        else:
            ext = R.ext(rel)
            conf = "medium" if ext in EXEC_STRONG or ext in NEUTRAL else "low"
            out.append(finding("binary.embedded_executable", conf, rel, 0, "%s  %s" % (head, kind), "%s shipped in the repo" % kind))
    return out


@check("binary.executable_as_text")
def executable_as_text(ctx):
    out = []
    for rel in ctx.files:
        text = ctx.text(rel)
        if not text or len(text) < 200 or R.ext(rel) in (".svg", ".json", ".lock", ".map"):
            continue
        for rx, how in ((B64_PE, "base64"), (HEX_PE, "hex")):
            m = rx.search(text)
            if not m:
                continue
            if how == "base64":
                try:
                    if base64.b64decode(m.group(0)[:128] + "=" * (-len(m.group(0)[:128]) % 4))[:2] != b"MZ":
                        continue
                except ValueError:
                    continue
            out.append(finding("binary.embedded_executable", "high", rel, text.count("\n", 0, m.start()) + 1,
                               "%s... (%s text, %d chars)" % (m.group(0)[:40], how, len(m.group(0))),
                               "a Windows executable written out as %s text" % how))
            break
    return out
