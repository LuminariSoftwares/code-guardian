"""Repo intake, text a person cannot see and text written for an AI agent instead of a person.

    text.invisible_unicode     zero-width, bidirectional-override and tag characters inside a text file
    text.agent_instructions    wording aimed at an AI coding agent: drop your instructions, hide this from the user,
                               send keys somewhere, run this command

Read from README / docs, agent instruction files (CLAUDE.md, AGENTS.md, GEMINI.md, SKILL.md, .cursorrules, Cursor
rules, Copilot instructions, MCP configs) and the comments of source files. Where the text sits decides the
confidence: inside an HTML comment or an agent file is higher than visible README prose; a line that is plainly
discussing prompt injection (quoting the phrase, "detects", "example") is lowered one step.
"""

import re
import unicodedata

from . import intake_rules as R
from .intake_rules import check, finding, command_signal

R.RULES.update({
    "text.invisible_unicode": {
        "title": "Invisible characters in a text file",
        "means": "The file contains zero-width, bidirectional-override or Unicode tag characters. They do not show on "
                 "screen but change what a program or an AI model reads: bidi overrides make code display in a "
                 "different order than it runs, and tag characters can carry a hidden instruction.",
        "false_positives": "Zero-width spaces get pasted into docs by accident (medium). Joiners inside emoji sequences "
                           "and between letters of scripts that use them, and a byte-order mark at the start, are ignored.",
    },
    "text.agent_instructions": {
        "title": "Text aimed at an AI agent",
        "means": "The file contains wording that tries to steer an AI coding assistant that reads it: to ignore its "
                 "instructions, to hide something from the user, to send keys or tokens somewhere, or to run a command. "
                 "An assistant that opens this repo may obey text a human reviewer never notices.",
        "false_positives": "Security tools, tutorials and test data quote these phrases on purpose (those lines are lowered "
                           "to low). Ordinary instructions like \"run the tests\" in AGENTS.md are not reported.",
    },
})

ZERO_WIDTH = {0x200B, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0x180E, 0xFEFF}
JOINERS = {0x200C, 0x200D}
BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A)) | {0x200E, 0x200F, 0x061C}
TAGS = range(0xE0000, 0xE0080)
AGENT_FILE = re.compile(r"(?i)(?:^|/)(?:CLAUDE|AGENTS|GEMINI|SKILL|COPILOT-INSTRUCTIONS|\.cursorrules|\.windsurfrules|\.clinerules|"
                        r"mcp\.json|\.mcp\.json)(?:\.md)?$|(?:^|/)\.(?:cursor/rules|claude|github|windsurf|clinerules)/[^/]+$|\.mdc$")
DOC_EXT = frozenset({".md", ".markdown", ".txt", ".rst", ".adoc", ".mdx"})
COMMENT_LINE = re.compile(r"^\s*(?:#|//|/\*|\*|--|;|<!--|rem\b)", re.I)
DISCUSSING = re.compile(r"(?i)injection|detect|jailbreak|attack|malicious|vulnerab|\bexamples?\b|test (?:case|data|input)|"
                        r"e\.g\.|for instance|such as|\bscanner\b|\bpayloads?\b|[\"'`“”][^\"'`“”]*(?:instructions?)[^\"'`“”]*[\"'`“”]")

AGENT_PATTERNS = (
    ("override", re.compile(r"(?i)\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(?:previous|prior|above|earlier|all|any|your|"
                            r"system)\b[^.\n]{0,30}\b(?:instructions?|rules|prompts?|guidelines|polic(?:y|ies)|safety)\b")),
    ("conceal", re.compile(r"(?i)\b(?:do not|don't|never|without)\b[^.\n]{0,30}\b(?:tell|inform|mention|reveal|show|notify|alert)\b"
                           r"[^.\n]{0,30}\b(?:the user|user|human|operator)\b")),
    ("exfil", re.compile(r"(?i)\b(?:send|post|upload|transmit|forward|leak|copy|email|mail)\b[^\n]{0,80}\b(?:api[ _-]?keys?|tokens?|"
                         r"secrets?|credentials?|passwords?|\.env\b|ssh keys?|private keys?|id_rsa|cookies|wallet|seed phrase)\b"
                         r"[^\n]{0,80}(?:https?://|\bto\s+(?:a |the |my |our |this )?(?:server|webhook|endpoint|url|address|remote|"
                         r"attacker|me\b)|@\w)|\bexfiltrat\w*\b")),
    ("role_hijack", re.compile(r"(?i)\byou are (?:now|no longer)\b|\bnew (?:system )?instructions?\b|\bact as (?:an? )?(?:unrestricted|"
                               r"jailbroken|root)\b|<\s*/?\s*(?:system|important|instructions?)\s*>")),
    ("run_command", re.compile(r"(?i)\b(?:you must|you should|please|always|first|now)\b[^.\n]{0,40}\b(?:run|execute|invoke)\b"
                               r"[^.\n]{0,40}\b(?:command|script|shell|terminal|bash|powershell|curl|wget)\b")),
    ("ai_addressed", re.compile(r"(?i)\b(?:attention|note to|dear|hey)\b[^.\n]{0,15}\b(?:ai|llm|assistant|agent|claude|copilot|gpt|model)s?\b|"
                                r"\b(?:ai|llm) (?:agents?|assistants?|models?)\b[^.\n]{0,30}\b(?:must|should|will|please|ignore|run)\b")),
)
STRONG = ("override", "conceal", "exfil")


def _bump(conf, steps):
    return R.CONFIDENCES[max(0, min(2, R.CONFIDENCES.index(conf) + steps))]


def _invisible(ch, prev, nxt):
    cp = ord(ch)
    if cp in BIDI or cp in TAGS:
        return "bidi/tag"
    if cp in ZERO_WIDTH:
        return "zero-width"
    if cp in JOINERS:  # legitimate between emoji and between letters of joining scripts; hidden between ASCII
        if prev and nxt and ord(prev) < 0x2E80 and ord(nxt) < 0x2E80 and unicodedata.category(prev)[0] in "LNP" \
                and ord(prev) < 0x250 and ord(nxt) < 0x250:
            return "zero-width"
    return None


@check("text.invisible_unicode")
def invisible_unicode(ctx):
    out = []
    for rel in ctx.files:
        text = ctx.text(rel)
        if not text or text.isascii():
            continue
        hits, first = {}, None
        for pos, ch in enumerate(text):
            if ord(ch) < 0x61C:
                continue
            if pos == 0 and ord(ch) == 0xFEFF:
                continue
            kind = _invisible(ch, text[pos - 1] if pos else "", text[pos + 1] if pos + 1 < len(text) else "")
            if kind:
                hits.setdefault(kind, []).append("U+%04X" % ord(ch))
                if first is None:
                    first = pos
        if first is not None:
            line_no = text.count("\n", 0, first) + 1
            line = text.split("\n")[line_no - 1]
            strict = "bidi/tag" in hits or bool(AGENT_FILE.search(rel)) or R.is_code(rel) or R.ext(rel) in (".json", ".yml", ".yaml", ".toml")
            conf = "high" if strict else "medium"
            codes = sorted({c for v in hits.values() for c in v})
            total = sum(len(v) for v in hits.values())
            out.append(finding("text.invisible_unicode", conf, rel, line_no, line.strip(),
                               "%d invisible character%s (%s)" % (total, "" if total == 1 else "s", ", ".join(codes[:6]))))
    return out


def _comment_spans(text):
    return [(m.start(), m.end()) for m in re.finditer(r"<!--.*?-->", text, re.S)]


@check("text.agent_instructions")
def agent_instructions(ctx):
    out = []
    for rel in ctx.files:
        agent = bool(AGENT_FILE.search(rel))
        doc = R.ext(rel) in DOC_EXT
        code = R.is_code(rel)
        if not (agent or doc or code):
            continue
        text = ctx.text(rel)
        if not text:
            continue
        spans = _comment_spans(text) if (agent or doc) else []
        offset, seen = 0, {}
        for i, line in enumerate(text.split("\n"), 1):
            start, offset = offset, offset + len(line) + 1
            if code:  # only the comment part of a source line is prose
                if not COMMENT_LINE.match(line):
                    m = re.search(r"\s(?:#|//)\s", line)
                    if not m:
                        continue
                    line = line[m.end():]
            hidden = any(a <= start < b for a, b in spans)
            if agent and "run_command" not in seen and command_signal(line) in ("fetch_exec", "obfuscated_exec"):
                seen["run_command"] = True
                out.append(finding("text.agent_instructions", "high", rel, i, line.strip(),
                                   "instruction file tells the agent to fetch and run code"))
            for kind, rx in AGENT_PATTERNS:
                m = rx.search(line)
                if not m or kind in seen:
                    continue
                if agent:
                    conf = "high" if kind in STRONG or kind == "role_hijack" else None
                    if kind == "run_command" and command_signal(line) in ("fetch_exec", "obfuscated_exec"):
                        conf = "high"
                    if kind == "ai_addressed":
                        conf = None
                elif doc:
                    conf = {"override": "medium", "conceal": "medium", "exfil": "medium", "role_hijack": "medium",
                            "run_command": "low", "ai_addressed": "low"}[kind]
                else:
                    conf = "medium" if kind in STRONG else "low"
                if conf is None:
                    continue
                if hidden:
                    conf = "high" if kind != "ai_addressed" else "medium"
                if DISCUSSING.search(re.sub(r"https?://\S+", "", line)) and not hidden:
                    conf = _bump(conf, -1)
                seen[kind] = True
                out.append(finding("text.agent_instructions", conf, rel, i, line.strip(),
                                   "%s wording aimed at an AI agent%s" % (kind.replace("_", " "), " (inside an HTML comment)" if hidden else "")))
    return out
