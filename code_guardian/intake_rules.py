"""Repo-intake rules: deterministic checks that read a quarantined copy of a repository as DATA. Nothing here runs,
imports or installs anything from the scanned tree.

Rule ids are `group.name`. Every finding records the file, the line, the rule id, the confidence (low / medium / high)
and the exact text that matched (control and invisible characters are shown as \\uXXXX escapes, long text is cut and
says by how much). Confidence is how likely a hit is to be a real problem rather than a false positive; generic
heuristics are low or medium on purpose. A rule that fires is a reason to look, not proof of harm.

These categories follow public write-ups on repo-borne malware; the rules, patterns and code are written
independently for this project.

Public contract:
    RULES                      {rule id: {"title", "means", "false_positives"}}
    CONFIDENCES                ("low", "medium", "high")
    finding(rule, confidence, file, line, match, summary=None) -> dict
    show(text, limit=MATCH_MAX) -> text with invisible characters escaped and long text cut
    Ctx(root, manifest)        read-only view of the copy: .files, .text(rel), .head(rel, n), .lines(rel)
    run_all(ctx) -> (findings, errors)
"""

import os
import unicodedata

CONFIDENCES = ("low", "medium", "high")
MATCH_MAX = 240
TEXT_MAX = 5_000_000
SNIFF = 8192

RULES = {
    "hash.known_bad": {
        "title": "File matches a known-bad hash",
        "means": "A file in the project has the same SHA-256 as a sample on the known-bad list you supplied. This is "
                 "the one check that is an exact match, not a pattern, and it always forces the malicious verdict.",
        "false_positives": "Only a wrong or stale entry on your own list; the shipped list is empty.",
    },
}

CHECKS = []  # [(name, fn(ctx) -> [finding])], filled by the check groups below


def show(text, limit=MATCH_MAX):
    """text made safe to print: control, format (zero-width, bidi, tag) and private-use characters become \\uXXXX, and
    text over `limit` characters is cut with the number of characters left off."""
    out = []
    for ch in text:
        cat = unicodedata.category(ch)
        if ch in "\t" or cat[0] not in "CZ" or ch == " ":
            out.append(ch)
        elif cat == "Zs" and ch != " ":
            out.append(ch)
        else:
            out.append("\\u%04x" % ord(ch) if ord(ch) <= 0xFFFF else "\\U%08x" % ord(ch))
    s = "".join(out)
    return s if len(s) <= limit else s[:limit] + " [...+%d chars]" % (len(s) - limit)


def finding(rule, confidence, file, line, match, summary=None):
    if confidence not in CONFIDENCES:
        raise ValueError("unknown confidence: %r" % (confidence,))
    info = RULES[rule]
    return {"rule": rule, "confidence": confidence, "file": file, "line": int(line), "match": show(str(match)),
            "summary": summary or info["title"], "why": info["means"], "false_positives": info["false_positives"]}


class Ctx:
    """Read-only view of the quarantined copy. `manifest` is {rel: {"size", "sha256", "truncated"}}."""

    def __init__(self, root, manifest):
        self.root = root
        self.manifest = manifest
        self.files = sorted(manifest)
        self._text = {}

    def path(self, rel):
        return os.path.join(self.root, *rel.split("/"))

    def head(self, rel, n=SNIFF):
        try:
            with open(self.path(rel), "rb") as fh:
                return fh.read(n)
        except OSError:
            return b""

    def is_binary(self, rel):
        return b"\0" in self.head(rel)

    def text(self, rel):
        """The file decoded as UTF-8 (replacement on bad bytes), or None for a binary, truncated or oversized file."""
        if rel in self._text:
            return self._text[rel]
        info = self.manifest.get(rel, {})
        out = None
        if not info.get("truncated") and info.get("size", 0) <= TEXT_MAX and not self.is_binary(rel):
            try:
                with open(self.path(rel), "rb") as fh:
                    out = fh.read().decode("utf-8", errors="replace")
            except OSError:
                out = None
        self._text[rel] = out
        return out

    def lines(self, rel):
        t = self.text(rel)
        return [] if t is None else t.split("\n")


def run_all(ctx):
    """Every registered check; a check that raises is reported in `errors` and never stops the others."""
    findings, errors = [], []
    for name, fn in CHECKS:
        try:
            findings.extend(fn(ctx))
        except Exception as exc:  # noqa: BLE001 - one broken rule must not hide the rest
            errors.append({"check": name, "error": "%s: %s" % (type(exc).__name__, str(exc)[:200])})
    return findings, errors
