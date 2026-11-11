"""Repo intake: should you open, install or run this repository? A first look at an UNTRUSTED repo before it touches
your machine, aimed at the attack classes that ride in a repository itself (auto-run hooks, hidden code, invisible
text, disguised executables, code that runs on import, download lures, hollow repos, known-bad files).

Deterministic and standard library only: no model, no network (the optional stars signal is separate), nothing from
the scanned repository is ever executed, imported, installed or followed. The folder is first copied into a
temporary read-only quarantine (symlinks, device files and the .git folder are not copied; only non-sample git hooks
are) and every check reads that copy as data, so the working clone is never scanned in place and never touched.

Trust model: every verdict is ADVISORY. A finding is a reason to look, not proof of harm, and "no checks fired" is not
a guarantee. Findings carry a confidence (low / medium / high) because generic heuristics can false-positive.

    verdict "malicious"      a file matches the known-bad hash list
    verdict "suspicious"     at least one high-confidence finding
    verdict "review"         medium-confidence findings, nothing higher
    verdict "weak_signals"   only low-confidence findings
    verdict "nothing_flagged" no check fired (not a guarantee)

Public contract:
    scan(path, bad_hashes=None, env=None) -> result dict       UsageError
    load_bad_hashes(path=None, env=None) -> {sha256 hex: label}
    verdict_of(findings, known_bad=False, check_errors=0) -> {"level", "trust", "text"}
    exit_code(result, fail_on="high") -> 0 or 1
    render(result) -> text      to_json(result) -> str      to_sarif(result) -> dict
"""

import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
from pathlib import Path

from . import __version__, intake_binary, intake_code, intake_hidden, intake_hollow, intake_hooks, intake_rules as rules, intake_text  # noqa: F401 - importing a group registers its checks
from .finding import summarize
from .scanners import redact_report

SCHEMA_VERSION = 1
HASH_FILE = Path(__file__).resolve().parent / "data" / "known_bad_hashes.json"
HASH_ENV = "CODE_GUARDIAN_BAD_HASHES"
SKIP_DIRS = frozenset({"node_modules", ".venv", "venv", "__pycache__"})
MAX_FILES = 50_000
MAX_COPY_BYTES = 25_000_000     # a larger file is hashed whole, but only its first HEAD_BYTES are copied
HEAD_BYTES = 65_536
CHUNK = 1 << 20
RANK = {"low": 0, "medium": 1, "high": 2}
CAVEAT = ("This check is advisory. It looks for known patterns in the files; a clean result is not a guarantee, and "
          "a finding is a reason to read, not proof of harm.")
HEX64 = re.compile(r"[0-9a-fA-F]{64}")
SARIF_SCHEMA = ("https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/"
                "sarif-schema-2.1.0.json")
SARIF_LEVEL = {"high": "error", "medium": "warning", "low": "note"}


class UsageError(Exception):
    pass


# ---- known-bad hash list (item 7) ----------------------------------------------------------------------------------

def _read_hash_file(path):
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as exc:
        raise UsageError("cannot read hash list %s: %s" % (os.path.basename(str(path)), exc)) from None
    if not isinstance(doc, dict) or doc.get("schema_version") != 1 or not isinstance(doc.get("sha256"), dict):
        raise UsageError('hash list %s must be {"schema_version": 1, "sha256": {digest: label}}'
                         % os.path.basename(str(path)))
    bad = [k for k in doc["sha256"] if not HEX64.fullmatch(str(k))]
    if bad:
        raise UsageError("hash list %s: %d entr%s not a 64-character SHA-256 hex digest (first: %r)"
                         % (os.path.basename(str(path)), len(bad), "y is" if len(bad) == 1 else "ies are", bad[0][:20]))
    return {k.lower(): str(v) for k, v in doc["sha256"].items()}


def load_bad_hashes(path=None, env=None):
    """The shipped list (empty) merged with the file named by CODE_GUARDIAN_BAD_HASHES and with `path`."""
    env = os.environ if env is None else env
    out = _read_hash_file(HASH_FILE)
    for extra in (env.get(HASH_ENV), path):
        if extra:
            out.update(_read_hash_file(extra))
    return out


# ---- quarantine (item 8) -------------------------------------------------------------------------------------------

def _copy_file(src, dest, rel):
    """Copy one regular file into the quarantine, hashing the whole file as it streams. Returns the manifest entry."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(src, flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("not a regular file")
        digest, size, kept = hashlib.sha256(), 0, 0
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with os.fdopen(fd, "rb", closefd=False) as fh, open(dest, "wb") as out:
            while True:
                chunk = fh.read(CHUNK)
                if not chunk:
                    break
                digest.update(chunk)
                size += len(chunk)
                if kept < (MAX_COPY_BYTES if size <= MAX_COPY_BYTES else HEAD_BYTES):
                    room = (MAX_COPY_BYTES if size <= MAX_COPY_BYTES else HEAD_BYTES) - kept
                    out.write(chunk[:room])
                    kept += min(len(chunk), room)
        truncated = size > MAX_COPY_BYTES
        if truncated:  # keep only the head of an oversized file
            with open(dest, "r+b") as out:
                out.truncate(HEAD_BYTES)
        return {"size": size, "sha256": digest.hexdigest(), "truncated": truncated}
    finally:
        os.close(fd)


def _quarantine(src, dest):
    """Copy src into dest as a read-only tree. Returns (manifest, skipped, skipped_dirs)."""
    manifest, skipped, skipped_dirs = {}, [], []
    stack = [("", src)]
    while stack:
        rel_dir, path = stack.pop()
        try:
            entries = sorted(os.scandir(path), key=lambda e: e.name)
        except OSError:
            skipped.append({"file": rel_dir or ".", "reason": "unreadable folder"})
            continue
        for entry in entries:
            rel = rel_dir + entry.name
            if entry.is_symlink():
                skipped.append({"file": rel, "reason": "symlink"})
            elif entry.is_dir(follow_symlinks=False):
                if entry.name == ".git":
                    hooks = os.path.join(entry.path, "hooks")
                    if os.path.isdir(hooks) and not os.path.islink(hooks):
                        stack.append((rel + "/hooks/", hooks))  # shipped git hooks are checked; .git is not copied
                    continue
                if entry.name in SKIP_DIRS:
                    skipped_dirs.append({"dir": rel, "reason": "not scanned"})
                    continue
                stack.append((rel + "/", entry.path))
            elif entry.is_file(follow_symlinks=False):
                if rel_dir.startswith(".git/hooks") and entry.name.endswith(".sample"):
                    continue
                if len(manifest) >= MAX_FILES:
                    skipped.append({"file": rel, "reason": "too many files"})
                    continue
                try:
                    manifest[rel] = _copy_file(entry.path, os.path.join(dest, *rel.split("/")), rel)
                except OSError as exc:
                    skipped.append({"file": rel, "reason": "could not copy (%s)" % type(exc).__name__})
            else:
                skipped.append({"file": rel, "reason": "not a regular file"})
    return dict(sorted(manifest.items())), sorted(skipped, key=lambda s: s["file"]), sorted(skipped_dirs, key=lambda s: s["dir"])


def _lock(root):
    """Make the copy read-only: files 0444, folders 0555 (bottom-up)."""
    for dp, _dns, fns in os.walk(root, topdown=False):
        for fn in fns:
            os.chmod(os.path.join(dp, fn), 0o444)
        os.chmod(dp, 0o555)


def _unlock_and_remove(root):
    for dp, _dns, fns in os.walk(root):
        os.chmod(dp, 0o700)
        for fn in fns:
            try:
                os.chmod(os.path.join(dp, fn), 0o600)
            except OSError:
                pass
    shutil.rmtree(root, ignore_errors=True)


# ---- the scan ------------------------------------------------------------------------------------------------------

def _hash_findings(manifest, bad):
    out = []
    for rel, info in manifest.items():
        label = bad.get(info["sha256"])
        if label is not None:
            out.append(rules.finding("hash.known_bad", "high", rel, 0, "%s  (%s)" % (info["sha256"], label),
                                     "matches known-bad hash: %s" % label))
    return out


def _analyse(copy_root, manifest, bad):
    """Run every check on the read-only copy. Returns (findings, check errors)."""
    findings, errors = rules.run_all(rules.Ctx(copy_root, manifest))
    findings.extend(_hash_findings(manifest, bad))
    return findings, errors


def _sorted(findings):
    return sorted(findings, key=lambda f: (-RANK[f["confidence"]], f["file"], f["line"], f["rule"], f["match"]))


def verdict_of(findings, known_bad=False, check_errors=0):
    top = max((RANK[f["confidence"]] for f in findings), default=-1)
    n = len(findings)
    if known_bad:
        level, text = "malicious", ("A file in this folder matches a known-bad hash. Do not open, install or run "
                                    "anything from it.")
    elif top == 2:
        level, text = "suspicious", ("%d finding%s, at least one high-confidence. Do not run, install or open this "
                                     "project in an editor or AI agent until you have read each high-confidence "
                                     "finding. A finding is not proof of harm." % (n, "" if n == 1 else "s"))
    elif top == 1:
        level, text = "review", ("%d finding%s, none high-confidence. Read them before running anything. These "
                                 "checks can false-positive; a finding is not proof of harm." % (n, "" if n == 1 else "s"))
    elif top == 0:
        level, text = "weak_signals", ("Only low-confidence signals fired (%d). These often are false positives "
                                       "and are not proof of harm; skim them." % n)
    else:
        level, text = "nothing_flagged", ("No checks fired. That is not a guarantee the project is safe: the checks "
                                          "are fixed patterns, they only see what they were written to look for, and "
                                          "a new or well-hidden attack passes them.")
    if check_errors:
        text += " %d check(s) crashed and did not run, so even this result is incomplete." % check_errors
    return {"level": level, "trust": "advisory", "text": text, "caveat": CAVEAT}


def scan(path, bad_hashes=None, env=None):
    """Quarantine a copy of `path` and run every intake check on the copy. The folder itself is only read."""
    root = os.path.abspath(str(path))
    if not os.path.isdir(root):
        raise UsageError("%s is not a folder (intake scans a repository folder)" % os.path.basename(root))
    bad = load_bad_hashes(bad_hashes, env)
    tmp = tempfile.mkdtemp(prefix="cg-intake-")
    try:
        dest = os.path.join(tmp, "copy")
        os.makedirs(dest)
        manifest, skipped, skipped_dirs = _quarantine(root, dest)
        _lock(tmp)
        findings, errors = _analyse(dest, manifest, bad)
    finally:
        _unlock_and_remove(tmp)
    findings = _sorted(findings)
    known_bad = any(f["rule"] == "hash.known_bad" for f in findings)
    counts = {c: sum(1 for f in findings if f["confidence"] == c) for c in ("high", "medium", "low")}
    return {
        "tool": "code-guardian intake", "schema_version": SCHEMA_VERSION, "version": __version__,
        "trust": "advisory", "name": os.path.basename(root),
        "verdict": verdict_of(findings, known_bad, len(errors)),
        "counts": counts, "findings": findings,
        "quarantine": {"scanned": "read-only copy", "files": len(manifest),
                       "symlinks_skipped": sum(1 for s in skipped if s["reason"] == "symlink"),
                       "truncated": sum(1 for i in manifest.values() if i["truncated"])},
        "skipped": skipped, "skipped_dirs": skipped_dirs, "check_errors": errors,
        "known_bad_hashes_loaded": len(bad),
    }


def exit_code(result, fail_on="high"):
    """1 for a known-bad match or any finding at or above `fail_on` (default high), else 0."""
    if result["verdict"]["level"] == "malicious":
        return 1
    return 1 if any(RANK[f["confidence"]] >= RANK[fail_on] for f in result["findings"]) else 0


# ---- output --------------------------------------------------------------------------------------------------------

def render(result):
    v = result["verdict"]
    lines = ["code-guardian intake: %s" % result["name"], "verdict: %s (advisory)" % v["level"].upper().replace("_", " "),
             v["text"], ""]
    c = result["counts"]
    lines.append("findings: %d high, %d medium, %d low   scanned %d files in a read-only copy"
                 % (c["high"], c["medium"], c["low"], result["quarantine"]["files"]))
    for f in result["findings"]:
        where = f["file"] + (":%d" % f["line"] if f["line"] else "")
        lines += ["", "[%s] %s  %s" % (f["confidence"].upper(), f["rule"], where), "  %s" % f["summary"],
                  "  matched: %s" % f["match"]]
    stars = result.get("stars")
    if stars:
        lines += ["", "stars signal (not part of the verdict): %s" % stars.get("summary", stars.get("status"))]
    if result["skipped_dirs"]:
        lines += ["", "not scanned: " + ", ".join(d["dir"] for d in result["skipped_dirs"])]
    if result["skipped"]:
        lines.append("skipped files: %d (symlinks, special or unreadable files)" % len(result["skipped"]))
    if result["check_errors"]:
        lines.append("checks that crashed: " + ", ".join(e["check"] for e in result["check_errors"]))
    lines += ["", v["caveat"]]
    return "\n".join(lines) + "\n"


def to_json(result):
    return json.dumps(redact_report(result), indent=1) + "\n"


def _fingerprint(f):
    return hashlib.sha256(("%s|%s|%s" % (f["rule"], f["file"], f["match"])).encode("utf-8")).hexdigest()[:32]


def to_sarif(result):
    findings = result["findings"]
    used = sorted({f["rule"] for f in findings})
    rule_defs = [{"id": r, "name": "".join(p.capitalize() for p in r.replace(".", "_").split("_")),
                  "shortDescription": {"text": rules.RULES[r]["title"]},
                  "fullDescription": {"text": rules.RULES[r]["means"]},
                  "help": {"text": "False positives: " + rules.RULES[r]["false_positives"]},
                  "properties": {"tags": ["repo-intake", "advisory"]}} for r in sorted(rules.RULES)]
    results = []
    for f in redact_report(findings):
        loc = {"artifactLocation": {"uri": f["file"]}}
        if f["line"] >= 1:
            loc["region"] = {"startLine": f["line"], "snippet": {"text": f["match"]}}
        results.append({"ruleId": f["rule"], "level": SARIF_LEVEL[f["confidence"]],
                        "message": {"text": "%s Matched: %s" % (f["summary"], f["match"])},
                        "locations": [{"physicalLocation": loc}],
                        "partialFingerprints": {"intakeFingerprint/v1": _fingerprint(f)},
                        "properties": {"confidence": f["confidence"], "falsePositives": f["false_positives"]}})
    return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "code-guardian", "version": result.get("version", __version__),
                            "informationUri": "https://github.com/LuminariSoftwares/code-guardian",
                            "rules": rule_defs}},
        "results": results,
        "properties": {"verdict": result["verdict"], "mode": "repo-intake", "rulesFired": used}}]}


def selftest():
    tmp = tempfile.mkdtemp()
    try:
        src = os.path.join(tmp, "repo")
        os.makedirs(src)
        payload = b"synthetic stand-in\n"
        with open(os.path.join(src, "a.dat"), "wb") as fh:
            fh.write(payload)
        lst = os.path.join(tmp, "bad.json")
        with open(lst, "w", encoding="utf-8") as fh:
            json.dump({"schema_version": 1, "sha256": {hashlib.sha256(payload).hexdigest(): "t"}}, fh)
        hit, clean = scan(src, lst), scan(src)
        checks = [
            ("shipped_list_empty", load_bad_hashes(env={}) == {}),
            ("hash_forces_malicious", hit["verdict"]["level"] == "malicious" and exit_code(hit) == 1),
            ("clean_is_advisory", clean["verdict"]["level"] == "nothing_flagged" and clean["trust"] == "advisory"
             and "not a guarantee" in clean["verdict"]["text"]),
            ("sarif_shape", to_sarif(hit)["version"] == "2.1.0" and len(to_sarif(hit)["runs"][0]["results"]) == 1),
            ("show_escapes", rules.show("a" + chr(0x202E) + "b") == "a\\u202eb"),
            ("not_a_folder", _raises(lambda: scan(lst))),
        ]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return summarize("intake", checks)


def _raises(fn):
    try:
        fn()
    except UsageError:
        return True
    return False


if __name__ == "__main__":
    sys.exit(selftest())
