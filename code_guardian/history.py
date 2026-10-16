"""--history: the secret.key shape rules over every line git history added (opt-in).

A key that was committed and deleted later is still in the history, and anyone with a clone can read it; it may still
be valid. This runs one read-only command through subprocess with an argument list (never a shell):

    git --no-pager -C PATH -c core.fsmonitor=false -c log.showSignature=false
        log -p --no-color --no-ext-diff --no-textconv --relative --format=%H --max-count=DEPTH -- .

and reads its output up to a byte cap. It only reads: no checkout, no fetch, no config change, no lock (env
GIT_OPTIONAL_LOCKS=0). The -c overrides stop a scanned repo's own config from running a program (fsmonitor, GPG
signature checks); --no-ext-diff and --no-textconv do the same for diff drivers. Only added lines are checked, and only
key shapes (API-key prefixes, provider formats, AWS secret keys, private-key blocks): never the value, only the short
sha and the path, reaches a finding. A key still present in the current file is left to secret.key.

Public contract:
    DEPTH, BYTE_CAP, TIMEOUT
    command(root, depth) -> argv list
    scan(root, depth=DEPTH, byte_cap=BYTE_CAP, current=None) -> (findings, notes, skipped)
        # skipped: None when the history was read, else the reason (git missing, not a repository, git failed)
        # current: {relpath: text} of the working tree, to leave keys still there to secret.key
"""

import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading

from .finding import make_finding, summarize
from .scanners import KEY_SHAPE, key_values, scan_secret_text

DEPTH = 500
BYTE_CAP = 64 * 1024 * 1024
TIMEOUT = 300
_COMMIT = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")


def command(root, depth):
    return ["git", "--no-pager", "-C", str(root), "-c", "core.fsmonitor=false", "-c", "log.showSignature=false",
            "log", "-p", "--no-color", "--no-ext-diff", "--no-textconv", "--relative", "--format=%H",
            "--max-count=%d" % int(depth), "--", "."]


def _env():
    env = dict(os.environ)
    env.update({"GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C", "GIT_PAGER": "cat"})
    return env


def _path(line):
    """'+++ b/app/x.py' -> 'app/x.py'; None for /dev/null."""
    target = line[4:].strip()
    if target.startswith('"') and target.endswith('"'):
        target = target[1:-1].encode("latin-1", "backslashreplace").decode("unicode_escape")
    if target == "/dev/null":
        return None
    return target[2:] if target.startswith("b/") else target


def _finding(sha, path, label):
    return make_finding("secret.history", "partial", "FAIL", path,
                        "a key shape was committed in %s and may still be valid even if the file no longer has it"
                        % sha[:7],
                        evidence=["commit: %s" % sha[:7], "path: %s" % path, "matched: %s" % label, KEY_SHAPE],
                        try_=["rotate the key now: deleting it from the file does not delete it from the history",
                              "then, if the repository is shared, consider rewriting the history (git filter-repo)"])


def scan(root, depth=DEPTH, byte_cap=BYTE_CAP, current=None):
    if shutil.which("git") is None:
        return [], ["history: git is not on PATH; the history was not scanned"], "git is not on PATH"
    try:
        probe = subprocess.run(["git", "--no-pager", "-C", str(root), "rev-parse", "--is-inside-work-tree"],
                               capture_output=True, text=True, stdin=subprocess.DEVNULL, env=_env(), timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        return [], ["history: git could not run (%s)" % type(exc).__name__], "git could not run"
    if probe.returncode != 0 or probe.stdout.strip() != "true":
        return [], ["history: PATH is not a git repository; the history was not scanned"], "not a git repository"
    proc = subprocess.Popen(command(root, depth), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            stdin=subprocess.DEVNULL, env=_env())
    timed_out = []

    def stop():
        timed_out.append(True)
        proc.kill()
    timer = threading.Timer(TIMEOUT, stop)
    timer.start()
    current = current or {}
    found, notes, read, capped = {}, [], 0, False
    sha, path, commits = None, None, 0
    try:
        for raw in proc.stdout:
            read += len(raw)
            if read > byte_cap:
                capped = True
                notes.append("history: stopped at the byte cap (%d bytes) after %d commit(s); older commits were not "
                             "scanned" % (byte_cap, commits))
                proc.kill()
                break
            line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            if _COMMIT.fullmatch(line):
                sha, path, commits = line, None, commits + 1
            elif line.startswith("+++ "):
                path = _path(line)
            elif line.startswith("+") and sha and path:
                values = key_values(line[1:])
                hits = [f for f in scan_secret_text(path, line[1:], python=True) if f["level"] == "FAIL"]
                if not values or not hits or any(v in current.get(path, "") for v in values):
                    continue  # nothing key-shaped, or still in the working tree (secret.key reports it)
                digest = hashlib.sha256("\0".join(sorted(values)).encode("utf-8")).hexdigest()
                # log runs newest first, so the last write is the oldest commit that added this value here
                found[(path, digest)] = _finding(sha, path, hits[0]["evidence"][0][len("matched: "):])
    finally:
        timer.cancel()
        proc.stdout.close()
        rc = proc.wait()
    if timed_out:
        notes.append("history: git log ran longer than %d s and was stopped after %d commit(s)" % (TIMEOUT, commits))
    elif rc != 0 and not capped:
        return [], ["history: git log failed (exit %d); the history was not scanned" % rc], "git log failed"
    if commits >= depth:
        notes.append("history: read the latest %d commit(s) (--history-depth); older ones were not scanned" % depth)
    return sorted(found.values(), key=lambda f: (f["node"], f["summary"])), notes, None


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if "--selftest" in argv:
        return selftest()
    sys.stderr.write("usage: python -m code_guardian.history --selftest\n")
    return 2


def selftest():
    cmd = command("repo", 7)
    tmp = tempfile.mkdtemp()
    try:
        found, notes, skipped = scan(tmp)  # an empty directory is not a repository (or git is missing)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    f = _finding("a" * 40, "app/x.py", "sk- key shape")
    checks = [
        ("argv_list", cmd[:2] == ["git", "--no-pager"] and "--max-count=7" in cmd and cmd[-2:] == ["--", "."]
         and "--no-ext-diff" in cmd and "--no-textconv" in cmd and "log.showSignature=false" in cmd),
        ("paths", _path("+++ b/app/x.py") == "app/x.py" and _path("+++ /dev/null") is None),
        ("commit_line", bool(_COMMIT.fullmatch("0" * 40)) and not _COMMIT.fullmatch("+" + "0" * 40)),
        ("not_a_repo_skips", found == [] and skipped in ("not a git repository", "git is not on PATH") and notes),
        ("finding", f["level"] == "FAIL" and f["node"] == "app/x.py" and "aaaaaaa" in f["summary"]
         and KEY_SHAPE in f["evidence"] and len(f["summary"]) <= 120),
    ]
    return summarize("history", checks)


if __name__ == "__main__":
    sys.exit(main())
