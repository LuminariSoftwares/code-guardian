"""Optional bought-stars signal for repo intake. SEPARATE from the intake verdict: it never changes it.

Asks the GitHub API about a repository's stargazers and reports three signals from a sample: a burst of stars in a
few hours, accounts that were created within 30 days of starring, and empty profiles (no repos, no followers, no bio,
no name). The result is a SIGNAL, not a verdict: a repo that hit a front page legitimately shows a burst, and plenty
of real accounts are empty.

Needs the user's own GitHub token, read from CODE_GUARDIAN_GITHUB_TOKEN (or GITHUB_TOKEN) in the environment at call
time. It is sent as a Bearer header to the API host only, never stored, never written to a file and never printed;
redirects are not followed, and a token is never sent over plain http except to a loopback test server. With no
token, or on any API error or rate limit, the signal is skipped with the reason and nothing is raised.
CODE_GUARDIAN_GITHUB_API overrides the API base (tests; GitHub Enterprise).

Public contract:
    analyse(owner_repo, env=None, opener=None) -> {"status": "ok"|"skipped", "level": "none"|"weak"|"notable", "stars",
                                                     "sampled", "signals": [...], "summary", "note"}   # or status + reason
"""

import datetime as dt
import json
import math
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

from .finding import summarize

API = "https://api.github.com"
TOKEN_VARS = ("CODE_GUARDIAN_GITHUB_TOKEN", "GITHUB_TOKEN")
PER_PAGE = 100
MAX_PAGES = 5
MAX_USERS = 60
MIN_STARS = 20
YOUNG_DAYS = 30
BURST_HOURS = 3
BURST_MIN = 40
YOUNG_SHARE = 0.25
EMPTY_SHARE = 0.35
NOTE = ("This is a signal, not a verdict. A repository that reached a front page or a newsletter shows a burst of "
        "new, empty accounts without any buying, and a sample of {n} accounts is a sample.")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def _get(url, headers):
    """(status, parsed JSON or None). Network failures raise OSError."""
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.build_opener(_NoRedirect).open(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        return exc.code, None
    except ValueError as exc:
        raise OSError("unreadable answer") from exc


def _skipped(reason):
    return {"status": "skipped", "reason": reason, "summary": "skipped: " + reason}


def _parse(ts):
    return dt.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)


def _safe_base(base):
    p = urllib.parse.urlparse(base)
    return p.scheme == "https" or (p.scheme == "http" and p.hostname in ("127.0.0.1", "localhost", "::1"))


def analyse(owner_repo, env=None, opener=None):
    env = os.environ if env is None else env
    token = next((env[v] for v in TOKEN_VARS if env.get(v)), None)
    if not token:
        return _skipped("no GitHub token in the environment (set CODE_GUARDIAN_GITHUB_TOKEN to your own token)")
    parts = str(owner_repo).strip("/").split("/")
    if len(parts) != 2 or not all(parts):
        return _skipped("expected OWNER/REPO")
    base = (env.get("CODE_GUARDIAN_GITHUB_API") or API).rstrip("/")
    if not _safe_base(base):
        return _skipped("refusing to send a token over plain http")
    owner, repo = (urllib.parse.quote(p) for p in parts)
    headers = {"Authorization": "Bearer " + token, "Accept": "application/vnd.github.star+json",
               "User-Agent": "code-guardian-intake", "X-GitHub-Api-Version": "2022-11-28"}
    fetch = opener or _get

    def call(path):
        status, body = fetch(base + path, headers)
        if status != 200 or body is None:
            raise _Api("GitHub answered %s" % status if status != 200 else "GitHub sent an unreadable answer")
        return body

    try:
        info = call("/repos/%s/%s" % (owner, repo))
        total = int(info.get("stargazers_count", 0))
        if total < MIN_STARS:
            return {"status": "ok", "level": "none", "stars": total, "sampled": 0, "signals": [],
                    "summary": "too few stars (%d) to judge" % total, "note": NOTE.format(n=0)}
        last = math.ceil(total / PER_PAGE)
        wanted = sorted({1, last} | {max(1, round(last * k / (MAX_PAGES - 1))) for k in range(1, MAX_PAGES - 1)})[:MAX_PAGES]
        collected, bursts = [], []
        for page in wanted:
            rows = call("/repos/%s/%s/stargazers?per_page=%d&page=%d" % (owner, repo, PER_PAGE, page))
            times = []
            for r in rows:
                if isinstance(r, dict) and r.get("starred_at") and isinstance(r.get("user"), dict):
                    t = _parse(r["starred_at"])
                    collected.append((r["user"].get("login"), t))
                    times.append(t)
            if len(times) >= BURST_MIN:
                span = (max(times) - min(times)).total_seconds() / 3600
                bursts.append(span <= BURST_HOURS)
        step = max(1, len(collected) / MAX_USERS)
        sample = [collected[int(k * step)] for k in range(min(MAX_USERS, len(collected)))]
        young = empty = got = 0
        for login, starred in sample:
            try:
                u = call("/users/%s" % urllib.parse.quote(str(login)))
            except _Api:
                continue
            got += 1
            if (starred - _parse(u["created_at"])).days < YOUNG_DAYS:
                young += 1
            if not (u.get("public_repos") or u.get("followers") or u.get("bio") or u.get("name")):
                empty += 1
    except _Api as exc:
        return _skipped(str(exc))
    except (OSError, KeyError, TypeError, ValueError) as exc:
        return _skipped("could not read GitHub's answer (%s)" % type(exc).__name__)
    if got < max(10, len(sample) // 2):
        return _skipped("GitHub answered for only %d of %d sampled accounts (rate limit?)" % (got, len(sample)))
    signals = [
        {"name": "burst", "flagged": any(bursts), "value": "%d of %d sampled pages had %d+ stars inside %d hours" % (sum(bursts), len(bursts), BURST_MIN, BURST_HOURS),
         "threshold": "any page"},
        {"name": "young_accounts", "flagged": young / got >= YOUNG_SHARE, "value": "%d%% starred within %d days of creating the account" % (round(100 * young / got), YOUNG_DAYS),
         "threshold": "%d%%" % round(100 * YOUNG_SHARE)},
        {"name": "empty_profiles", "flagged": empty / got >= EMPTY_SHARE, "value": "%d%% have no repos, followers, bio or name" % round(100 * empty / got),
         "threshold": "%d%%" % round(100 * EMPTY_SHARE)},
    ]
    n = sum(s["flagged"] for s in signals)
    level = "none" if n == 0 else "weak" if n == 1 else "notable"
    return {"status": "ok", "level": level, "stars": total, "sampled": got, "signals": signals,
            "summary": "%s: %d of 3 signals (%s)" % (level, n, "; ".join(s["name"] for s in signals if s["flagged"]) or "none flagged"),
            "note": NOTE.format(n=got)}


class _Api(Exception):
    pass


def selftest():
    out = analyse("o/r", env={})
    leaked = analyse("o/r", {"CODE_GUARDIAN_GITHUB_TOKEN": "t0k3n", "CODE_GUARDIAN_GITHUB_API": "http://example.invalid"})
    checks = [
        ("no_token_skips", out["status"] == "skipped" and "token" in out["reason"]),
        ("plain_http_refused", leaked["status"] == "skipped" and "plain http" in leaked["reason"]),
        ("bad_spec", analyse("nope", {"CODE_GUARDIAN_GITHUB_TOKEN": "x"})["status"] == "skipped"),
        ("loopback_ok", _safe_base("http://127.0.0.1:1") and not _safe_base("http://example.com")),
    ]
    return summarize("stars", checks)


if __name__ == "__main__":
    sys.exit(selftest())
