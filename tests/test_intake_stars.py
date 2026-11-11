"""Repo intake, item 9: the optional bought-stars signal. Loopback stub GitHub API only; no real network, no real token."""
import datetime as dt
import json

from code_guardian import cli, stars

TOKEN = "ghp_" + "S3ntinel" * 5  # built at runtime; not a real credential
BASE = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)


def iso(d):
    return d.strftime("%Y-%m-%dT%H:%M:%SZ")


def stargazer(i, starred):
    return {"starred_at": iso(starred), "user": {"login": "user%03d" % i}}


def routes(n, starred_at, user_for):
    r = {("GET", "/repos/o/r"): (200, {"stargazers_count": n}, 0)}
    pages = (n + 99) // 100
    for p in range(1, pages + 1):
        lo, hi = (p - 1) * 100, min(n, p * 100)
        r[("GET", "/repos/o/r/stargazers?per_page=100&page=%d" % p)] = (200, [stargazer(i, starred_at(i)) for i in range(lo, hi)], 0)
    for i in range(n):
        r[("GET", "/users/user%03d" % i)] = (200, user_for(i, starred_at(i)), 0)
    return r


def user(created, repos, followers, bio):
    return {"created_at": iso(created), "public_repos": repos, "followers": followers, "bio": bio, "name": None if not bio else "N"}


def env(stub_url, token=TOKEN):
    return {"CODE_GUARDIAN_GITHUB_TOKEN": token, "CODE_GUARDIAN_GITHUB_API": stub_url} if token else {"CODE_GUARDIAN_GITHUB_API": stub_url}


def test_bought_pattern_is_a_notable_signal_not_a_verdict(stub):
    api = stub(routes(150, lambda i: BASE + dt.timedelta(minutes=i // 3),
                      lambda i, at: user(at - dt.timedelta(days=2), 0, 0, None)))
    out = stars.analyse("o/r", env(api.url))
    assert out["status"] == "ok" and out["level"] == "notable" and out["sampled"] == 60 and out["stars"] == 150
    flagged = {s["name"] for s in out["signals"] if s["flagged"]}
    assert flagged == {"burst", "young_accounts", "empty_profiles"}
    assert "not a verdict" in out["note"].lower()


def test_organic_pattern_is_quiet(stub):
    api = stub(routes(150, lambda i: BASE + dt.timedelta(days=i * 2),
                      lambda i, at: user(at - dt.timedelta(days=900), 12, 20, "dev")))
    out = stars.analyse("o/r", env(api.url))
    assert out["status"] == "ok" and out["level"] == "none"
    assert not any(s["flagged"] for s in out["signals"])


def test_no_token_skips_gracefully_and_makes_no_request(stub):
    api = stub({})
    out = stars.analyse("o/r", env(api.url, token=None))
    assert out["status"] == "skipped" and "token" in out["reason"].lower()
    assert api.requests == []


def test_few_stars_are_not_judged(stub):
    api = stub({("GET", "/repos/o/r"): (200, {"stargazers_count": 7}, 0)})
    out = stars.analyse("o/r", env(api.url))
    assert out["status"] == "ok" and out["level"] == "none" and "too few" in out["summary"].lower()


def test_rate_limit_or_error_is_reported_not_raised(stub):
    api = stub({("GET", "/repos/o/r"): (403, {"message": "API rate limit exceeded"}, 0)})
    out = stars.analyse("o/r", env(api.url))
    assert out["status"] == "skipped" and "403" in out["reason"]
    assert stars.analyse("not-a-repo", env(api.url))["status"] == "skipped"
    assert stars.analyse("o/r", {"CODE_GUARDIAN_GITHUB_TOKEN": TOKEN, "CODE_GUARDIAN_GITHUB_API": "http://127.0.0.1:9"})["status"] == "skipped"


def test_the_token_is_sent_as_a_bearer_header_and_never_appears_in_any_output(tmp_path, capsys):
    seen = []

    def opener(url, headers):
        seen.append(dict(headers))
        return 200, {"stargazers_count": 3}

    out = stars.analyse("o/r", {"CODE_GUARDIAN_GITHUB_TOKEN": TOKEN}, opener=opener)
    assert seen and seen[0]["Authorization"] == "Bearer " + TOKEN
    assert TOKEN not in json.dumps(out) and TOKEN not in repr(out)
    d = tmp_path / "repo"
    d.mkdir()
    (d / "a.py").write_text("x = 1\n")
    import os
    os.environ["CODE_GUARDIAN_GITHUB_TOKEN"] = TOKEN
    os.environ["CODE_GUARDIAN_GITHUB_API"] = "http://127.0.0.1:9"
    try:
        cli.main(["intake", str(d), "--stars", "o/r"])
        text = capsys.readouterr().out
        cli.main(["intake", str(d), "--stars", "o/r", "--json"])
        js = capsys.readouterr().out
    finally:
        del os.environ["CODE_GUARDIAN_GITHUB_TOKEN"], os.environ["CODE_GUARDIAN_GITHUB_API"]
    assert TOKEN not in text + js and "stars signal" in text and json.loads(js)["stars"]["status"] == "skipped"
    assert json.loads(js)["verdict"]["level"] == "nothing_flagged", "the stars signal never changes the verdict"


def test_cli_without_a_token_skips_the_stars_signal(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("CODE_GUARDIAN_GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    d = tmp_path / "repo"
    d.mkdir()
    (d / "a.py").write_text("x = 1\n")
    assert cli.main(["intake", str(d), "--stars", "o/r", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["stars"]["status"] == "skipped"
