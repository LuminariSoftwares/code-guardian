"""P88 S3 acceptance -- value signals in scanners.py, secret.history inherits the level, the fixture repair (plan P88
C3, C4 history part, C6; section S3's proof row).

Written by the overseer from plan P88 BEFORE the build session. The build session must add this file to the PR
byte-for-byte and must not edit it; a PR that changes it fails the section. Pure ASCII on purpose. No key-shaped
literal appears in this file: every key is built by concatenation at test time (the privacy gate stays at 0 hits).

How this file reads the contract where the plan leaves a choice (the build follows these readings):
- test_value_reason(prefix, body) returns exactly one of: "spells out <word>" (V1; <word> is the PLACEHOLDER_WORDS
  entry, compared case-insensitively), "is mostly one character" (V2: <= 4 distinct characters), "repeats one
  character" (V2: a run of 6+ identical characters), "counts up" (V2: 8 characters in a row, each one code point
  above the one before, e.g. 12345678 / abcdefgh), or None. The exact-string cases below each meet ONE criterion
  only, so no precedence between criteria is tested.
- GitHub classic token checksum. GitHub's own description of the format
  (https://github.blog/engineering/platform-security/behind-githubs-new-authentication-token-formats/) says: "A 32
  bit checksum in the last 6 digits of each token", "a CRC32 algorithm", "encode the result with a Base62
  implementation, using leading zeros for padding as needed". It does NOT state the Base62 alphabet order or which
  characters the CRC32 covers. If the PR defines github_checksum_ok, it must use the reading this file tests: CRC32
  of the 30 characters between "ghp_" and the last six, Base62 alphabet 0-9 A-Z a-z, left-padded with "0" to six
  characters; github_checksum_ok(body) takes the body after "ghp_". If the PR decides GitHub's docs do not confirm
  the format, it does not define github_checksum_ok (and says so in the PR); the checksum test then checks that the
  name appears nowhere in scanners.py and that a low-variety ghp_ body is downgraded like any other.
- tests/test_history.py keeps a key() function that returns the history test's key (the repair changes its body
  only); this file imports that module to read it. tests/make_risky.py keeps writing API_KEY_VALUE = "<key>" as the
  first line of risky/settings.py.
- The secret.history INFO weight (C4 asks for a ("secret.history", "INFO"): 0 row in score.SAFE_WEIGHTS). Every report
  publishes the whole weight table (report["weights"] = score.weight_table()), so adding that row changes all 8 fixture
  reports by one line and trips plan P88's kill criterion "C7 (a) shows any byte difference on the 8 fixtures after S3".
  score.weight() already returns 0 for a missing row, so the weight is 0 without the row: this file checks the
  effective weight and the fixtures stay byte-identical; DO NOT add the row (overseer reading, 2026-10-24, filed as a
  pickup item against the plan).
- The 8 fixture digests are canonical `scan --json` reports recorded by the overseer on main at v0.4.0 (top-level
  "version" and "path" dropped, json.dumps(sort_keys=True, indent=1), sha256 of the UTF-8 text); recorded on Linux
  and on Windows, where the CRLF checkout changes complete_bare's report only.
"""
import binascii
import hashlib
import importlib.util
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SCANNERS = ROOT / "code_guardian" / "scanners.py"
MAIN_SCANNERS_SELFTEST = 27  # `python -m code_guardian.scanners --selftest` on main at v0.4.0
SK = "sk" + "-"
GHP = "gh" + "p_"
B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
GIT = shutil.which("git")

FIXTURES = ("clean_repo", "complete_app", "complete_bare", "orphan_repo", "risky_repo", "supply_repo",
            "works_broken", "works_weak_tests")
BEFORE = {
    "clean_repo": "12f9f1151c3dc3eda0b2f869f520e27cbe6ccecdb84c3614b28ebdde2af7ac46",
    "complete_app": "624f6dacf3603ca362436120b689f574dca97f7d7302e20fd7c3c3f469adca2a",
    "complete_bare": "2e70cb8974f3297b2167254f938631b0917d3aa2a1332982c97b03954c796959",
    "orphan_repo": "d0a852c06dff6496d57b8577ac62111e75c9b04d4ff56d7fa61e5c9eb05d987a",
    "risky_repo": "085fae5fb1b7becf5507dc3caee5ad974fe142db8b2abba4a19b77eb6b863ecc",
    "supply_repo": "db10eccf8f15f585003b7a5837eff997b3d4dd5de474602644ea6920d5e3c482",
    "works_broken": "c55f9726a6375b3d82fa55b1dcb2bd0e72966082c3cd7b5c314deb90aa9edb17",
    "works_weak_tests": "f6d89b6ce81f7d8802e0d94fa42edc1b6db2a53481fe8e26d6fe1a98c227a84e",
}
# A Windows checkout is CRLF: complete_bare's report differs there (recorded by the overseer on Windows, main v0.4.0).
BEFORE_NT = dict(BEFORE, complete_bare="d413640c66bf30142bcfd858b1082301566d538518b5b93508a3a45f057de2b4")

# Twelve bodies, each meeting exactly one criterion, with the reason it must give.
REASON_CASES = [
    ("fake" + "Qm7xK2pL9wR3vT8b", "spells out fake"),
    ("Qm7xK2" + "dummy" + "pL9wR3vT8b", "spells out dummy"),
    ("Zr4" + "sample" + "Wn8Jt2Xc5Bv", "spells out sample"),
    ("Kp2Ld9" + "mock" + "Gt7Hs3Rf5Wq", "spells out mock"),
    ("Hq4" * 10, "is mostly one character"),
    ("aB3c" * 5, "is mostly one character"),
    ("Zx" * 9, "is mostly one character"),
    ("Qm7xK2" + "0" * 8 + "pL9wR3", "repeats one character"),
    ("Tz5Wq" + "Y" * 6 + "Jn3Rd8", "repeats one character"),
    ("Bv8Nc2Lk4" + "h" * 7 + "Pd6", "repeats one character"),
    ("Qm7xK2" + "12345678" + "pL9wR3", "counts up"),
    ("Zx9Rq" + "abcdefgh" + "T2w7W", "counts up"),
]
# Three mixed bodies that read like real keys: no reason.
MIXED = [
    (SK, "Qm7xK2pL9wR3vT8bN4cD6fH1"),
    (SK, "Wn8Jt2Xc5BvZr4Kp2Ld9Gt7Hs3R"),
    (GHP, "Kp2Ld9Gt7Hs3RfWq5Zr4Wn8Jt2Xc5BvQm7x"),
]
V2_REASONS = ("is mostly one character", "repeats one character", "counts up")
INFO_FIX = ["keep test values out of the source too, or make them obviously fake"]


def _scanners():
    from code_guardian import scanners
    return scanners


def _b62(n, width=6):
    out = ""
    while n:
        n, r = divmod(n, 62)
        out = B62[r] + out
    return out.rjust(width, "0")


def _ghp_body(first30):
    return first30 + _b62(binascii.crc32(first30.encode("ascii")) & 0xFFFFFFFF)


def _one(text, rel="a.js", python=False):
    out = _scanners().scan_secret_text(rel, text, python)
    assert len(out) == 1, out
    return out[0]


# --------------------------------------------------------------------------- C3: test_value_reason

@pytest.mark.parametrize("body,reason", REASON_CASES, ids=["reason%02d" % i for i in range(len(REASON_CASES))])
def test_value_reason_exact_strings(body, reason):
    assert _scanners().test_value_reason(SK, body) == reason


def test_value_reason_word_is_case_insensitive():
    got = _scanners().test_value_reason(SK, "FAKE" + "Qm7xK2pL9wR3vT8b")
    assert got is not None and got.lower() == "spells out fake"


@pytest.mark.parametrize("prefix,body", MIXED, ids=["mixed%d" % i for i in range(len(MIXED))])  # no key shape in ids
def test_value_reason_none_for_real_shaped(prefix, body):
    assert _scanners().test_value_reason(prefix, body) is None


def test_github_checksum_override():
    s = _scanners()
    low = "A" * 30
    if hasattr(s, "github_checksum_ok"):
        good = _ghp_body(low)
        assert len(good) == 36 and s.github_checksum_ok(good) is True
        assert s.test_value_reason(GHP, good) is None, "a verifying ghp_ body is never downgraded"
        changed = "B" + good[1:]  # one character changed: the checksum no longer verifies
        assert s.github_checksum_ok(changed) is False
        assert s.test_value_reason(GHP, changed) in V2_REASONS
        # and the scanner keeps the verifying one at FAIL
        f = _one("t = '%s'\n" % (GHP + good))
        assert f["level"] == "FAIL", f
    else:
        assert SCANNERS.read_text(encoding="utf-8").count("github_checksum_ok") == 0
        assert s.test_value_reason(GHP, low + "AAAAAA") in V2_REASONS


# --------------------------------------------------------------------------- C3: scan_secret_text

def test_scan_v1_line_info_verbatim():
    f = _one("const k = '%s';\n" % (SK + "fake" + "Qm7xK2pL9wR3vT8bN4"))
    assert f["code"] == "secret.key" and f["level"] == "INFO"
    assert f["summary"] == "sk- key shape (privacy pattern 5) in the source (looks like a test value; value redacted)"
    assert f["evidence"] == ["matched: sk- key shape (privacy pattern 5)", "length: 25 characters",
                             "kind: provider key shape", "looks like a test value: spells out fake"]
    assert f["try"] == INFO_FIX


def test_scan_v2_line_info_verbatim():
    f = _one("const k = '%s';\n" % (SK + "Qm7xK2" + "0" * 8 + "pL9wR3"))
    assert f["code"] == "secret.key" and f["level"] == "INFO"
    assert f["summary"] == "sk- key shape (privacy pattern 5) in the source (looks like a test value; value redacted)"
    assert f["evidence"] == ["matched: sk- key shape (privacy pattern 5)", "length: 23 characters",
                             "kind: provider key shape", "looks like a test value: repeats one character"]
    assert f["try"] == INFO_FIX


def test_scan_mixed_body_fail_unchanged():
    f = _one("const k = '%s';\n" % (SK + MIXED[0][1]))
    assert f["level"] == "FAIL"
    assert f["summary"] == "sk- key shape (privacy pattern 5) in the source; value redacted"
    assert f["evidence"] == ["matched: sk- key shape (privacy pattern 5)", "length: 27 characters",
                             "kind: provider key shape"]
    assert f["try"] == ["move it to an environment variable or a secret store",
                        "rotate it: it is in this file's history"]


def test_scan_fake_and_real_on_one_line_stays_fail():
    s = _scanners()
    assert s.test_value_reason(SK, "Hq4" * 10) is not None  # red on main: the reason function is the feature
    f = _one("a = '%s'; b = '%s'\n" % (SK + "Hq4" * 10, SK + MIXED[0][1]))
    assert f["level"] == "FAIL", f


def test_scan_pem_never_info():
    s = _scanners()
    assert hasattr(s, "test_value_reason")
    pem = "-----BEGIN " + "RSA PRIVATE KEY-----"
    f = _one(pem + " fake\n")
    assert f["level"] == "FAIL" and f["evidence"][0] == "matched: private-key block"
    g = _one("%s %s\n" % (pem, SK + "Hq4" * 10))
    assert g["level"] == "FAIL", g


def test_scan_provider_fail_pattern_lowvar_info():
    f = _one("A=%s\n" % ("AK" + "IA" + "Q" * 16), rel="a.env")
    assert f["level"] == "INFO", f
    assert f["summary"] == "AWS access key ID shape in the source (looks like a test value; value redacted)"
    assert f["evidence"][-1] in ["looks like a test value: " + r for r in V2_REASONS]


def test_scanners_selftest_grew_by_ten():
    p = subprocess.run([sys.executable, "-m", "code_guardian.scanners", "--selftest"], cwd=str(ROOT),
                       capture_output=True, text=True)
    m = re.search(r"(\d+) checks, (\d+) passed, (\d+) failed", p.stdout)
    assert p.returncode == 0 and m, p.stdout + p.stderr
    total, passed, failed = (int(x) for x in m.groups())
    assert failed == 0 and passed == total
    assert total >= MAIN_SCANNERS_SELFTEST + 10, "scanners --selftest has %d checks; needs >= %d" % (
        total, MAIN_SCANNERS_SELFTEST + 10)


# --------------------------------------------------------------------------- C4 (history part) + score row

def _git(root, *args):
    import os
    env = dict(os.environ, GIT_AUTHOR_DATE="2026-01-01T00:00:00Z", GIT_COMMITTER_DATE="2026-01-01T00:00:00Z")
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, env=env)


def _history_repo(root, value):
    root.mkdir()
    _git(root, "init", "-q")
    for k, v in (("user.name", "t"), ("user.email", "t@example.com"), ("commit.gpgsign", "false"),
                 ("maintenance.auto", "false"), ("gc.auto", "0")):
        _git(root, "config", k, v)
    (root / "app").mkdir()
    (root / "app" / "__init__.py").write_text("", encoding="utf-8")
    (root / "app" / "settings.py").write_text("API = '%s'\n" % value, encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "add")
    (root / "app" / "settings.py").write_text("import os\nAPI = os.environ.get('API')\n", encoding="utf-8")
    _git(root, "commit", "-q", "-am", "remove")
    return root


@pytest.mark.skipif(GIT is None, reason="git is not on PATH")
def test_history_lowvar_value_inherits_info(tmp_path):
    from code_guardian import report
    rep = report.scan(str(_history_repo(tmp_path / "repo", SK + "Hq4" * 10)), history=True)
    found = [f for f in rep["findings"] if f["code"] == "secret.history"]
    assert len(found) == 1, "a history value with a test-value reason is reported, never dropped: %r" % found
    assert found[0]["level"] == "INFO", found[0]
    assert "looks like a test value: is mostly one character" in found[0]["evidence"], found[0]
    assert ("Hq4" * 10) not in json.dumps(rep)


@pytest.mark.skipif(GIT is None, reason="git is not on PATH")
def test_history_real_shaped_value_stays_fail(tmp_path):
    from code_guardian import report
    assert hasattr(_scanners(), "test_value_reason")  # red on main: the reason function is the feature
    rep = report.scan(str(_history_repo(tmp_path / "repo", SK + MIXED[1][1])), history=True)
    found = [f for f in rep["findings"] if f["code"] == "secret.history"]
    assert len(found) == 1 and found[0]["level"] == "FAIL", found


@pytest.mark.skipif(GIT is None, reason="git is not on PATH")
def test_secret_history_info_weighs_zero(tmp_path):
    from code_guardian import report, score
    assert score.weight({"code": "secret.history", "level": "INFO"}) == 0
    assert score.weight({"code": "secret.history", "level": "FAIL"}) == 30
    assert ("secret.history", "INFO") not in score.SAFE_WEIGHTS, "the row would change every report (see docstring)"
    rep = report.scan(str(_history_repo(tmp_path / "repo", SK + "Hq4" * 10)), history=True)
    assert rep["scores"]["safe"] == 100, rep["scores"]  # red on main: today it is FAIL, weight 30


# --------------------------------------------------------------------------- C6: fixture repair

def _mixed_body_ok(body, length):
    assert len(body) == length, len(body)
    assert len(set(body)) >= 12, "needs >= 12 distinct characters"
    assert any(c.isdigit() for c in body) and any(c.isalpha() for c in body), "mixed letters and digits"
    assert not re.search(r"(.)\1\1", body), "no character three times in a row"
    low = body.lower()
    assert not [w for w in _scanners().PLACEHOLDER_WORDS if len(w) >= 4 and w in low]
    assert _scanners().test_value_reason(SK, body) is None


def test_make_risky_key_is_real_shaped(tmp_path):
    sys.path.insert(0, str(HERE))
    import make_risky
    values = []
    for name in ("a", "b"):
        dest = make_risky.build(tmp_path / name)
        first = (dest / "risky" / "settings.py").read_text(encoding="utf-8").splitlines()[0]
        m = re.fullmatch(r'API_KEY_VALUE = "([^"]*)"', first)
        assert m, first
        values.append(m.group(1))
    assert values[0] == values[1], "the build is deterministic"
    value = values[0]
    assert value.startswith(SK) and len(value) == 27
    _mixed_body_ok(value[len(SK):], 24)
    assert "hashlib" in (HERE / "make_risky.py").read_text(encoding="utf-8")


def test_history_test_key_is_real_shaped():
    spec = importlib.util.spec_from_file_location("p88_th", str(HERE / "test_history.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    value = mod.key()
    assert value == mod.key(), "the key is deterministic"
    assert value.startswith(SK) and len(value) == 33
    _mixed_body_ok(value[len(SK):], 30)


# --------------------------------------------------------------------------- the 8 fixtures, byte-identical

def _canon(raw):
    d = json.loads(raw)
    d.pop("version", None)
    d.pop("path", None)
    d.pop("weights", None)  # P81 S2 adds weight rows; test_golden excludes weights the same way
    return json.dumps(d, sort_keys=True, indent=1)


@pytest.mark.parametrize("name", FIXTURES)
def test_fixture_report_identical_to_s0(name, tmp_path):
    target = ROOT / "tests" / "fixtures" / name
    if name == "risky_repo":
        sys.path.insert(0, str(HERE))
        import make_risky
        target = make_risky.build(tmp_path / "risky_repo")
    p = subprocess.run([sys.executable, "-m", "code_guardian", "scan", str(target), "--json"], cwd=str(ROOT),
                       capture_output=True, text=True, encoding="utf-8")
    assert p.stdout.strip().startswith("{"), p.stderr[-500:]
    digest = hashlib.sha256(_canon(p.stdout).encode("utf-8")).hexdigest()
    import os
    want = (BEFORE_NT if os.name == "nt" else BEFORE)[name]
    assert digest == want, "%s report changed since S0's record" % name
