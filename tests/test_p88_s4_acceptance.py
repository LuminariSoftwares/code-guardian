"""P88 S4 acceptance -- context signals for key-shaped values in report.py (plan P88 C4, report part), the
one-weak-signal hint, the test_values_graded summary key, and the 0.4.1 docs (C8).

Written by the overseer BEFORE the build session. The build session must add this file to the PR byte-for-byte and
must not edit it; a PR that changes it fails the section. Pure ASCII on purpose.

No key-shaped literal is stored in this file (the privacy gate and the self-scan would rightly flag it): every value
is built by concatenation at test time, into a temporary repo that this file writes itself. "Real-shaped" means a
mixed letters+digits body of 32 characters derived from a fixed seed with hashlib: at least 12 distinct characters,
no placeholder word, no 3-run, no sequential 4-gram. The PR's own tests/make_testkeys_repo.py must exist, but the
pass criterion here never depends on it.

The rule under test (plan P88 section 2.3, C4): INFO only when U2 holds and at least one of U1/L1/L2 holds (or the
value itself says test: V1/V2, which is C3 and S3's). U1/L1/L2 in any combination without U2 stay FAIL and gain the
hint; U2 alone stays FAIL and gains the hint; no signal stays FAIL without it.

Contract strings fixed by this file (the plan gives the vocabulary and two examples; these are exact):
  signal names, always in the order U2, L1, L2, U1:
    U2 -> "assigned to <name>"      L1 -> "in a test file"
    L2 -> "inside <name>()"         U1 -> "compared in an assert"
  INFO evidence line: "looks like a test value: " + signals joined by " and "
  FAIL evidence line (only when >= 1 weak signal): "test signals seen: " + signals joined by ", "
  the hint, appended to the finding's "try" list (a FAIL with >= 1 weak signal only):
    "if this is a test value, make it say so (FAKE or TEST in the value, or one character repeated, like 000000) and it
     is reported as information"  (O5 deviation 2026-10-24: the plan's "0000" does not meet V2's run of 6)
  an INFO from C4 carries the C3 fix line "keep test values out of the source too, or make them obviously fake".
  top-level report key "test_values_graded": the number of secret.key INFO findings carrying a "looks like a test
  value" evidence line; present only when > 0.

Not in this file: the C7(b) numbers for the owner's scripts folder on Windows. They are measured by the overseer
through cg_review.py on the PR worktree and asserted by the overseer's S0 acceptance (test_p88_s0_acceptance.py).
Also required green in the full suite, not repeated here: test_readme_sync, test_tool_docs, test_plain, and the
windows-latest CI job.

ADR number: the plan names docs/adr/0009-test-values-are-graded-by-value-and-use.md, but 0009 is already taken on
main (0009-folder-dialog-refusals-reopen-loopback.md). This file accepts the slug under any ADR number not used by
another record (0010 is the next free one) and requires the ADR index to link it.
"""
import hashlib
import json
import os
import re
import string
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
FIXTURES = HERE / "fixtures"

HINT = ("if this is a test value, make it say so (FAKE or TEST in the value, or one character repeated, like 000000) "
        "and it is reported as information")
C3_FIX = "keep test values out of the source too, or make them obviously fake"
LOOKS = "looks like a test value: "
SEEN = "test signals seen: "
PREFIX = "s" + "k-"  # the sk- key shape (privacy pattern 5), split so this file holds no shape

# sha256 of the canonical `scan --json` of each fixture on main at S0 (top-level "version" and "path" dropped,
# json.dumps(sort_keys=True, indent=1)); risky_repo as built by tests/make_risky.build.
BEFORE = {
    "clean_repo": "5c1a5965f2978f22af70474f0ab81b264d48f2113c7af86fbbe9a2607a19f8d1",
    "complete_app": "4df1c2aa227cb223da14ff578a9a25005f8ab7c10e0c14a66dfe86bb467704d7",
    "complete_bare": "0fac84bb829c27cd90e3a45881ed17dd849012652422372483276ab7b0d65f9d",
    "orphan_repo": "d6d039fcb3b799626752c926cf048bc8af27dec17a4d8a808de98872bb81f69f",
    "risky_repo": "085fae5fb1b7becf5507dc3caee5ad974fe142db8b2abba4a19b77eb6b863ecc",
    "supply_repo": "3574a3faaef76c5b18653cfb334785e8d6770859723bfb64e75fceb9c7eb0724",
    "works_broken": "ffb102455fc0e66f933fe52699079cdeed8227a950b991e89e49d7851e2ccd8f",
    "works_weak_tests": "15b979c7fc9c8a1554508bf6711512c2394a45030c8e88fc70a3c03d9ae32846",
}
# A Windows checkout (CRLF) changes one fixture's report; every other digest is the same on both platforms.
BEFORE_NT = dict(BEFORE, complete_bare="aaebf8aaecbb12bb0b521dd1eef40c334d802e9a760accaa25c43e23be153657")

ALNUM = string.ascii_letters + string.digits
WORDS = ("mock", "fake", "dummy", "example", "placeholder", "sample", "redacted", "test", "testing", "notreal",
         "changeit")


def _sequential(body):
    low = body.lower()
    for i in range(len(low) - 3):
        g = low[i:i + 4]
        if all(ord(g[j + 1]) - ord(g[j]) == 1 for j in range(3)):
            return True
    return False


def real_body(seed, n=32):
    """A deterministic, mixed, high-variety key body that nothing about the value calls fake."""
    i = 0
    while True:
        out = ""
        k = 0
        while len(out) < n:
            for b in hashlib.sha256(("%s:%d:%d" % (seed, i, k)).encode("ascii")).digest():
                c = ALNUM[b % len(ALNUM)]
                if len(out) >= 2 and out[-1] == c and out[-2] == c:
                    continue
                out += c
            k += 1
        body = out[:n]
        low = body.lower()
        ok = (len(set(body)) >= 12 and not any(w in low for w in WORDS) and not _sequential(body)
              and any(c.isdigit() for c in body) and any(c.isupper() for c in body)
              and any(c.islower() for c in body))
        if ok:
            return body
        i += 1


def real_key(seed):
    return PREFIX + real_body(seed)


# One file per case, so U1 (same value compared in the same file) never leaks between cases. Each file holds
# exactly one key-shaped value.
def _cases():
    low_variety = PREFIX + "Q" * 28
    return {
        # U2 + L2 -> INFO
        "app/selfcheck.py": (
            "def _selftest():\n"
            "    test_key = \"%s\"\n"
            "    return len(test_key)\n" % real_key("u2-l2")),
        # U2 + L1 -> INFO
        "tests/conftest.py": (
            "FAKE_TOKEN = \"%s\"\n" % real_key("u2-l1")),
        # L1 + L2 + U1 -> FAIL with the hint (the classic leak)
        "tests/test_live.py": (
            "from app.config import load\n"
            "\n"
            "\n"
            "def test_x():\n"
            "    cfg = load()\n"
            "    assert cfg.key == \"%s\"\n" % real_key("l1-l2-u1")),
        # U1 + L2 -> FAIL with the hint
        "app/checks.py": (
            "def make():\n"
            "    return None\n"
            "\n"
            "\n"
            "def _selftest():\n"
            "    value = make()\n"
            "    assert value == \"%s\"\n" % real_key("u1-l2")),
        # L1 + L2 -> FAIL with the hint
        "tests/test_client.py": (
            "def connect(api=None):\n"
            "    return api\n"
            "\n"
            "\n"
            "def test_client():\n"
            "    connect(api=\"%s\")\n" % real_key("l1-l2")),
        # L2 alone -> FAIL with the hint
        "app/tool.py": (
            "def connect(api=None):\n"
            "    return api\n"
            "\n"
            "\n"
            "def _selftest():\n"
            "    return connect(api=\"%s\")\n" % real_key("l2")),
        # U2 alone -> FAIL with the hint
        "app/config.py": (
            "test_key = \"%s\"\n"
            "\n"
            "\n"
            "def load():\n"
            "    return None\n" % real_key("u2")),
        # no signal -> FAIL without the hint
        "app/settings.py": (
            "API_VALUE = \"%s\"\n" % real_key("none")),
        # V2 in a non-test file -> INFO (C3, unchanged by C4)
        "app/demo.py": (
            "DEMO_VALUE = \"%s\"\n" % low_variety),
        "app/__init__.py": "",
        "pyproject.toml": "[project]\nname = \"testkeys-demo\"\nversion = \"0.0.1\"\n",
    }


def _write(root, files):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8", newline="\n")
    return root


@pytest.fixture(scope="module")
def rep(tmp_path_factory):
    from code_guardian import report
    root = _write(tmp_path_factory.mktemp("p88s4") / "repo", _cases())
    return report.scan(str(root))


@pytest.fixture(scope="module")
def rep_no_assert(tmp_path_factory):
    """A real-shaped key in tests/test_live.py::test_x() with no assert and no fake-named variable."""
    from code_guardian import report
    files = {
        "app/__init__.py": "",
        "app/client.py": "def connect(api=None):\n    return api\n",
        "tests/test_live.py": (
            "from app.client import connect\n"
            "\n"
            "\n"
            "def test_x():\n"
            "    connect(api=\"%s\")\n" % real_key("no-assert")),
        "pyproject.toml": "[project]\nname = \"testkeys-demo2\"\nversion = \"0.0.1\"\n",
    }
    root = _write(tmp_path_factory.mktemp("p88s4b") / "repo", files)
    return report.scan(str(root))


def key_finding(report_, rel):
    got = [f for f in report_["findings"] if f["code"] == "secret.key" and f["node"].rpartition(":")[0] == rel]
    assert len(got) == 1, "expected exactly one secret.key finding in %s, got %d: %r" % (
        rel, len(got), [(f["level"], f["summary"]) for f in got])
    return got[0]


def lines_starting(f, head):
    return [e for e in f["evidence"] if e.startswith(head)]


def assert_info(f, exact_looks=None):
    assert f["level"] == "INFO", "%s: level %s, want INFO (evidence %r)" % (f["node"], f["level"], f["evidence"])
    looks = lines_starting(f, LOOKS)
    assert len(looks) == 1, "%s: want one %r evidence line, got %r" % (f["node"], LOOKS, f["evidence"])
    if exact_looks is not None:
        assert looks[0] == exact_looks, "%s: %r != %r" % (f["node"], looks[0], exact_looks)
    assert not lines_starting(f, SEEN), "%s: an INFO must not say %r" % (f["node"], SEEN)
    assert HINT not in f["try"], "%s: the FAIL hint is not for an INFO" % f["node"]


def assert_fail_with_hint(f, exact_seen):
    assert f["level"] == "FAIL", "%s: level %s, want FAIL (evidence %r)" % (f["node"], f["level"], f["evidence"])
    assert HINT in f["try"], "%s: the hint is missing from try %r" % (f["node"], f["try"])
    seen = lines_starting(f, SEEN)
    assert seen == [exact_seen], "%s: want evidence %r, got %r" % (f["node"], exact_seen, f["evidence"])
    assert not lines_starting(f, LOOKS), "%s: a FAIL must not say %r" % (f["node"], LOOKS)


# ------------------------------------------------------------------------------------------- the generator itself

def test_real_shaped_values_are_real_shaped():
    for seed in ("u2-l2", "u2-l1", "l1-l2-u1", "u1-l2", "l1-l2", "l2", "u2", "none", "no-assert"):
        body = real_body(seed)
        assert len(body) == 32 and len(set(body)) >= 12 and not _sequential(body)
        assert not any(w in body.lower() for w in WORDS)
    assert len({real_body(s) for s in ("u2-l2", "u2-l1", "l1-l2-u1", "u1-l2", "l1-l2", "l2", "u2", "none")}) == 8


# ------------------------------------------------------------------------------------------- INFO cases

def test_u2_l2_selftest_test_key_is_info(rep):
    f = key_finding(rep, "app/selfcheck.py")
    assert_info(f, LOOKS + "assigned to test_key and inside _selftest()")
    assert C3_FIX in f["try"]


def test_u2_l1_fake_token_in_conftest_is_info(rep):
    f = key_finding(rep, "tests/conftest.py")
    assert_info(f, LOOKS + "assigned to FAKE_TOKEN and in a test file")
    assert C3_FIX in f["try"]
    assert not [e for e in f["evidence"] if "reported at INFO (was" in e], "C4 grades it, not _test_code_to_info"


def test_v2_low_variety_in_non_test_file_is_info(rep):
    f = key_finding(rep, "app/demo.py")
    assert_info(f)  # the reason wording is C3's (S3); C4 must not change it to FAIL


# ------------------------------------------------------------------------------------------- FAIL cases

def test_assert_in_test_function_in_test_file_stays_fail(rep):
    f = key_finding(rep, "tests/test_live.py")
    assert_fail_with_hint(f, SEEN + "in a test file, inside test_x(), compared in an assert")


def test_u1_l2_stays_fail_with_hint(rep):
    f = key_finding(rep, "app/checks.py")
    assert_fail_with_hint(f, SEEN + "inside _selftest(), compared in an assert")


def test_l1_l2_stays_fail_with_hint(rep):
    f = key_finding(rep, "tests/test_client.py")
    assert_fail_with_hint(f, SEEN + "in a test file, inside test_client()")


def test_l2_alone_stays_fail_with_hint(rep):
    f = key_finding(rep, "app/tool.py")
    assert_fail_with_hint(f, SEEN + "inside _selftest()")


def test_u2_alone_stays_fail_with_hint(rep):
    f = key_finding(rep, "app/config.py")
    assert_fail_with_hint(f, SEEN + "assigned to test_key")


def test_no_signal_stays_fail_without_hint(rep):
    f = key_finding(rep, "app/settings.py")
    assert f["level"] == "FAIL"
    assert HINT not in f["try"]
    assert not lines_starting(f, SEEN) and not lines_starting(f, LOOKS)


def test_real_key_in_test_x_without_assert_stays_fail(rep_no_assert):
    f = key_finding(rep_no_assert, "tests/test_live.py")
    assert_fail_with_hint(f, SEEN + "in a test file, inside test_x()")


# ------------------------------------------------------------------------------------------- summary key

def test_test_values_graded_counts_the_info_findings(rep):
    graded = [f for f in rep["findings"] if f["code"] == "secret.key" and f["level"] == "INFO"
              and lines_starting(f, LOOKS)]
    assert len(graded) == 3, [f["node"] for f in graded]
    assert rep.get("test_values_graded") == 3


def test_test_values_graded_absent_without_downgrades(rep_no_assert):
    from code_guardian import report
    assert "test_values_graded" not in report.scan(str(FIXTURES / "clean_repo"))
    assert "test_values_graded" not in rep_no_assert


def test_test_code_to_info_still_leaves_key_shape_fails_alone():
    from code_guardian import report, scanners
    f = scanners.finding("secret.key", "FAIL", "tests/test_a.py:3", "sk- key shape in the source; value redacted",
                         ["matched: x", "length: 30 characters", scanners.KEY_SHAPE], ["rotate it"])
    out = report._test_code_to_info([f])
    assert out[0]["level"] == "FAIL"


def test_report_scan_calls_test_key_context():
    import inspect
    from code_guardian import report
    assert callable(getattr(report, "_test_key_context", None)), "report._test_key_context is missing (C4)"
    assert "_test_key_context(" in inspect.getsource(report.scan), "report.scan does not call _test_key_context"


# ------------------------------------------------------------------------------------------- nothing else moved

def _canon(raw):
    d = json.loads(raw)
    d.pop("version", None)
    d.pop("path", None)
    d.pop("weights", None)  # P81 S2 adds weight rows; test_golden excludes weights the same way
    d.pop("schema_version", None)  # P81 S4 bumps it; the additive keys below are test_golden's
    d.get("files", {}).pop("javascript", None)
    d.get("files", {}).pop("generated", None)
    d.get("coverage", {}).pop("languages", None)
    return json.dumps(d, sort_keys=True, indent=1)


@pytest.mark.parametrize("name", sorted(BEFORE))
def test_fixture_report_is_byte_identical_to_s0(name, tmp_path):
    target = FIXTURES / name
    if name == "risky_repo":
        sys.path.insert(0, str(HERE))
        import make_risky
        target = make_risky.build(tmp_path / "risky_repo")
    env = dict(os.environ, PYTHONPATH=str(ROOT))
    p = subprocess.run([sys.executable, "-m", "code_guardian", "scan", str(target), "--json"], cwd=str(ROOT),
                       env=env, capture_output=True, text=True, encoding="utf-8")
    assert p.stdout.strip().startswith("{"), p.stderr[-800:]
    digest = hashlib.sha256(_canon(p.stdout).encode("utf-8")).hexdigest()
    if name == "risky_repo":
        pytest.skip("risky_repo changes on purpose in P81 S4; test_golden checks it through its delta")
    want = (BEFORE_NT if os.name == "nt" else BEFORE)[name]
    assert digest == want, "%s report changed since S0 (sha256 %s)" % (name, digest)


# ------------------------------------------------------------------------------------------- docs (C8)

def _read(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def test_builder_and_unit_test_files_exist():
    assert (HERE / "make_testkeys_repo.py").is_file()
    assert (HERE / "test_report.py").is_file()


def test_changelog_has_a_041_section():
    assert re.search(r"^## .*\b0\.4\.1\b", _read("CHANGELOG.md"), re.M), "CHANGELOG.md has no 0.4.1 heading"


def test_readme_upgrading_line():
    text = _read("README.md")
    i = text.find("Upgrading to 0.4.1")
    assert i >= 0, "README.md has no 'Upgrading to 0.4.1' line"
    assert "code-guardian baseline" in text[i:i + 800], "the Upgrading line must say to re-record the baseline"


def test_readme_backup_copies_in_the_app_section():
    text = _read("README.md")
    m = re.search(r"^## The app\s*$(.*?)(?=^## )", text, re.M | re.S)
    assert m, "README.md has no '## The app' section"
    assert "Backup copies" in m.group(1), "no 'Backup copies' paragraph inside The app section"


def test_readme_cli_table_has_exclude():
    assert re.search(r"^\|\s*`--exclude", _read("README.md"), re.M), "no `--exclude` row in a README table"


def test_adr_test_values_exists_and_is_indexed():
    adr = ROOT / "docs" / "adr"
    hits = sorted(adr.glob("[0-9][0-9][0-9][0-9]-test-values-are-graded-by-value-and-use.md"))
    assert len(hits) == 1, "want one docs/adr/NNNN-test-values-are-graded-by-value-and-use.md, got %r" % hits
    num = hits[0].name[:4]
    same = [p.name for p in adr.glob(num + "-*.md")]
    assert same == [hits[0].name], "ADR number %s is shared: %r" % (num, same)
    body = hits[0].read_text(encoding="utf-8").lower()
    for word in ("location", "value", "history", "assert"):
        assert word in body, "the ADR does not discuss %r" % word
    assert "(%s)" % hits[0].name in _read("docs/adr/README.md"), "docs/adr/README.md does not link the new ADR"


def test_calibration_has_the_041_section():
    assert re.search(r"^#{2,3} Backup folders and test values \(0\.4\.1\)\s*$", _read("calibration.md"), re.M)
