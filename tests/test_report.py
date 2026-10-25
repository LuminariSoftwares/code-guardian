"""report._test_key_context (P88 C4): how a key-shaped FAIL is read by the way its value is used. The acceptance file
(test_p88_s4_acceptance.py) pins the strings; these check the rule's edges on small trees."""
import ast
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import make_testkeys_repo as mk  # noqa: E402
from code_guardian import report, scanners  # noqa: E402

HINT = report.TEST_VALUE_HINT


def graded(rel, source):
    """The one secret.key finding of a one-file project after _test_key_context, from the scan's own scanners."""
    found = scanners.scan_secret_text(rel, source, python=True)
    assert len(found) == 1 and found[0]["level"] == "FAIL", found
    out = report._test_key_context(found, {rel: ast.parse(source)}, {rel: source})
    return out[0]


def seen(f):
    return [e for e in f["evidence"] if e.startswith("test signals seen: ")]


@pytest.fixture(scope="module")
def scanned(tmp_path_factory):
    return report.scan(str(mk.build(tmp_path_factory.mktemp("testkeys") / "repo")))


def test_builder_cases_grade_as_expected(scanned):
    for rel, (level, line) in mk.EXPECTED.items():
        got = [f for f in scanned["findings"] if f["code"] == "secret.key" and f["node"].startswith(rel + ":")]
        assert len(got) == 1, rel
        f = got[0]
        assert f["level"] == level, (rel, f["evidence"])
        lines = [e for e in f["evidence"] if e.startswith(("looks like a test value", "test signals seen"))]
        assert lines == ([line] if line else []), (rel, f["evidence"])
        assert (HINT in f["try"]) == (level == "FAIL" and line is not None), rel


def test_summary_key_counts_graded_info_and_is_printed(scanned):
    assert scanned["test_values_graded"] == 3
    assert "3 key-shaped value(s) look like test values" in report.render(scanned)


def test_info_from_context_keeps_the_c3_fix_and_no_test_code_line(scanned):
    f = next(f for f in scanned["findings"] if f["node"].startswith("tests/conftest.py:"))
    assert f["try"] == [report.TEST_VALUE_FIX]
    assert "looks like a test value" in f["summary"]
    assert not [e for e in f["evidence"] if "reported at INFO (was" in e]


def test_the_value_never_appears_in_the_report(scanned):
    text = repr(scanned)
    for body in (mk.key(s) for s in ("u2-l2", "u2-l1", "l1-l2-u1", "u1-l2", "l1-l2", "l2", "u2", "none")):
        assert body not in text


def key(seed="t"):
    return mk.key(seed)


def test_location_alone_is_never_info():
    f = graded("tests/test_a.py", 'KEY = "%s"\n' % key())
    assert f["level"] == "FAIL" and seen(f) == ["test signals seen: in a test file"] and HINT in f["try"]


def test_comparison_alone_is_never_info():
    f = graded("app/a.py", 'def check(x):\n    return x == "%s"\n' % key())
    assert f["level"] == "FAIL" and seen(f) == ["test signals seen: compared in an assert"]


def test_comparison_elsewhere_in_the_file_counts():
    v = key()
    src = 'KEEP = "%s"\n\n\ndef f(x):\n    return x == "%s"\n' % (v, v)
    out = report._test_key_context(scanners.scan_secret_text("app/a.py", src, python=True),
                                   {"app/a.py": ast.parse(src)}, {"app/a.py": src})
    assert [seen(f) for f in out] == [["test signals seen: compared in an assert"]] * 2


def test_fake_name_with_no_second_signal_stays_fail():
    f = graded("app/a.py", 'fake_key = "%s"\n' % key())
    assert f["level"] == "FAIL" and seen(f) == ["test signals seen: assigned to fake_key"]


@pytest.mark.parametrize("source,name", [
    ('def _selftest():\n    connect(sample_key="%s")\n', "sample_key"),                  # keyword argument
    ('class C:\n    def _selftest(self):\n        self.dummy_token = "%s"\n', "dummy_token"),  # attribute target
    ('def _selftest():\n    TestKey: str = "%s"\n', "TestKey"),                  # annotated, camel case
])
def test_u2_reads_keywords_attributes_annotations_and_camel_case(source, name):
    f = graded("app/a.py", source % key())
    assert f["level"] == "INFO" and ("assigned to " + name) in f["evidence"][-1]


def test_innermost_scope_decides_l2():
    outer = 'def test_outer():\n    def helper():\n        return connect(api="%s")\n    return helper\n'
    f = graded("app/a.py", outer % key())
    assert f["level"] == "FAIL" and seen(f) == []   # helper is not a fake name: the test_ around it does not count
    inner = 'def run():\n    def _selftest():\n        return connect(api="%s")\n    return _selftest\n'
    assert seen(graded("app/a.py", inner % key())) == ["test signals seen: inside _selftest()"]


def test_async_and_class_scopes_count():
    assert seen(graded("app/a.py", 'async def test_it():\n    connect(api="%s")\n' % key())) == [
        "test signals seen: inside test_it()"]
    assert seen(graded("app/a.py", 'class TestLive:\n    API = "%s"\n' % key())) == [
        "test signals seen: inside TestLive()"]


def test_names_only_count_on_whole_words():
    for name in ("latest_key", "contest", "attestation", "protest_value"):
        f = graded("app/a.py", '%s = "%s"\n' % (name, key()))
        assert f["level"] == "FAIL" and seen(f) == [] and HINT not in f["try"], name


def test_a_multi_line_string_is_found_by_its_span():
    v = key()
    f = graded("app/a.py", 'def _selftest():\n    test_key = """\n%s\n"""\n' % v)
    assert f["level"] == "INFO"


def test_unparsed_file_and_non_python_files_are_left_alone():
    v = key()
    found = scanners.scan_secret_text("tests/test_a.py", 'FAKE_KEY = "%s"\n' % v, python=True)
    assert report._test_key_context(found, {}, {"tests/test_a.py": 'FAKE_KEY = "%s"\n' % v})[0]["level"] == "FAIL"
    cfg = scanners.scan_secret_text("config/test.env", "FAKE_KEY=%s\n" % v, python=False)
    assert report._test_key_context(cfg, {}, {"config/test.env": "FAKE_KEY=%s\n" % v})[0]["level"] == "FAIL"
    assert not seen(cfg[0]) and HINT not in cfg[0]["try"]


def test_only_key_shape_fails_are_read():
    f = scanners.finding("secret.key", "FAIL", "tests/test_a.py:1", "password-like literal; value redacted",
                         ["matched: password-like literal"], ["move it"])
    src = 'FAKE_PASSWORD = "hunter2-hunter2"\n'
    out = report._test_key_context([f], {"tests/test_a.py": ast.parse(src)}, {"tests/test_a.py": src})
    assert out[0]["level"] == "FAIL" and out[0]["evidence"] == ["matched: password-like literal"]


def test_no_graded_key_means_no_summary_key(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "a.py").write_text('API_VALUE = "%s"\n' % key(), encoding="utf-8")
    rep = report.scan(str(tmp_path))
    assert "test_values_graded" not in rep and "look like test values" not in report.render(rep)


@pytest.mark.parametrize("scope", ["stub_client", "fixture_keys", "StubClient", "make_fixtures"])
def test_stub_and_fixture_scopes_count_for_l2(scope):
    f = graded("app/a.py", 'def %s():\n    test_key = "%s"\n' % (scope, key(scope)))
    assert f["level"] == "INFO"
    assert f["evidence"][-1] == "looks like a test value: assigned to test_key and inside %s()" % scope
