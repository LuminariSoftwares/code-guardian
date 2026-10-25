"""Build a small repo with one key-shaped value per way a test value can be used (P88 C4).

Every value is real-shaped (letters and digits, many distinct characters, no placeholder word), so only the way the
value is used can grade it. Key-shaped strings are never stored in a tracked file (the privacy scan would rightly flag
them): they are built here by concatenation, at test time. One file per case, so one case never reads another's
asserts.

    python tests/make_testkeys_repo.py DEST      # DEST must not exist

EXPECTED maps each file to what the scan must say about its one secret.key finding: the level and the evidence line
that names the signals (None when the finding carries none).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from make_risky import mixed_body  # noqa: E402

PREFIX = "s" + "k-"


def key(seed):
    return PREFIX + mixed_body("make_testkeys_repo:" + seed, 32)


def files():
    """{relative path: text} of the repo."""
    return {
        "app/__init__.py": "",
        "pyproject.toml": '[project]\nname = "testkeys-demo"\nversion = "0.0.1"\n',
        "app/selfcheck.py": 'def _selftest():\n    test_key = "%s"\n    return len(test_key)\n' % key("u2-l2"),
        "tests/conftest.py": 'FAKE_TOKEN = "%s"\n' % key("u2-l1"),
        "tests/test_live.py": ("from app.config import load\n\n\ndef test_x():\n    cfg = load()\n"
                               '    assert cfg.key == "%s"\n' % key("l1-l2-u1")),
        "app/checks.py": ("def make():\n    return None\n\n\ndef _selftest():\n    value = make()\n"
                          '    assert value == "%s"\n' % key("u1-l2")),
        "tests/test_client.py": ('def connect(api=None):\n    return api\n\n\ndef test_client():\n'
                                 '    connect(api="%s")\n' % key("l1-l2")),
        "app/tool.py": ('def connect(api=None):\n    return api\n\n\ndef _selftest():\n'
                        '    return connect(api="%s")\n' % key("l2")),
        "app/config.py": 'test_key = "%s"\n\n\ndef load():\n    return None\n' % key("u2"),
        "app/settings.py": 'API_VALUE = "%s"\n' % key("none"),
        "app/demo.py": 'DEMO_VALUE = "%s"\n' % (PREFIX + "Q" * 28),
    }


EXPECTED = {
    "app/selfcheck.py": ("INFO", "looks like a test value: assigned to test_key and inside _selftest()"),
    "tests/conftest.py": ("INFO", "looks like a test value: assigned to FAKE_TOKEN and in a test file"),
    "tests/test_live.py": ("FAIL", "test signals seen: in a test file, inside test_x(), compared in an assert"),
    "app/checks.py": ("FAIL", "test signals seen: inside _selftest(), compared in an assert"),
    "tests/test_client.py": ("FAIL", "test signals seen: in a test file, inside test_client()"),
    "app/tool.py": ("FAIL", "test signals seen: inside _selftest()"),
    "app/config.py": ("FAIL", "test signals seen: assigned to test_key"),
    "app/settings.py": ("FAIL", None),
    "app/demo.py": ("INFO", "looks like a test value: is mostly one character"),
}


def build(dest):
    dest = Path(dest)
    for rel, text in files().items():
        path = dest / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
    return dest


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python tests/make_testkeys_repo.py DEST")
    if Path(sys.argv[1]).exists():
        sys.exit("DEST exists")
    print(build(sys.argv[1]))
