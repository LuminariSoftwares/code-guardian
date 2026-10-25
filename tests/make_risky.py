"""Build a copy of tests/fixtures/risky_repo with the key-shaped strings added.

Key-shaped strings are never stored in a tracked file (the privacy scan would rightly flag them): they are built here
by concatenation, at test time, into a temporary copy.

    python tests/make_risky.py DEST      # DEST must not exist
"""
import hashlib
import re
import shutil
import string
import sys
from pathlib import Path

SOURCE = Path(__file__).resolve().parent / "fixtures" / "risky_repo"
_PLACEHOLDERS = ("mock", "fake", "dummy", "example", "placeholder", "sample", "redacted", "test", "notreal", "changeit")


def mixed_body(seed, length, alphabet=string.ascii_letters + string.digits):
    """A deterministic key body that reads like a real one, so a test that models a real leak keeps failing as one:
    `length` letters and digits drawn from hashlib(seed), at least 12 distinct characters, no character three times
    in a row, no placeholder word. The same seed always gives the same body."""
    n = 0
    while True:
        digest = hashlib.sha256(("%s:%d" % (seed, n)).encode("utf-8")).digest()
        body = "".join(alphabet[b % len(alphabet)] for b in digest[:length])
        n += 1
        if (len(body) == length and len(set(body)) >= 12 and any(c.isdigit() for c in body)
                and any(c.isalpha() for c in body) and not re.search(r"(.)\1\1", body)
                and not any(w in body.lower() for w in _PLACEHOLDERS)):
            return body


def risky_key():
    """The key build() writes as line 1 of risky/settings.py: sk- and 24 mixed characters."""
    return "sk-" + mixed_body("make_risky", 24)


def build(dest):
    dest = Path(dest)
    shutil.copytree(SOURCE, dest)
    key = risky_key()
    password = "Tr0ub4dor" + "-and-3"
    alphabet = string.ascii_letters + string.digits
    seed, token = 12345, ""
    for _ in range(48):  # a fixed pseudo-random draw: high entropy, and it repeats characters like a real token
        seed = (seed * 1103515245 + 12345) % 2 ** 31
        token += alphabet[(seed >> 16) % len(alphabet)]
    (dest / "risky" / "settings.py").write_text(
        'API_KEY_VALUE = "%s"\npassword = "%s"\nTOKEN_BLOB = "%s"\n' % (key, password, token), encoding="utf-8")
    (dest / "deploy").mkdir()
    (dest / "deploy" / "id_rsa").write_text(
        "-----BEGIN " + "RSA PRIVATE KEY-----\nfixture-not-a-real-key\n-----END " + "RSA PRIVATE KEY-----\n",
        encoding="utf-8")
    return dest


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python tests/make_risky.py DEST")
    print(build(sys.argv[1]))
