"""Build a copy of tests/fixtures/risky_repo with the key-shaped strings added.

Key-shaped strings are never stored in a tracked file (the privacy scan would rightly flag them): they are built here
by concatenation, at test time, into a temporary copy.

    python tests/make_risky.py DEST      # DEST must not exist
"""
import shutil
import string
import sys
from pathlib import Path

SOURCE = Path(__file__).resolve().parent / "fixtures" / "risky_repo"


def build(dest):
    dest = Path(dest)
    shutil.copytree(SOURCE, dest)
    key = "sk-" + "A" * 24
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
