"""Build a copy of tests/fixtures/backup_repo with the key-shaped value planted in its _archive/ copy.

The tree holds an app (app/main.py), a backup copy the app still imports (old/helper.py, with one finding of its own)
and a backup copy nothing uses (_archive/). After build, every finding inside _archive/ is a secret.key FAIL: one
provider-shaped key, mixed letters and digits with many distinct characters and no repeated run, the way a real key
looks, and under the 40 characters where the high-entropy literal rule starts. It is built here by concatenation, at
test time, into a temporary copy: no key shape is ever stored in a tracked file (the privacy scan would rightly flag
it).

The repository's .gitignore ignores every _archive/ folder, so tests/fixtures/backup_repo/_archive/main_v1.py is
tracked with `git add -f`; build() makes _archive/ itself if a checkout lacks it.

    python tests/make_backup_repo.py DEST      # DEST must not exist
"""
import shutil
import string
import sys
from pathlib import Path

SOURCE = Path(__file__).resolve().parent / "fixtures" / "backup_repo"


def mixed_key(length=32, seed=20260824):
    """A fixed pseudo-random draw from letters and digits that never repeats the character before it."""
    alphabet = string.ascii_letters + string.digits
    out = ""
    while len(out) < length:
        seed = (seed * 1103515245 + 12345) % 2 ** 31
        ch = alphabet[(seed >> 16) % len(alphabet)]
        if not out or ch != out[-1]:
            out += ch
    return out


def build(dest):
    dest = Path(dest)
    shutil.copytree(SOURCE, dest)
    (dest / "_archive").mkdir(exist_ok=True)
    (dest / "_archive" / "settings_v1.py").write_text(
        '"""Settings as they were in the first version: kept for reference, never run."""\n\n'
        'OPENAI_API_KEY = "%s"\n' % ("sk-" + mixed_key()), encoding="utf-8")
    return dest


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python tests/make_backup_repo.py DEST")
    print(build(sys.argv[1]))
