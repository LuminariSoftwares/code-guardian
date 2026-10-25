"""Build a copy of tests/fixtures/js_risky with the one key-shaped value added.

The key shape is never stored in a tracked file (the privacy scan would rightly flag it): it is built here, at test
time, into a temporary copy -- the way tests/make_risky.py does for risky_repo.

    python tests/make_risky_js.py DEST      # DEST must not exist
"""
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import make_risky  # noqa: E402  (mixed_body: the same deterministic key body)

SOURCE = Path(__file__).resolve().parent / "fixtures" / "js_risky"


def risky_key():
    """The key build() writes as line 1 of config.js: sk- and 24 mixed characters."""
    return "sk-" + make_risky.mixed_body("make_risky_js", 24)


def build(dest):
    dest = Path(dest)
    shutil.copytree(SOURCE, dest)
    (dest / "config.js").write_text('const API_KEY_VALUE = "%s";\nmodule.exports = { API_KEY_VALUE };\n'
                                        % risky_key(), encoding="utf-8")
    return dest


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python tests/make_risky_js.py DEST")
    print(build(sys.argv[1]))
