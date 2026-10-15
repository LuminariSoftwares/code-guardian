"""Build code_guardian/data/known_packages.txt.gz from the hand-built tools/known_packages.txt.

    python tools/build_known_packages.py            # normalise, de-duplicate, sort, write
    python tools/build_known_packages.py --verify   # also ask PyPI that every name exists; drop and list the ones
                                                    # that do not (network; the build itself never needs it)

The gzip is written with mtime 0, so the same list always gives the same bytes.
"""
import concurrent.futures
import gzip
import io
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "tools" / "known_packages.txt"
TARGET = ROOT / "code_guardian" / "data" / "known_packages.txt.gz"
PYPI = "https://pypi.org/pypi/%s/json"


def normalise(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def read_source(path=SOURCE):
    names = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0]
        names.update(normalise(token) for token in line.split())
    return sorted(names)


def exists(name):
    try:
        with urllib.request.urlopen(PYPI % name, timeout=20) as resp:
            return name, resp.status == 200
    except urllib.error.HTTPError as exc:
        return name, False if exc.code == 404 else None
    except (urllib.error.URLError, OSError):
        return name, None


def write(names, target=TARGET):
    data = ("# code-guardian known PyPI projects: hand-built (tools/known_packages.txt), %d names\n" % len(names)
            + "".join(n + "\n" for n in names)).encode("utf-8")
    buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buf, mtime=0) as gz:
        gz.write(data)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(buf.getvalue())


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    names = read_source()
    if "--verify" in argv:
        with concurrent.futures.ThreadPoolExecutor(16) as pool:
            answers = dict(pool.map(exists, names))
        missing = sorted(n for n, ok in answers.items() if ok is False)
        unknown = sorted(n for n, ok in answers.items() if ok is None)
        for n in missing:
            print("not on PyPI, dropped:", n)
        for n in unknown:
            print("could not check, kept:", n)
        names = [n for n in names if n not in missing]
    write(names)
    print("wrote %d names to %s" % (len(names), TARGET.relative_to(ROOT).as_posix()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
