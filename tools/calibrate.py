"""Re-run the calibration in calibration.md: clone each repository at its pinned commit and scan it offline.

    python tools/calibrate.py [WORKDIR]     # network for git only; the scans themselves are offline

Prints one table row per repository, then every FAIL and WARN. Needs git on PATH.
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

REPOS = [
    ("psf/requests", "611c6162cbc4ac2020a2f91c7cfa4f3abf9bbb60"),
    ("pallets/click", "2247b35ea1c47c727d7a06e51fa280e12a863ff6"),
    ("Textualize/rich", "9d8f9a372cc5916fd4781fec207ced7ddac2f08f"),
    ("encode/httpx", "b5addb64f0161ff6bfe94c124ef76f6a1fba5254"),
    ("pallets/flask", "d086db856be187255b8ec61ef409357393020f32"),
    ("LuminariSoftwares/stack-guardian", "9561a8f58e696f978c2d9f8bdda75d31a4d598b4"),
    ("LuminariSoftwares/context-guardian", "ad7aebc67476c9a5cfe294c62a782813dbbef21d"),
    ("LuminariSoftwares/tool-guardian", "3fd93288716ab5a83ed89b0d942f586eec253638"),
]


def checkout(repo, sha, workdir):
    dest = Path(workdir) / repo.replace("/", "__")
    if not (dest / ".git").exists():
        subprocess.run(["git", "init", "-q", str(dest)], check=True)
        subprocess.run(["git", "-C", str(dest), "fetch", "-q", "--depth", "1", "https://github.com/%s" % repo, sha],
                       check=True)
    subprocess.run(["git", "-C", str(dest), "checkout", "-q", sha], check=True)
    return dest


def scan(path):
    r = subprocess.run([sys.executable, "-m", "code_guardian", "scan", str(path), "--json"], capture_output=True,
                       text=True)
    return json.loads(r.stdout)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    workdir = argv[0] if argv else tempfile.mkdtemp(prefix="cg-calibration-")
    print("| repo | commit | Safe | Works | Complete | Overall | grade | FAIL | WARN |")
    details = []
    for repo, sha in REPOS:
        rep = scan(checkout(repo, sha, workdir))
        s = rep["scores"]
        items = [f for f in rep["findings"] + rep["hygiene"]["findings"] if f["level"] in ("FAIL", "WARN")]
        print("| %s | `%s` | %d | %d | %d | %d | %s | %d | %d |" % (
            repo, sha[:12], s["safe"], s["works"], s["complete"], s["overall"], s["grade"],
            sum(f["level"] == "FAIL" for f in items), sum(f["level"] == "WARN" for f in items)))
        details.extend((repo, f) for f in items)
    print()
    for repo, f in details:
        print("%s  %s  %s  %s  %s" % (repo, f["level"], f["code"], f["node"], f["summary"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
