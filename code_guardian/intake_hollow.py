"""Repo intake, hollow projects: a README that sells a tool, almost no code behind it, and the weight in releases,
archives or binaries. A common shape for fake tools whose "release" is the payload.

    hollow.readme_heavy   README of 5,000+ bytes, three or fewer source files and little source compared to the README;
                          medium when binaries or archives are shipped or the README pushes releases / downloads,
                          low when it is only a big README with no code

A heuristic: docs-only repos (awesome lists, specs, books) are legitimately like this, so without binaries or a
download push it stays low.
"""

import re

from . import intake_rules as R
from .intake_rules import check, finding

R.RULES["hollow.readme_heavy"] = {
    "title": "Large README, almost no code",
    "means": "The README is long, the repository has at most a few source files and far less code than text, and it "
             "ships archives or programs or pushes you to download releases. Fake tools often look like this: the "
             "page is the product, the download is the payload.",
    "false_positives": "Documentation, lists, specs and book repos are all README and no code. Without binaries or a "
                       "download push the finding is only low.",
}

README = re.compile(r"(?i)^(?:readme)(?:\.\w+)?$")
README_MIN = 5000
SOURCE_FILES_MAX = 3
RATIO = 0.25
BINARY_EXT = frozenset({".exe", ".msi", ".scr", ".dll", ".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".jar", ".dmg", ".pkg", ".apk", ".iso", ".cab", ".lnk"})
PUSH = re.compile(r"(?i)/releases?\b|releases/download|\bdownload (?:the )?(?:latest|release|installer|setup)\b|\bget it now\b|\bfree download\b")


@check("hollow.readme_heavy")
def readme_heavy(ctx):
    readmes = [r for r in ctx.files if "/" not in r and README.match(r)]
    if not readmes:
        return []
    rel = max(readmes, key=lambda r: ctx.manifest[r]["size"])
    size = ctx.manifest[rel]["size"]
    if size < README_MIN:
        return []
    src = [r for r in ctx.files if R.is_code(r)]
    src_bytes = sum(ctx.manifest[r]["size"] for r in src)
    if len(src) > SOURCE_FILES_MAX or src_bytes > size * RATIO:
        return []
    bins = [r for r in ctx.files if R.ext(r) in BINARY_EXT or ctx.head(r, 4)[:2] == b"MZ" or ctx.head(r, 4)[:4] == b"\x7fELF"]
    text = ctx.text(rel) or ""
    push = len(PUSH.findall(text))
    conf = "medium" if bins or push >= 2 else "low"
    return [finding("hollow.readme_heavy", conf, rel, 0,
                    "README %d bytes; %d source file%s, %d bytes of source; %d binaries/archives; %d download/release links"
                    % (size, len(src), "" if len(src) == 1 else "s", src_bytes, len(bins), push),
                    "README is %d bytes against %d bytes of source" % (size, src_bytes))]
