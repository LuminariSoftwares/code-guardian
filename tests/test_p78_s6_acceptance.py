"""P78 S6 acceptance -- README and CHANGELOG for app v1.1 (plan P78 C9), and the https rule for the page files.

Written by the overseer BEFORE the build session. The build session must add this file to the PR byte-for-byte and
must not edit it; a PR that changes it fails the section. This file is pure ASCII on purpose.

Amended by the overseer after PR #39 (P78 deviation 20): the plan's C9 paragraph promised Tailscale Serve and an SSH
tunnel with mismatched ports, and the page's Host guard refuses both (it answers only 127.0.0.1 / localhost with its
own port). The paragraph below says what is true today.

Amended again by the overseer at P76 S7 (release 0.4.0): the CHANGELOG check read `## Unreleased`, which the release
renames to its 0.4.0 heading. It now reads the 0.4.0 section, which stays in the file after later releases.
"""
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
UI = ROOT / "code_guardian" / "ui"

FROM_A_PHONE = (
    "code-guardian ui only ever listens on 127.0.0.1 of the computer it runs on; it never opens a port to your "
    "network, and the page only answers when the address in the browser is 127.0.0.1 or localhost with the port "
    "code-guardian printed. To look at it from a phone, use an SSH tunnel you already trust with the same port number "
    "on both ends (`ssh -L <port>:127.0.0.1:<port> you@that-computer`, where <port> is the one in the printed link, "
    "usually 8765), then open the printed link on the phone. Tailscale Serve and other proxies that pass on their own "
    "address are refused for now. The Browse button opens its folder window on the computer running code-guardian, "
    "not on the phone."
)
SECTIONS = ("Settings", "Sizes", "Every file", "Browse and the folders it refuses", "Re-open vs Check again",
            "From a phone")
SHOTS = ("result_390x844.png", "result_light_1280x800.png", "code_1280x800.png", "settings_390x844.png")


def _readme():
    return (ROOT / "README.md").read_text(encoding="utf-8")


def _flat(text):
    return re.sub(r"\s+", " ", text)


def test_from_a_phone_paragraph_verbatim():
    assert FROM_A_PHONE in _flat(_readme()), "the From a phone paragraph is not in README.md verbatim"


def test_the_app_section_has_the_six_parts_in_order():
    text = _readme()
    places = []
    for name in SECTIONS:
        m = re.search(r"^#{2,4}\s+%s\s*$" % re.escape(name), text, re.M)
        assert m, "no heading named %r" % name
        places.append(m.start())
    assert places == sorted(places), "the six parts are out of order"


def test_four_screenshots_in_the_readme():
    text = _readme()
    for shot in SHOTS:
        assert re.search(r"docs/screenshots/%s" % re.escape(shot), text), shot
        assert (ROOT / "docs" / "screenshots" / shot).is_file(), shot


def test_browse_refusals_and_the_cli_note():
    flat = _flat(_readme())
    assert "`code-guardian scan` on the command line is not limited" in flat
    for word in ("Downloads", "Desktop", "Documents", "OneDrive", "home folder", "drive"):
        assert word in flat, word


def test_partly_checked_and_not_read_are_explained():
    flat = _flat(_readme())
    assert "Partly checked" in flat and "Not read" in flat
    assert re.search(r"(Partly checked|Not read)[^.]*\bnot\b[^.]*no (known )?risks", flat, re.I), \
        "the README must say Partly checked / Not read are not the same as no known risks"


def test_https_appears_once_in_the_page_files():
    html = (UI / "index.html").read_text(encoding="utf-8")
    assert html.count("https://") == 1, html.count("https://")
    for name in ("app.js", "app.css"):
        assert "https://" not in (UI / name).read_text(encoding="utf-8"), name


def test_changelog_names_the_six_sections():
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    m = re.search(r"^## [^\n]*\b0\.4\.0\b[^\n]*$(.*?)(?=^## |\Z)", text, re.M | re.S)
    assert m, "no ## ... 0.4.0 ... section"
    body = m.group(1).lower()
    for word in ("settings", "size", "every file", "browse", "re-open", "phone"):
        assert word in body, word
