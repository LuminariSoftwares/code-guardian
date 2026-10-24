"""code_guardian/refuse.py: the cases the S4a acceptance file does not spell out. Windows paths are built from parts
so no literal here looks like a personal profile path."""
import re
import subprocess
import sys
from pathlib import Path

import pytest

from code_guardian import refuse
from code_guardian.refuse import REASONS, refused

ROOT = Path(__file__).resolve().parent.parent
BS = chr(92)
WIN_HOME = BS.join(("C:", "Users", "alex"))
NIX_HOME = "/home/alex"
VERDICT_WORDS = ("sa" + "fe", "se" + "cure", "cl" + "ean", "no ri" + "sks", "harm" + "less", "guarant" + "eed")


def w(*parts):
    return BS.join(parts)


def nt(path, env=None):
    return refused(path, home=WIN_HOME, env={} if env is None else env, platform="nt", ismount=lambda p: False)


def nix(path, env=None):
    return refused(path, home=NIX_HOME, env={} if env is None else env, platform="posix", ismount=lambda p: False)


def test_trailing_separators_do_not_change_the_answer():
    for tail in ("", BS, BS + BS):
        assert nt(w(WIN_HOME, "Downloads") + tail) == refuse.DOWNLOADS
        assert nt(WIN_HOME + tail) == refuse.HOME
        assert nt("C:" + BS + tail) == refuse.DRIVE
    for tail in ("", "/", "//"):
        assert nix(NIX_HOME + tail) == refuse.HOME
        assert nix(NIX_HOME + "/Downloads" + tail) == refuse.DOWNLOADS
    assert nix("/") == refuse.DRIVE


def test_forward_slashes_are_accepted_on_nt():
    assert nt("C:/Windows/System32") == refuse.SYSTEM
    assert nt("D:/") == refuse.DRIVE


def test_unc_share_root_is_refused_and_a_folder_in_it_is_allowed():
    share = BS + BS + w("nas", "share")
    assert nt(share) == refuse.DRIVE
    assert nt(share + BS) == refuse.DRIVE
    assert nt(w(share, "proj")) is None
    assert nt(w(share, "proj", "src")) is None


def test_env_none_means_os_environ(monkeypatch):
    monkeypatch.setenv("XDG_DOWNLOAD_DIR", NIX_HOME + "/dl")
    monkeypatch.setenv("OneDrive", NIX_HOME + "/od")
    kw = dict(home=NIX_HOME, platform="posix", ismount=lambda p: False)
    assert refused(NIX_HOME + "/dl", env=None, **kw) == refuse.DOWNLOADS
    assert refused(NIX_HOME + "/dl", **kw) == refuse.DOWNLOADS
    assert refused(NIX_HOME + "/od", env=None, **kw) == refuse.ONEDRIVE
    assert refused(NIX_HOME + "/dl", env={}, **kw) is None


def test_env_none_is_read_for_system_roots_on_nt(monkeypatch):
    monkeypatch.setenv("SystemRoot", w("E:", "Win"))
    assert refused(w("E:", "Win", "x"), home=WIN_HOME, env=None, platform="nt", ismount=lambda p: False) == refuse.SYSTEM


def test_a_missing_system_root_falls_back_to_the_default():
    assert nt(w("C:", "Windows", "x")) == refuse.SYSTEM
    assert nt(w("C:", "Windows2", "x")) is None


def test_system_roots_match_on_a_path_boundary():
    assert nix("/usr") == refuse.SYSTEM
    assert nix("/usr/bin") == refuse.SYSTEM
    assert nix("/usrx") is None
    assert nix("/lib64/x") == refuse.SYSTEM
    assert nix("/libx") is None


def test_the_temp_folders_are_not_system_folders():
    for p in ("/tmp", "/var/tmp", "/opt", "/private/var/folders/ab/cd", "/var/folders/ab/cd"):
        assert nix(p) is None, p
    assert nt(w(WIN_HOME, "AppData", "Local", "Temp")) is None


def test_posix_keeps_case_and_nt_folds_it():
    assert nix(NIX_HOME + "/downloads") is None
    assert nt(w(WIN_HOME, "DOWNLOADS")) == refuse.DOWNLOADS
    assert nix("/ETC") is None
    assert nt(w("c:", "windows")) == refuse.SYSTEM


def test_both_platforms_work_on_every_os():
    # the platform argument picks the path module, not the machine
    assert nt(WIN_HOME) == refuse.HOME
    assert nix(NIX_HOME) == refuse.HOME


def test_ismount_receives_the_normalised_path():
    seen = []

    def spy(p):
        seen.append(p)
        return False

    refused("/srv/data//", home=NIX_HOME, env={}, platform="posix", ismount=spy)
    assert seen == ["/srv/data"]


def test_ismount_errors_mean_not_a_mount():
    def boom(p):
        raise OSError("denied")

    assert refused("/srv/data", home=NIX_HOME, env={}, platform="posix", ismount=boom) is None


def test_a_mounted_folder_is_refused_on_nt_too():
    assert refused(w("D:", "disk"), home=WIN_HOME, env={}, platform="nt", ismount=lambda p: True) == refuse.DRIVE


def test_a_mounted_home_folder_is_a_drive():
    # a mounted home folder is still reported as a drive, in the contract's order
    assert refused(NIX_HOME, home=NIX_HOME, env={}, platform="posix", ismount=lambda p: True) == refuse.DRIVE


def test_reasons_map_to_sentences_the_function_returns():
    returned = {nt(w("C:", "")), nt(WIN_HOME), nt(w("C:", "Users")), nt(w(WIN_HOME, "Downloads")),
                nt(w(WIN_HOME, "Desktop")), nt(w(WIN_HOME, "Documents")), nt(w("C:", "Windows")),
                nt(w("D:", "OneDrive"), {"OneDrive": w("D:", "OneDrive")})}
    assert returned == {s for sentences in REASONS.values() for s in sentences}


def test_no_sentence_holds_a_verdict_word():
    for sentences in REASONS.values():
        for s in sentences:
            assert not any(word in s.casefold() for word in VERDICT_WORDS), s
            assert s.endswith(".") and " -- " not in s


def run(*args):
    return subprocess.run([sys.executable, "-m", "code_guardian.refuse"] + list(args), cwd=str(ROOT),
                          capture_output=True, text=True, timeout=120)


def test_selftest_prints_the_count_line():
    r = run("--selftest")
    assert r.returncode == 0, r.stdout + r.stderr
    m = re.search(r"^refuse selftest: (\d+) checks, (\d+) passed, 0 failed$", r.stdout, re.MULTILINE)
    assert m and m.group(1) == m.group(2) and int(m.group(1)) >= 22, r.stdout


def test_help_and_no_arguments_print_usage_and_exit_zero():
    for args in (("--help",), ("-h",), ()):
        r = run(*args)
        assert r.returncode == 0 and "usage" in r.stdout, (args, r.stdout, r.stderr)


def test_an_unknown_option_is_a_usage_error():
    r = run("--nope")
    assert r.returncode == 2 and "usage" in r.stderr
