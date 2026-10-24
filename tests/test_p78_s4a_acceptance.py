"""P78 S4a acceptance -- the refusal list, code_guardian/refuse.py (plan P78 C5).

Written by the overseer BEFORE the build session. The build session must add this file to the PR byte-for-byte and
must not edit it; a PR that changes it fails the section. This file is pure ASCII on purpose.

Every example runs for both platforms on every CI OS: the module is handed platform="nt" or "posix", home=, env= and
ismount= so nothing here depends on the machine it runs on -- except test_real_tmp_path_is_allowed, which uses every
default (the real os.path.ismount, the real home, the real environment) on purpose.
"""
import ast
import importlib
import re
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SRC = ROOT / "code_guardian" / "refuse.py"

VERDICT = re.compile(
    r"is safe|safe to run|\bsecure\b|\bclean\b|no risks|risk-free|\bharmless\b|\bguaranteed\b", re.IGNORECASE)

DRIVE = "That is a whole drive. Pick the folder your project is in."
HOME = "That is your home folder, which holds everything you own. Pick the project folder inside it."
ABOVE = "That folder contains your home folder and more. Pick the project folder instead."
DOWNLOADS = ("Downloads holds everything you ever downloaded. Move the project into its own folder, or pick that "
             "folder inside Downloads.")
DESKTOP = "Your Desktop holds everything on it. Pick the project folder on the Desktop, not the Desktop itself."
DOCUMENTS = "Documents holds all of your documents. Pick the project folder inside it."
ONEDRIVE = "That is your whole OneDrive. Pick the project folder inside it."
SYSTEM = "That is part of the operating system, not a project. Pick the folder your project is in."

BS = chr(92)  # a backslash, built so no escape sequence has to survive being retyped
WIN_HOME = "C:" + BS + "Users" + BS + "alex"
NIX_HOME = "/home/alex"
MOUNTS = {"/Volumes/Backup", "/media/alex/USB", "/mnt/c"}


def w(*parts):
    """A Windows path from parts: w("C:", "Users") == C:<backslash>Users."""
    return BS.join(parts)


def _fake_mount(p):
    return p.rstrip("/") in MOUNTS


def _no_mount(p):
    return False


def _mod():
    # imported per test, so on main every test fails with "No module named 'code_guardian.refuse'"
    return importlib.import_module("code_guardian.refuse")


def _nt(path, env=None, home=WIN_HOME):
    return _mod().refused(path, home=home, env={} if env is None else env, platform="nt", ismount=_no_mount)


def _nix(path, env=None, home=NIX_HOME):
    return _mod().refused(path, home=home, env={} if env is None else env, platform="posix", ismount=_fake_mount)


# ---- refused, with the exact sentence -------------------------------------------------------------------------------

NT_REFUSED = [
    (w("C:", ""), {}, DRIVE),
    (w("D:", ""), {}, DRIVE),
    (w("F:", ""), {}, DRIVE),
    (w("Z:", ""), {}, DRIVE),
    (BS + BS + w("nas", "share"), {}, DRIVE),
    (BS + BS + w("nas", "share", ""), {}, DRIVE),
    (WIN_HOME, {}, HOME),
    (WIN_HOME + BS, {}, HOME),
    (w("c:", "users", "ALEX"), {}, HOME),
    (w("C:", "Users"), {}, ABOVE),
    (w(WIN_HOME, "Downloads"), {}, DOWNLOADS),
    (w(WIN_HOME, "Downloads", ""), {}, DOWNLOADS),
    (w(WIN_HOME, "Desktop"), {}, DESKTOP),
    (w(WIN_HOME, "Documents"), {}, DOCUMENTS),
    (w("D:", "OneDrive"), {"OneDrive": w("D:", "OneDrive")}, ONEDRIVE),
    (w("C:", "Windows"), {}, SYSTEM),
    (w("C:", "Windows", "System32"), {}, SYSTEM),
    (w("c:", "WINDOWS"), {}, SYSTEM),
    (w("E:", "Win", "System32"), {"SystemRoot": w("E:", "Win")}, SYSTEM),
    (w("C:", "Program Files", "App"), {"ProgramFiles": w("C:", "Program Files")}, SYSTEM),
    (w("C:", "Program Files (x86)"), {"ProgramFiles(x86)": w("C:", "Program Files (x86)")}, SYSTEM),
    (w("C:", "ProgramData", "x"), {"ProgramData": w("C:", "ProgramData")}, SYSTEM),
]

NIX_REFUSED = [
    ("/", {}, DRIVE),
    ("/Volumes/Backup", {}, DRIVE),
    ("/Volumes/Backup/", {}, DRIVE),
    ("/media/alex/USB", {}, DRIVE),
    ("/mnt/c", {}, DRIVE),
    (NIX_HOME, {}, HOME),
    (NIX_HOME + "/", {}, HOME),
    ("/home", {}, ABOVE),
    (NIX_HOME + "/Downloads", {}, DOWNLOADS),
    (NIX_HOME + "/dl", {"XDG_DOWNLOAD_DIR": NIX_HOME + "/dl"}, DOWNLOADS),
    (NIX_HOME + "/Desktop", {}, DESKTOP),
    (NIX_HOME + "/Documents", {}, DOCUMENTS),
    ("/usr/local/lib", {}, SYSTEM),
    ("/etc", {}, SYSTEM),
    ("/bin", {}, SYSTEM),
    ("/System/Library", {}, SYSTEM),
    ("/Applications", {}, SYSTEM),
    ("/private/etc/hosts.d", {}, SYSTEM),
]


@pytest.mark.parametrize("path,env,want", NT_REFUSED, ids=[repr(c[0]) for c in NT_REFUSED])
def test_nt_refused(path, env, want):
    assert _nt(path, env) == want


@pytest.mark.parametrize("path,env,want", NIX_REFUSED, ids=[repr(c[0]) for c in NIX_REFUSED])
def test_posix_refused(path, env, want):
    assert _nix(path, env) == want


def test_mac_home_and_users_folder():
    assert _nix("/Users/alex", home="/Users/alex") == HOME
    assert _nix("/Users", home="/Users/alex") == ABOVE
    assert _nix("/Users/alex/Downloads", home="/Users/alex") == DOWNLOADS


# ---- allowed --------------------------------------------------------------------------------------------------------

NT_ALLOWED = [
    (w(WIN_HOME, "Downloads", "my-app"), {}),
    (w(WIN_HOME, "Documents", "school", "proj"), {}),
    (w(WIN_HOME, "Desktop", "proj"), {}),
    (w(WIN_HOME, "AppData", "Local", "Temp", "x"), {}),
    (w(WIN_HOME, "projects", "x"), {}),
    (w("D:", "OneDrive", "proj"), {"OneDrive": w("D:", "OneDrive")}),
    (w("D:", "OneDrive"), {}),
    (w("D:", "code", "proj"), {}),
    (w("C:", "Windows2", "x"), {}),
]

NIX_ALLOWED = [
    (NIX_HOME + "/projects/x", {}),
    ("/opt/x", {}),
    ("/tmp/x", {}),
    ("/var/x", {}),
    ("/private/var/folders/ab/x", {}),
    ("/mnt/c/Users/alex/proj", {}),
    ("/Volumes/Backup/code/app", {}),
    (NIX_HOME + "/Downloads/my-app", {}),
    (NIX_HOME + "/Documents/school/proj", {}),
    (NIX_HOME + "/dl/app", {"XDG_DOWNLOAD_DIR": NIX_HOME + "/dl"}),
    ("/usrlocal/x", {}),
    (NIX_HOME + "/Library/proj", {}),
]


@pytest.mark.parametrize("path,env", NT_ALLOWED, ids=[repr(c[0]) for c in NT_ALLOWED])
def test_nt_allowed(path, env):
    assert _nt(path, env) is None


@pytest.mark.parametrize("path,env", NIX_ALLOWED, ids=[repr(c[0]) for c in NIX_ALLOWED])
def test_posix_allowed(path, env):
    assert _nix(path, env) is None


# ---- the machine this runs on ---------------------------------------------------------------------------------------

def test_real_tmp_path_is_allowed(tmp_path):
    assert _mod().refused(str(tmp_path)) is None
    sub = tmp_path / "proj"
    sub.mkdir()
    assert _mod().refused(str(sub)) is None


def test_a_file_is_never_refused(tmp_path):
    native = "nt" if sys.platform == "win32" else "posix"
    kw = dict(home=str(tmp_path), env={}, platform=native, ismount=_no_mount)
    folder = tmp_path / "Downloads"
    folder.mkdir()
    assert _mod().refused(str(folder), **kw) == DOWNLOADS
    single = tmp_path / "Desktop"
    single.write_text("x = 1\n", encoding="utf-8")
    assert _mod().refused(str(single), **kw) is None


def test_ismount_is_what_decides_a_mounted_folder():
    calls = []

    def spy(p):
        calls.append(p)
        return True

    assert _mod().refused("/srv/data", home=NIX_HOME, env={}, platform="posix", ismount=spy) == DRIVE
    assert calls, "refused() did not ask ismount"
    assert _mod().refused("/srv/data", home=NIX_HOME, env={}, platform="posix", ismount=_no_mount) is None


# ---- the module itself ----------------------------------------------------------------------------------------------

def test_reasons_keys():
    assert set(_mod().REASONS) == {"drive", "home", "above_home", "catchall", "system"}


def test_no_sentence_is_a_verdict():
    for s in (DRIVE, HOME, ABOVE, DOWNLOADS, DESKTOP, DOCUMENTS, ONEDRIVE, SYSTEM):
        assert not VERDICT.search(s) and " -- " not in s, s
    src = SRC.read_text(encoding="utf-8")
    for lit in re.findall(r'"([^"\n]{20,})"', src):
        assert not VERDICT.search(lit), lit


def test_imports_only_the_stdlib_path_modules():
    tree = ast.parse(SRC.read_text(encoding="utf-8"))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.add((node.module or "").split(".")[0])
    assert names <= {"os", "sys", "re", "posixpath", "ntpath", "__future__"}, names


def _run(*args):
    return subprocess.run([sys.executable, "-m", "code_guardian.refuse"] + list(args), cwd=str(ROOT),
                          capture_output=True, text=True, timeout=120)


def test_selftest_count():
    r = _run("--selftest")
    assert r.returncode == 0, r.stdout + r.stderr
    m = re.search(r"(\d+) checks, (\d+) passed", r.stdout)
    assert m and m.group(1) == m.group(2) and int(m.group(1)) >= 22, r.stdout[-400:]


def test_help_exits_zero():
    r = _run("--help")
    assert r.returncode == 0, r.stdout + r.stderr
    assert r.stdout.strip(), "--help printed nothing"
