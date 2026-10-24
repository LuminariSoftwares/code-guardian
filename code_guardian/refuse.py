"""The folders the app will not check as a whole, each with one plain sentence (plan P78 C5).

Pure and standalone: standard library only, no network, no files written. Nothing calls this yet; the Browse button,
the typed path and `code-guardian ui PATH` apply it in a later section.

Public contract:
    refused(path, *, home=None, env=None, platform=None, ismount=None) -> str | None
        a plain sentence when the folder is one to refuse, None when it is allowed. A path that is an existing file is
        never refused (a single file is copied into a temp folder by the caller); a path that does not exist is judged
        as a folder.
    REASONS -> {"drive", "home", "above_home", "catchall", "system"}, each mapped to the sentences it can return

Defaults: platform is os.name ("nt" or "posix"), home is os.path.expanduser("~"), env is os.environ and ismount is
os.path.ismount. Paths are normalised with ntpath or posixpath by the platform argument, never by os.path, so a
Windows path is judged the same way on Linux and a POSIX path the same way on Windows. On "nt" everything is compared
case-folded with forward slashes; on "posix" case is kept.

Not refused on purpose: /var, /tmp, /opt, /private/var, %TEMP% and AppData. Temp folders live there on macOS and
Windows, and a project may live in /opt.

CLI:
    python -m code_guardian.refuse --selftest   # counted checks; rc 0 only if all pass
    python -m code_guardian.refuse --help
"""

import ntpath
import os
import posixpath
import re
import sys

DRIVE = "That is a whole drive. Pick the folder your project is in."
HOME = "That is your home folder, which holds everything you own. Pick the project folder inside it."
ABOVE_HOME = "That folder contains your home folder and more. Pick the project folder instead."
DOWNLOADS = ("Downloads holds everything you ever downloaded. Move the project into its own folder, or pick that "
             "folder inside Downloads.")
DESKTOP = "Your Desktop holds everything on it. Pick the project folder on the Desktop, not the Desktop itself."
DOCUMENTS = "Documents holds all of your documents. Pick the project folder inside it."
ONEDRIVE = "That is your whole OneDrive. Pick the project folder inside it."
SYSTEM = "That is part of the operating system, not a project. Pick the folder your project is in."

# the key is what the tests and callers match on; the value is every sentence that reason can return
REASONS = {
    "drive": (DRIVE,),
    "home": (HOME,),
    "above_home": (ABOVE_HOME,),
    "catchall": (DOWNLOADS, DESKTOP, DOCUMENTS, ONEDRIVE),
    "system": (SYSTEM,),
}

_NT_DRIVE = re.compile(r"^[a-z]:/?$")
_NT_UNC_SHARE = re.compile(r"^//[^/]+/[^/]+/?$")
_POSIX_SYSTEM = ("/bin", "/sbin", "/usr", "/etc", "/boot", "/dev", "/proc", "/sys", "/lib", "/lib32", "/lib64",
                 "/System", "/Library", "/Applications", "/private/etc")
_NT_SYSTEM_VARS = ("ProgramFiles", "ProgramFiles(x86)", "ProgramData", "windir")
_NT_SYSTEM_ROOT_DEFAULT = "C:/Windows"


def _normalise(path, mod, nt):
    """Absolute, no trailing separator (except a bare root); on nt also forward slashes and case-folded."""
    p = mod.abspath(path)
    if nt:
        p = p.replace(chr(92), "/").casefold()
    if len(p) > 1 and p.endswith("/") and not (nt and _NT_DRIVE.match(p)):
        p = p.rstrip("/") or "/"
    return p


def _inside(p, root):
    return p == root or p.startswith(root.rstrip("/") + "/")


def _is_mount(ismount, p):
    try:
        return bool(ismount(p))
    except (OSError, ValueError):
        return False


def refused(path, *, home=None, env=None, platform=None, ismount=None):
    """The sentence to show for a folder the app will not check whole, or None when the folder is allowed."""
    path = os.fspath(path)
    if os.path.isfile(path):
        return None
    nt = (os.name if platform is None else platform) == "nt"
    mod = ntpath if nt else posixpath
    env = os.environ if env is None else env
    home = os.path.expanduser("~") if home is None else home
    ismount = os.path.ismount if ismount is None else ismount

    def norm(p):
        return _normalise(p, mod, nt)

    p = norm(path)

    if (nt and (_NT_DRIVE.match(p) or _NT_UNC_SHARE.match(p))) or (not nt and p == "/") or _is_mount(ismount, p):
        return DRIVE

    h = norm(home) if home else None
    if h:
        if p == h:
            return HOME
        if h.startswith(p.rstrip("/") + "/"):
            return ABOVE_HOME

    catchall = []
    if h:
        for name, sentence in (("Downloads", DOWNLOADS), ("Desktop", DESKTOP), ("Documents", DOCUMENTS)):
            catchall.append((h + "/" + (name.casefold() if nt else name), sentence))
    for var, sentence in (("XDG_DOWNLOAD_DIR", DOWNLOADS), ("OneDrive", ONEDRIVE)):
        if env.get(var):
            catchall.append((norm(env[var]), sentence))
    for folder, sentence in catchall:
        if p == folder:
            return sentence

    if nt:
        roots = [norm(env.get("SystemRoot") or _NT_SYSTEM_ROOT_DEFAULT)]
        roots += [norm(env[v]) for v in _NT_SYSTEM_VARS if env.get(v)]
    else:
        roots = list(_POSIX_SYSTEM)
    if any(_inside(p, r) for r in roots):
        return SYSTEM
    return None


def _usage():
    return ("usage: python -m code_guardian.refuse --selftest\n"
            "       python -m code_guardian.refuse --help\n"
            "\n"
            "refuse.py is the list of folders the app will not check as a whole: a drive, your home folder,\n"
            "the folders above it, Downloads, Desktop, Documents, the OneDrive root and system folders.\n"
            "It is a module; the app calls refused(path), which returns a plain sentence or None.")


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    if not argv or argv[0] in ("-h", "--help"):
        print(_usage())
        return 0
    if argv == ["--selftest"]:
        return _selftest()
    print(_usage(), file=sys.stderr)
    return 2


def _selftest():
    bs = chr(92)

    def w(*parts):
        return bs.join(parts)

    win_home = w("C:", "Users", "alex")
    nix_home = "/home/alex"
    mounts = {"/Volumes/Backup", "/media/alex/USB", "/mnt/c"}

    def nt(path, env=None):
        return refused(path, home=win_home, env=env or {}, platform="nt", ismount=lambda p: False)

    def nix(path, env=None, home=nix_home):
        return refused(path, home=home, env=env or {}, platform="posix", ismount=lambda p: p.rstrip("/") in mounts)

    onedrive = w("D:", "OneDrive")
    # split so this file does not hold the very words it checks the sentences against
    verdict_words = [x.replace("-", "") for x in ("sa-fe", "se-cure", "cl-ean", "harm-less", "guarant-eed", "no ri-sks")]
    here = os.path.abspath(__file__)
    native = "nt" if os.name == "nt" else "posix"
    checks = [
        # drive
        ("nt_c_root", nt(w("C:", "")) == DRIVE),
        ("nt_d_root", nt(w("D:", "")) == DRIVE),
        ("nt_f_root", nt(w("F:", "")) == DRIVE),
        ("nt_mapped_z_root", nt(w("Z:", "")) == DRIVE),
        ("nt_unc_share_root", nt(bs + bs + w("nas", "share")) == DRIVE),
        ("nt_unc_share_root_trailing", nt(bs + bs + w("nas", "share", "")) == DRIVE),
        ("nt_unc_deeper_allowed", nt(bs + bs + w("nas", "share", "proj")) is None),
        ("posix_root", nix("/") == DRIVE),
        ("posix_mac_disk", nix("/Volumes/Backup") == DRIVE),
        ("posix_media_disk", nix("/media/alex/USB") == DRIVE),
        ("posix_wsl_drive", nix("/mnt/c") == DRIVE),
        ("posix_wsl_folder_allowed", nix("/mnt/c/Users/alex/proj") is None),
        # home and above it
        ("nt_home", nt(win_home) == HOME),
        ("nt_home_trailing", nt(win_home + bs) == HOME),
        ("nt_home_case", nt(w("c:", "users", "ALEX")) == HOME),
        ("nt_above_home", nt(w("C:", "Users")) == ABOVE_HOME),
        ("posix_home", nix(nix_home) == HOME),
        ("posix_home_trailing", nix(nix_home + "/") == HOME),
        ("posix_above_home", nix("/home") == ABOVE_HOME),
        ("posix_mac_home", nix("/Users/alex", home="/Users/alex") == HOME),
        ("posix_mac_above_home", nix("/Users", home="/Users/alex") == ABOVE_HOME),
        # catch-all folders: the folder itself is refused, a subfolder is allowed
        ("nt_downloads", nt(w(win_home, "Downloads")) == DOWNLOADS),
        ("nt_desktop", nt(w(win_home, "Desktop")) == DESKTOP),
        ("nt_documents", nt(w(win_home, "Documents")) == DOCUMENTS),
        ("nt_onedrive", nt(onedrive, {"OneDrive": onedrive}) == ONEDRIVE),
        ("nt_onedrive_unset_allowed", nt(onedrive) is None),
        ("nt_downloads_subfolder_allowed", nt(w(win_home, "Downloads", "my-app")) is None),
        ("nt_documents_subfolder_allowed", nt(w(win_home, "Documents", "school", "proj")) is None),
        ("posix_downloads", nix(nix_home + "/Downloads") == DOWNLOADS),
        ("posix_xdg_downloads", nix(nix_home + "/dl", {"XDG_DOWNLOAD_DIR": nix_home + "/dl"}) == DOWNLOADS),
        ("posix_desktop", nix(nix_home + "/Desktop") == DESKTOP),
        ("posix_documents", nix(nix_home + "/Documents") == DOCUMENTS),
        ("posix_downloads_subfolder_allowed", nix(nix_home + "/Downloads/my-app") is None),
        # system folders, matched on a path boundary
        ("nt_windows_system32", nt(w("C:", "Windows", "System32")) == SYSTEM),
        ("nt_windows_case", nt(w("c:", "WINDOWS")) == SYSTEM),
        ("nt_systemroot_env", nt(w("E:", "Win", "System32"), {"SystemRoot": w("E:", "Win")}) == SYSTEM),
        ("nt_program_files_env", nt(w("C:", "Program Files", "App"), {"ProgramFiles": w("C:", "Program Files")}) == SYSTEM),
        ("nt_windows2_allowed", nt(w("C:", "Windows2", "x")) is None),
        ("posix_usr_local_lib", nix("/usr/local/lib") == SYSTEM),
        ("posix_etc", nix("/etc") == SYSTEM),
        ("posix_usrlocal_allowed", nix("/usrlocal/x") is None),
        # allowed
        ("posix_project", nix(nix_home + "/projects/x") is None),
        ("posix_opt", nix("/opt/x") is None),
        ("posix_tmp", nix("/tmp/x") is None),
        ("posix_mac_temp", nix("/private/var/folders/ab/x") is None),
        ("nt_appdata_temp", nt(w(win_home, "AppData", "Local", "Temp", "x")) is None),
        # a file is never refused; a path that does not exist is judged as a folder
        ("file_is_none", refused(here, home=os.path.dirname(here), env={}, platform=native, ismount=lambda p: False) is None),
        ("missing_is_a_folder", nix("/no-such-folder-here/x") is None and nix("/no-such-folder-here") is None),
        # ismount decides a mounted folder
        ("ismount_decides", refused("/srv/data", home=nix_home, env={}, platform="posix", ismount=lambda p: True) == DRIVE),
        ("env_none_is_os_environ", refused(nix_home + "/x", home=nix_home, env=None, platform="posix",
                                           ismount=lambda p: False) is None),
        # reasons
        ("reasons_keys", set(REASONS) == {"drive", "home", "above_home", "catchall", "system"}),
        ("sentences_have_no_verdict", not any(word in sentence.casefold() for word in verdict_words
                                              for sentences in REASONS.values() for sentence in sentences)),
    ]
    passed = sum(1 for _, ok in checks if ok)
    for name, ok in checks:
        if not ok:
            print("FAIL %s" % name)
    print("refuse selftest: %d checks, %d passed, %d failed" % (len(checks), passed, len(checks) - passed))
    return 0 if passed == len(checks) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
