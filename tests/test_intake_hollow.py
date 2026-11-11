"""Repo intake, item 6: hollow-project heuristic (a big README, almost no source, the weight in releases / binaries)."""
from code_guardian import intake
from intake_helpers import mk, of
from test_intake_binary import pe

README_BIG = "# Great Tool\n\n" + "This amazing tool does everything you need, fast and free.\n" * 120


def scan(tmp_path, files):
    return intake.scan(mk(tmp_path / "repo", files))


def test_big_readme_tiny_source_with_binaries_is_medium(tmp_path):
    res = scan(tmp_path, {"README.md": README_BIG + "[Releases](https://example.com/org/tool/releases)\n", "main.py": "print(1)\n",
                          "release/Tool.exe": pe(), "release/data.zip": b"PK\x03\x04" + b"\0" * 100})
    (f,) = of(res, "hollow.readme_heavy")
    assert f["confidence"] == "medium" and f["file"] == "README.md"
    assert "README" in f["match"] and "source" in f["match"] and "binaries/archives" in f["match"]


def test_big_readme_and_no_source_alone_is_low(tmp_path):
    res = scan(tmp_path, {"README.md": README_BIG})
    (f,) = of(res, "hollow.readme_heavy")
    assert f["confidence"] == "low"


def test_a_real_project_is_not_hollow(tmp_path):
    files = {"README.md": README_BIG}
    for i in range(12):
        files["src/m%d.py" % i] = "def f%d():\n    return %d\n" % (i, i) * 120
    assert of(scan(tmp_path, files), "hollow.readme_heavy") == []


def test_a_short_readme_is_not_judged(tmp_path):
    assert of(scan(tmp_path, {"README.md": "# x\n", "a.exe": pe()}), "hollow.readme_heavy") == []
