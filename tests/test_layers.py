"""P141 S13: declared layer rules and file-size limits in the goal contract.

The goal file is written in tmp_path over a COPY of the complete_app fixture; the fixture itself is never changed
(its golden is frozen)."""
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from code_guardian import catalogue, goal, layers, report, score  # noqa: E402

GOAL = '''goal = "EXAMPLE-ONLY web service"
entry_points = ["svc.web:app"]

[[layers]]
path = "svc/*"
forbidden_imports = ["flask"]

[size_limits]
"svc/web.py" = 5
'''


def app(tmp_path, goal_text):
    dest = tmp_path / "complete_app"
    shutil.copytree(HERE / "fixtures" / "complete_app", dest)
    if goal_text is not None:
        (dest / goal.FILENAME).write_text(goal_text, encoding="utf-8")
    return dest


def load(tmp_path, text):
    path = tmp_path / goal.FILENAME
    path.write_text(text, encoding="utf-8")
    return goal.load(str(path))


def test_load_accepts_both_keys(tmp_path):
    g = load(tmp_path, GOAL)
    assert g["layers"] == [{"path": "svc/*", "forbidden_imports": ["flask"]}]
    assert g["size_limits"] == {"svc/web.py": 5}
    assert g["unknown_keys"] == []


def test_absent_keys_default_empty(tmp_path):
    g = load(tmp_path, 'goal = "x"\n')
    assert g["layers"] == [] and g["size_limits"] == {}


@pytest.mark.parametrize("text,named", [
    ('layers = "svc"\n', "layers"),
    ('[[layers]]\nforbidden_imports = ["a"]\n', "layers"),
    ('[[layers]]\npath = "a"\nforbidden_imports = "flask"\n', "forbidden_imports"),
    ('[[layers]]\npath = "a"\nforbidden_imports = [1]\n', "forbidden_imports"),
    ('[size_limits]\n"a.py" = "big"\n', "size_limits"),
    ('[size_limits]\n"a.py" = 0\n', "size_limits"),
    ('[size_limits]\n"a.py" = -3\n', "size_limits"),
    ('[size_limits]\n"a.py" = true\n', "size_limits"),
    ('size_limits = 5\n', "size_limits"),
])
def test_bad_shape_names_the_key(tmp_path, text, named):
    with pytest.raises(goal.GoalError) as exc:
        load(tmp_path, text)
    assert named in str(exc.value)


def test_render_round_trips(tmp_path):
    text = goal.render("x", ["a:b"], layers=[{"path": "svc/*", "forbidden_imports": ["flask", "requests"]}],
                       size_limits={"svc/web.py": 5, 'we"ird*.py': 9})
    g = load(tmp_path, text)
    assert g["layers"] == [{"path": "svc/*", "forbidden_imports": ["flask", "requests"]}]
    assert g["size_limits"] == {"svc/web.py": 5, 'we"ird*.py': 9}


def test_render_without_declarations_is_unchanged():
    assert goal.render("x", ["a:b"]) == goal.render("x", ["a:b"], layers=(), size_limits=None)
    assert "layers" not in goal.render("x", ["a:b"]) and "size_limits" not in goal.render("x", ["a:b"])


def test_scan_reports_the_planted_violations(tmp_path):
    found = report.scan(str(app(tmp_path, GOAL)))["findings"]
    imp = [f for f in found if f["code"] == "works.layer_import"]
    big = [f for f in found if f["code"] == "works.file_too_long"]
    assert [(f["node"], f["level"]) for f in imp] == [("svc/web.py:4", "WARN")]
    assert [(f["node"], f["level"]) for f in big] == [("svc/web.py", "WARN")]


def test_scan_without_declarations_reports_nothing(tmp_path):
    plain = 'goal = "EXAMPLE-ONLY web service"\nentry_points = ["svc.web:app"]\n'
    for text in (plain, None):
        found = report.scan(str(app(tmp_path / ("a" if text else "b"), text)))["findings"]
        assert not [f for f in found if f["code"] in ("works.layer_import", "works.file_too_long")]


def test_prefix_is_not_a_substring():
    g = {"layers": [{"path": "*", "forbidden_imports": ["flask"]}]}
    got = layers.violations(g, {"a.py": 1}, {"a.py": [("flasky", 1), ("flask", 2), ("flask.x", 3), ("x.flask", 4)]})
    assert [f["node"] for f in got] == ["a.py:2", "a.py:3"]


def test_file_at_the_limit_is_fine():
    assert not layers.violations({"size_limits": {"a.py": 5}}, {"a.py": 5}, {})
    assert len(layers.violations({"size_limits": {"a.py": 5}}, {"a.py": 6}, {})) == 1


def test_weights_and_catalogue():
    for code in ("works.layer_import", "works.file_too_long"):
        assert score.TABLES["works"][(code, "WARN")] == 5
        assert catalogue.CATALOGUE[code]["fix"]


def test_selftests_pass():
    for mod in ("code_guardian.layers", "code_guardian.goal"):
        r = subprocess.run([sys.executable, "-m", mod, "--selftest"], cwd=str(HERE.parent), capture_output=True,
                           text=True, timeout=120)
        assert r.returncode == 0 and " 0 failed" in r.stdout, (mod, r.stdout)
