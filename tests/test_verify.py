"""The verify loop: diff two reports by fingerprint (what did the change fix, what did it break) and the repair plan
(what should be fixed next, with the exact Overall points each check row is worth)."""
import json
import shutil
import subprocess
import sys

import pytest

import make_risky
from conftest import FIXTURES

from code_guardian import mcp_server, report, score, verify


def cli(*args):
    return subprocess.run([sys.executable, "-m", "code_guardian", *map(str, args)], capture_output=True, text=True,
                          timeout=120)


def fake(fp, code="exec.shell", level="WARN", node="a.py:1"):
    return {"code": code, "level": level, "node": node, "summary": "s", "fingerprint": fp}


def rep(findings, safe=100, works=100, complete=100, overall=100, grade="A", status="COMPLETE"):
    return {"tool": "code-guardian", "version": "0.3.0", "schema_version": 2, "status": status, "findings": findings,
            "hygiene": {"findings": []}, "scores": {"safe": safe, "works": works, "complete": complete,
                                                    "overall": overall, "grade": grade}}


def test_synthetic_pair_gives_exact_fixed_new_unchanged_sets():
    a, b, c, d = ("%064x" % i for i in range(1, 5))
    before = rep([fake(a), fake(b), fake(b, node="a.py:9"), fake(c, level="INFO")], safe=80, overall=90)
    after = rep([fake(b, node="a.py:30"), fake(c, level="INFO"), fake(d, code="tls.off", level="FAIL")], safe=75,
                overall=88, grade="B")
    d_ = verify.diff(before, after)
    assert sorted(f["fingerprint"] for f in d_["fixed"]) == [a, b]
    assert [f["fingerprint"] for f in d_["new"]] == [d]
    assert sorted(f["fingerprint"] for f in d_["unchanged"]) == [b, c]
    assert d_["scores"]["safe"] == {"before": 80, "after": 75, "delta": -5}
    assert d_["scores"]["overall"] == {"before": 90, "after": 88, "delta": -2}
    assert d_["grade"] == {"before": "A", "after": "B"}
    assert d_["verdict"] == "mixed" and verify.diff_exit(d_) == 1


def test_verdicts():
    a, b = "%064x" % 1, "%064x" % 2
    assert verify.diff(rep([fake(a)]), rep([fake(a)]))["verdict"] == "unchanged"
    assert verify.diff(rep([fake(a), fake(b)]), rep([fake(a)]))["verdict"] == "improved"
    assert verify.diff(rep([fake(a)]), rep([fake(a), fake(b)]))["verdict"] == "regressed"
    # a new INFO finding is inventory, not a regression
    assert verify.diff(rep([]), rep([fake(b, level="INFO")]))["verdict"] == "unchanged"
    # a scan that became PARTIAL is a regression
    assert verify.diff(rep([]), rep([], status="PARTIAL"))["verdict"] == "regressed"
    assert verify.diff_exit(verify.diff(rep([fake(a)]), rep([])) ) == 0


def test_reports_without_fingerprints_are_refused():
    old = rep([{"code": "x", "level": "WARN", "node": "a.py:1", "summary": "s"}])
    with pytest.raises(ValueError, match="fingerprint"):
        verify.diff(old, rep([]))


@pytest.fixture
def risky(tmp_path):
    return make_risky.build(tmp_path / "risky_repo")


def test_cli_diff_on_real_scans(risky, tmp_path):
    before = tmp_path / "before.json"
    before.write_text(cli("scan", risky, "--json").stdout, encoding="utf-8")
    (risky / "risky" / "runner.py").write_text("import subprocess\n\n\ndef run_user_command():\n"
                                               "    subprocess.run(['ls'])\n", encoding="utf-8")
    after = tmp_path / "after.json"
    after.write_text(cli("scan", risky, "--json").stdout, encoding="utf-8")
    r = cli("diff", before, after)
    assert r.returncode == 0, r.stdout + r.stderr
    assert r.stdout.splitlines()[0].startswith("verdict: improved (")
    body = json.loads(cli("diff", before, after, "--json").stdout)
    assert {f["code"] for f in body["fixed"]} >= {"exec.shell"} and body["new"] == []
    assert cli("diff", after, before).returncode == 1  # the reverse change regressed
    assert cli("diff", before, tmp_path / "missing.json").returncode == 2


def test_plan_gains_are_exact_rescorings(risky):
    rp = report.scan(str(risky))
    plan = verify.plan(rp, top=50)
    assert plan["label"] == "estimated gain if fixed"
    scored = report.scored_findings(rp)
    for item in plan["items"]:
        rest = [f for f in scored if (f["code"], f["level"]) != (item["code"], item["level"])]
        dims = {n: score.dimension(rest, n) for n in score.DIMENSIONS}
        after = score.scores([f for f in rest if f in rp["findings"]], dims, rp["status"])["overall"]
        assert item["gain"] == after - rp["scores"]["overall"], item
    gains = [i["gain"] for i in plan["items"]]
    assert gains == sorted(gains, reverse=True)
    ties = [i for i in plan["items"] if i["gain"] == gains[0]]
    assert plan["items"][0]["count"] == min(i["count"] for i in ties)  # ties: fewest locations first


def test_plan_says_when_a_dimension_is_floored(risky):
    plan = verify.plan(report.scan(str(risky)))
    assert any("Safe is at 0/100" in n for n in plan["notes"])
    assert all(i["gain"] == 0 for i in verify.plan(report.scan(str(risky)), top=50)["items"] if i["dimension"] == "safe")


def test_plan_top_item_is_the_largest_deduction_when_nothing_is_floored(tmp_path):
    shutil.copytree(FIXTURES / "clean_repo", tmp_path / "r")
    root = tmp_path / "r"
    (root / "cleanpkg" / "net.py").write_text(
        "import requests, os\n\ndef get(u):\n    os.system('ls')\n    return requests.get(u, verify=False)\n",
        encoding="utf-8")
    rp = report.scan(str(root))
    plan = verify.plan(rp)
    assert (plan["items"][0]["code"], plan["items"][0]["level"]) == (rp["top"][0]["code"], rp["top"][0]["level"])


FIXES = {
    "complete.license_missing": lambda root: (root / "LICENSE").write_text("MIT License\n", encoding="utf-8"),
    "complete.readme_missing": lambda root: (root / "README.md").write_text("# risky\n", encoding="utf-8"),
    "complete.ci_missing": lambda root: ((root / ".github" / "workflows").mkdir(parents=True),
                                         (root / ".github" / "workflows" / "ci.yml").write_text("on: push\n")),
}


def test_applying_the_top_fix_raises_overall_by_exactly_the_prediction(risky):
    rp = report.scan(str(risky))
    item = verify.plan(rp)["items"][0]
    assert item["code"] in FIXES, item
    FIXES[item["code"]](risky)
    again = report.scan(str(risky))
    assert again["scores"]["overall"] - rp["scores"]["overall"] == item["gain"] > 0
    assert again["scores"]["overall"] == item["overall_after"]


def test_plan_outputs(risky):
    md = cli("plan", risky, "--top", "3")
    assert md.returncode == 0 and "estimated gain if fixed" in md.stdout and md.stdout.count("\n### ") == 3
    body = json.loads(cli("plan", risky, "--json").stdout)
    assert len(body["items"]) == 10 and body["items"][0]["fix"] and body["items"][0]["locations"]


def test_mcp_diff_and_plan(risky, tmp_path):
    tools = mcp_server.default_tools()
    before = json.dumps(tools["scan"]({"path": str(risky)}))
    (risky / "LICENSE").write_text("MIT License\n", encoding="utf-8")
    after_path = tmp_path / "after.json"
    after_path.write_text(json.dumps(tools["scan"]({"path": str(risky)})), encoding="utf-8")
    d = tools["diff"]({"before": before, "after": str(after_path)})
    assert d["verdict"] == "improved" and [f["code"] for f in d["fixed"]] == ["complete.license_missing"]
    p = tools["plan"]({"path": str(risky), "top": 2})
    assert len(p["items"]) == 2
    names = {t["name"]: t for t in mcp_server.TOOL_SPECS}
    for name in ("diff", "plan"):
        ann = names[name]["annotations"]
        assert ann["readOnlyHint"] and not ann["destructiveHint"] and ann["idempotentHint"] and not ann["openWorldHint"]


def test_plan_and_diff_print_on_a_cp1252_console(risky, tmp_path):
    """Windows consoles default to cp1252: every character the plan and the diff print must encode there."""
    import os
    env = dict(os.environ, PYTHONIOENCODING="cp1252")
    r = subprocess.run([sys.executable, "-m", "code_guardian", "plan", str(risky)], capture_output=True, text=True,
                       timeout=120, env=env)
    assert r.returncode == 0, r.stderr[-500:]
    rep = tmp_path / "r.json"
    rep.write_text(cli("scan", risky, "--json").stdout, encoding="utf-8")
    r = subprocess.run([sys.executable, "-m", "code_guardian", "diff", str(rep), str(rep)], capture_output=True,
                       text=True, timeout=120, env=env)
    assert r.returncode == 0, r.stderr[-500:]


def _synthetic(rows):
    """A report from (code, level, count) Safe rows; Works and Complete stay at 100."""
    from code_guardian.finding import make_finding
    findings = [make_finding(code, "partial", level, "s.py:%d" % (10 * i + j + 1), "s")
                for i, (code, level, n) in enumerate(rows) for j in range(n)]
    dims = {n: score.dimension(findings, n) for n in score.DIMENSIONS}
    return {"path": "demo", "status": "COMPLETE", "findings": findings, "hygiene": {"findings": []},
            "dimensions": dims, "scores": score.scores(findings, dims, "COMPLETE")}


def test_floor_note_only_when_no_single_fix_moves_overall():
    # (a) the reproducer: Safe 0/100 with 130 deducted (30 over); secret.key x2 deducts 50 > 30, so fixing it moves
    # Safe to 20 and Overall by +10. The note would contradict that row, so it must not appear.
    a = _synthetic([("secret.key", "FAIL", 2), ("exec.shell", "FAIL", 1), ("tls.off", "FAIL", 1),
                    ("deser.unsafe", "WARN", 1), ("exec.dynamic", "WARN", 1), ("net.bind_all", "WARN", 1)])
    assert a["dimensions"]["safe"]["deducted"] == 130 and a["scores"]["safe"] == 0
    plan_a = verify.plan(a, top=50)
    assert not any("Safe is at 0/100" in n for n in plan_a["notes"]), plan_a["notes"]
    top = plan_a["items"][0]
    assert (top["code"], top["level"], top["gain"]) == ("secret.key", "FAIL", 10)
    # (b) every Safe row (largest 40) is smaller than the excess (205 - 100 = 105): the note appears, names 105,
    # and every Safe row shows +0
    b = _synthetic([("secret.key", "FAIL", 1), ("exec.dynamic", "FAIL", 1), ("exec.shell", "FAIL", 1),
                    ("obfuscation", "FAIL", 1), ("tls.off", "FAIL", 1), ("supply.unknown_package", "FAIL", 1)])
    assert b["dimensions"]["safe"]["deducted"] == 205
    plan_b = verify.plan(b, top=50)
    notes = [n for n in plan_b["notes"] if "Safe is at 0/100" in n]
    assert len(notes) == 1 and "105 points of Safe deductions must go first" in notes[0], plan_b["notes"]
    assert [i["gain"] for i in plan_b["items"] if i["dimension"] == "safe"] == [0] * 6
