"""P141 S11: shipped agent configs as Safe findings (code_guardian/agents.py).

The fixture under tests/fixtures/agent_risky is inert: every agent config is stored with a .fixture suffix and the
risky pieces are placeholders ({{IGNORE}}, {{PIPE}}, {{ZWSP}}, {{ANY}}) that these tests fill in, in a temporary
copy, under the files' real names. No committed file holds an injection phrase or a fetch piped into a shell."""
import ast
import json
import os
import shutil
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from code_guardian import agents, catalogue, report, score  # noqa: E402
from code_guardian.scanners import redact_report  # noqa: E402

FIXTURE = HERE / "fixtures" / "agent_risky"
FILL = {"{{IGNORE}}": "ignore " + "previous instructions", "{{PIPE}}": " | ", "{{ZWSP}}": chr(0x200B),
        "{{ANY}}": "*"}
PLACE = {"CLAUDE.md.fixture": "CLAUDE.md", "AGENTS.md.fixture": "AGENTS.md",
         "settings.json.fixture": ".claude/settings.json", "mcp.json.fixture": ".mcp.json"}
SCHEME = "https:" + "//"  # built, not written, so the self-scan sees no URL literal here
EXPECT = {"safe.agent_hook_runs_command": "WARN", "safe.agent_auto_approve": "FAIL", "safe.agent_pipe_to_shell": "FAIL",
          "safe.agent_mcp_unpinned": "WARN", "safe.agent_injection_text": "WARN", "safe.agent_hidden_unicode": "FAIL"}


def build(tmp_path, only=None):
    root = tmp_path / "repo"
    (root / "pkg").mkdir(parents=True)
    shutil.copy(FIXTURE / "pkg" / "__init__.py", root / "pkg" / "__init__.py")
    for stored, real in PLACE.items():
        if only is not None and stored not in only:
            continue
        text = (FIXTURE / stored).read_text(encoding="utf-8")
        for key, value in FILL.items():
            text = text.replace(key, value)
        (root / real).parent.mkdir(parents=True, exist_ok=True)
        (root / real).write_text(text, encoding="utf-8")
    return root


def scan(root):
    return json.loads(json.dumps(redact_report(report.scan(str(root)))))


def agent_findings(rep):
    return [f for f in rep["findings"] if f["code"].startswith("safe.agent_")]


def project(tmp_path, files):
    root = tmp_path / "p"
    (root / "pkg").mkdir(parents=True)
    (root / "pkg" / "__init__.py").write_text("X = 1\n", encoding="utf-8")
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text, encoding="utf-8")
    return root


def servers(*specs):
    return json.dumps({"mcpServers": {"s%d" % i: spec for i, spec in enumerate(specs)}})


def test_fixture_is_inert():
    names = {p.name for p in FIXTURE.rglob("*") if p.is_file()}
    assert names == set(PLACE) | {"__init__.py"}
    blob = "\n".join(p.read_text(encoding="utf-8") for p in FIXTURE.rglob("*") if p.is_file())
    assert "previous instructions" not in blob and not agents.PIPE_TO_SHELL.search(blob)
    assert not any(ord(c) in range(0x200B, 0x2010) for c in blob)
    assert SCHEME + "example.org" in blob and "EXAMPLE-ONLY" in blob


def test_all_six_codes_fire_at_their_levels(tmp_path):
    got = {(f["code"], f["level"]) for f in agent_findings(scan(build(tmp_path)))}
    assert got == set(EXPECT.items())


def test_counts_in_the_fixture(tmp_path):
    codes = [f["code"] for f in agent_findings(scan(build(tmp_path)))]
    assert codes.count("safe.agent_hook_runs_command") == 2
    assert codes.count("safe.agent_auto_approve") == 2  # the setting and the open allow entry
    assert codes.count("safe.agent_pipe_to_shell") == 2  # one in a hook, one in CLAUDE.md
    assert codes.count("safe.agent_mcp_unpinned") == 1
    assert codes.count("safe.agent_injection_text") == 1
    assert codes.count("safe.agent_hidden_unicode") == 1


def test_only_the_loose_server_is_reported(tmp_path):
    hits = [f for f in agent_findings(scan(build(tmp_path))) if f["code"] == "safe.agent_mcp_unpinned"]
    assert len(hits) == 1 and "loose" in hits[0]["summary"] and "server: exact" not in json.dumps(hits[0])
    assert hits[0]["node"] == ".mcp.json:3"


def test_md_findings_keep_their_level(tmp_path):
    levels = {f["node"].split(":")[0]: f["level"] for f in agent_findings(scan(build(tmp_path)))
              if f["node"].startswith(("CLAUDE.md", "AGENTS.md"))}
    assert levels == {"CLAUDE.md": "FAIL", "AGENTS.md": "FAIL"}  # the last finding per file; none is lowered to INFO
    assert all(f["level"] != "INFO" for f in agent_findings(scan(build(tmp_path / "again"))))


def test_report_shape_and_scoring(tmp_path):
    rep = scan(build(tmp_path))
    assert rep["coverage"]["agent_configs"] == [".claude/settings.json", ".mcp.json", "AGENTS.md", "CLAUDE.md"]
    assert {"check": "agents", "outcome": "ran", "reason": None} in rep["outcomes"]
    assert rep["scores"]["grade"] in ("D", "F") and rep["scores"]["safe"] < 100
    for code, level in EXPECT.items():
        assert score.SAFE_WEIGHTS[(code, level)] == (15 if level == "FAIL" else 5)
        assert score.dimension_of(code) == "safe"


def test_repo_without_agent_files_is_untouched(tmp_path):
    rep = scan(project(tmp_path, {}))
    assert "agent_configs" not in rep["coverage"]
    assert all(row["check"] != "agents" for row in rep["outcomes"])
    assert not agent_findings(rep)


def test_catalogue_covers_the_codes():
    from code_guardian import plain
    for code in agents.CODES:
        entry = catalogue.CATALOGUE[code]
        assert entry["means"] and entry["fix"] and entry["title"] and entry["false_positives"]
        assert code in plain.WHY


def test_data_file_shape_and_every_code_maps():
    data = json.loads(agents.PATTERNS_FILE.read_text(encoding="utf-8"))
    assert data["version"] == 1 and data["patterns"]
    assert {p["kind"] for p in data["patterns"]} == {"regex", "unicode_class"}
    pats = agents.load_patterns()
    assert len(pats["regex"]) + len(pats["unicode"]) == len(data["patterns"])
    assert any(lo <= 0x200B <= hi for _, rs, _ in pats["unicode"] for lo, hi in rs)


def test_never_runs_anything():
    tree = ast.parse(Path(agents.__file__).read_text(encoding="utf-8"))
    mods = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    mods |= {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.level == 0}
    assert mods <= {"json", "os", "re", "pathlib"}
    used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | {n.attr for n in ast.walk(tree)
                                                                       if isinstance(n, ast.Attribute)}
    assert not used & {"subprocess", "eval", "exec", "system", "popen", "import_module", "run_path"}


@pytest.mark.parametrize("command,args,flagged", [
    ("npx", ["-y", "pkg"], True),
    ("npx", ["-y", "pkg@latest"], True),
    ("npx", ["-y", "pkg@1.2.3"], False),
    ("npx", ["-y", "@scope/pkg"], True),
    ("npx", ["-y", "@scope/pkg@2.0.0"], False),
    ("uvx", ["pkg"], True),
    ("uvx", ["pkg==1.0"], False),
    ("uvx", ["--from", "pkg", "tool"], True),
    ("pipx", ["run", "pkg"], True),
    ("pipx", ["run", "pkg==1.0"], False),
    ("pipx", ["install", "pkg"], False),
    ("npx.cmd", ["pkg"], True),
    ("node", ["server.js"], False),
    ("npx", ["./local-server"], False),
])
def test_unpinned_rule(tmp_path, command, args, flagged):
    root = project(tmp_path, {".mcp.json": servers({"command": command, "args": args})})
    hits = [f for f in agent_findings(scan(root)) if f["code"] == "safe.agent_mcp_unpinned"]
    assert bool(hits) is flagged


def test_each_unpinned_server_is_one_finding_and_url_servers_none(tmp_path):
    root = project(tmp_path, {".cursor/mcp.json": servers(
        {"command": "npx", "args": ["a"]}, {"command": "uvx", "args": ["b"]}, {"url": SCHEME + "example.org/mcp"})})
    hits = [f for f in agent_findings(scan(root)) if f["code"] == "safe.agent_mcp_unpinned"]
    assert len(hits) == 2 and scan(root)["coverage"]["agent_configs"] == [".cursor/mcp.json"]


@pytest.mark.parametrize("allow,flagged", [(["Bash(*)"], True), (["*"], True), (["Bash(npm test)", "Read"], False)])
def test_open_allow_list(tmp_path, allow, flagged):
    root = project(tmp_path, {".claude/settings.local.json": json.dumps({"permissions": {"allow": allow}})})
    assert bool([f for f in agent_findings(scan(root)) if f["code"] == "safe.agent_auto_approve"]) is flagged


def test_skip_permissions_off_is_fine(tmp_path):
    root = project(tmp_path, {".claude/settings.json": json.dumps({"skipPermissions": False})})
    assert not agent_findings(scan(root))


def test_rules_folder_and_file(tmp_path):
    hide = "x" + chr(0x202E) + "y\n"
    root = project(tmp_path, {".cursor/rules/a.mdc": hide, ".cursor/rules2": "plain\n", ".cursor/other.txt": hide})
    rep = scan(root)
    assert rep["coverage"]["agent_configs"] == [".cursor/rules/a.mdc", ".cursor/rules2"]
    assert [f["node"] for f in agent_findings(rep)] == [".cursor/rules/a.mdc:1"]


def test_bom_at_start_is_not_hidden_text(tmp_path):
    root = project(tmp_path, {"AGENTS.md": chr(0xFEFF) + "plain notes\n"})
    assert not agent_findings(scan(root))


def test_invalid_json_still_gets_the_invisible_character_scan(tmp_path):
    root = project(tmp_path, {".mcp.json": "{ not json " + chr(0x200B)})
    assert [f["code"] for f in agent_findings(scan(root))] == ["safe.agent_hidden_unicode"]


def test_symlinks_are_not_followed(tmp_path):
    outside = tmp_path / "outside.md"
    outside.write_text("EXAMPLE-ONLY " + "disregard all " + "previous instructions\n", encoding="utf-8")
    root = project(tmp_path, {})
    try:
        os.symlink(outside, root / "CLAUDE.md")
    except (OSError, NotImplementedError):
        pytest.skip("no symlinks here")
    rep = scan(root)
    assert not agent_findings(rep) and "agent_configs" not in rep["coverage"]


def test_evidence_does_not_echo_the_matched_text(tmp_path):
    rep = scan(build(tmp_path))
    hit = [f for f in agent_findings(rep) if f["code"] == "safe.agent_injection_text"][0]
    assert "previous" not in json.dumps(hit)
