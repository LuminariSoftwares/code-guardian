"""The official MCP Registry markers: the mcp-name line in the README PyPI receives, and server.json agreeing with it."""
import json
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NAME = "io.github.LuminariSoftwares/code-guardian"


def test_registry_markers_exist_and_agree():
    with open(ROOT / "pyproject.toml", "rb") as fh:
        project = tomllib.load(fh)["project"]
    readme = (ROOT / project["readme"]).read_text(encoding="utf-8")  # the file setuptools ships as the PyPI description
    lines = [ln for ln in readme.splitlines() if ln.startswith("mcp-name:")]
    assert lines == ["mcp-name: " + NAME], lines
    server = json.loads((ROOT / "server.json").read_text(encoding="utf-8"))
    assert server["name"] == NAME
    assert re.fullmatch(r"mcp-name: (\S+)", lines[0]).group(1) == server["name"]
    # near the top: before the first section heading
    assert readme.index(lines[0]) < readme.index("\n## ")


def test_server_json_points_at_this_pypi_package():
    with open(ROOT / "pyproject.toml", "rb") as fh:
        project = tomllib.load(fh)["project"]
    server = json.loads((ROOT / "server.json").read_text(encoding="utf-8"))
    assert server["$schema"] == "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json"
    (pkg,) = server["packages"]
    assert project["name"] == pkg["identifier"] == "code-guardian-mcp"
    assert pkg["registryType"] == "pypi" and pkg["runtimeHint"] == "uvx"
    assert pkg["packageArguments"] == [{"type": "positional", "value": "mcp"}]
    assert pkg["transport"] == {"type": "stdio"}
    assert project["scripts"]["code-guardian-mcp"] == "code_guardian.mcp_server:main"
    assert len(server["description"]) <= 100


def test_release_descriptions_mention_the_verify_loop():
    with open(ROOT / "pyproject.toml", "rb") as fh:
        project = tomllib.load(fh)["project"]
    server = json.loads((ROOT / "server.json").read_text(encoding="utf-8"))
    assert "verify loop" in project["description"] and "verify loop" in server["description"]
    assert len(server["description"]) <= 100
