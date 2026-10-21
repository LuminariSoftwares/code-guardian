"""Every MCP tool and parameter is documented well enough for an agent to choose it: what it returns, when to use
it, which sibling to use instead, its side effects, and for each parameter a type, description and example. The
README's tool reference is generated from the same specs (tools/tool_reference.py) and must match them."""
import importlib.util
import json

import pytest
from conftest import ROOT

from code_guardian import mcp_server

SPECS = mcp_server.TOOL_SPECS
NAMES = [t["name"] for t in SPECS]


def _reference_module():
    spec = importlib.util.spec_from_file_location("tool_reference", ROOT / "tools" / "tool_reference.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize("tool", SPECS, ids=NAMES)
def test_tool_description_covers_purpose_usage_behaviour_and_output(tool):
    desc = tool.get("description") or ""
    assert tool["name"].isidentifier() and tool["name"].islower(), tool["name"]
    assert 200 <= len(desc) <= 1000, (tool["name"], len(desc))
    assert "Use " in desc or "Use it" in desc, "%s: says when to use it" % tool["name"]
    siblings = [n for n in NAMES if n != tool["name"] and n in desc]
    assert siblings, "%s: names a sibling tool to use instead" % tool["name"]
    assert "Behaviour:" in desc, "%s: states side effects" % tool["name"]
    assert "Returns JSON:" in desc, "%s: states the output shape" % tool["name"]
    assert ("network" in desc) or ("offline" in desc), "%s: says whether it uses the network" % tool["name"]
    assert "Errors:" in desc, "%s: states its failure modes" % tool["name"]
    assert not desc.split(".")[0].endswith("?"), "%s: opens with what it does, not a question" % tool["name"]


@pytest.mark.parametrize("tool", SPECS, ids=NAMES)
def test_description_explains_every_parameter(tool):
    """Glama's Parameters dimension stays at its baseline when the description adds nothing beyond the schema, so
    each description carries a Parameters clause that names every parameter."""
    desc = tool["description"]
    assert "Parameters:" in desc, tool["name"]
    clause = desc[desc.index("Parameters:"):desc.index("Behaviour:")]
    for name in tool["inputSchema"]["properties"]:
        assert name in clause, (tool["name"], name)


@pytest.mark.parametrize("tool", SPECS, ids=NAMES)
def test_every_parameter_has_type_description_and_example(tool):
    schema = tool["inputSchema"]
    assert schema["type"] == "object" and schema.get("additionalProperties") is False
    assert set(schema.get("required", [])) <= set(schema["properties"])
    for name, prop in schema["properties"].items():
        where = "%s.%s" % (tool["name"], name)
        assert prop.get("type") in ("string", "integer"), where
        assert len(prop.get("description") or "") >= 40, where
        assert isinstance(prop.get("examples"), list) and prop["examples"], where
        for ex in prop["examples"]:
            assert isinstance(ex, int if prop["type"] == "integer" else str), where
            if "enum" in prop:
                assert ex in prop["enum"], where
            if "minimum" in prop:
                assert ex >= prop["minimum"], where
        if name not in schema.get("required", []):
            assert "default" in prop or "Default" in prop["description"] or "Optional" in prop["description"], where
            if "default" in prop:
                assert ("default %s" % prop["default"]).lower() in prop["description"].lower(), where


def test_schemas_are_valid_json_schema_and_examples_validate():
    jsonschema = pytest.importorskip("jsonschema")
    for tool in SPECS:
        jsonschema.Draft202012Validator.check_schema(tool["inputSchema"])
        for name, prop in tool["inputSchema"]["properties"].items():
            for ex in prop["examples"]:
                errors = list(jsonschema.Draft202012Validator(prop).iter_errors(ex))
                assert errors == [], (tool["name"], name, ex)


def test_documented_defaults_are_the_defaults_the_server_uses():
    seen = {}

    def fake_scan(path, goal, explain, baseline):
        return {"findings": [{"level": "WARN"}], "scores": {}, "notes": []}

    def fake_exit(findings, fail_on, status, baseline):
        seen["fail_on"] = fail_on
        return 0

    tools = mcp_server.make_tools(fake_scan, lambda p, g: {}, fake_exit, lambda b, a: {},
                                  lambda p, g, top: seen.setdefault("top", top))
    tools["scan"]({"path": str(ROOT)})
    tools["plan"]({"path": str(ROOT)})
    props = {t["name"]: t["inputSchema"]["properties"] for t in SPECS}
    assert seen == {"fail_on": props["scan"]["fail_on"]["default"], "top": props["plan"]["top"]["default"]}


def test_only_explain_mentions_using_the_network():
    for tool in SPECS:
        open_world = tool["annotations"]["openWorldHint"]
        assert ("offline" in tool["description"]) is not open_world, tool["name"]


def test_readme_tool_reference_matches_the_specs():
    ref = _reference_module()
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    block = ref.readme_block(text)
    assert block is not None, "README.md lost the tool-reference markers"
    assert block == ref.render(), "README tool reference is stale: run python tools/tool_reference.py --write"


def test_tools_list_over_the_protocol_serves_the_documented_specs():
    reply = mcp_server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, {})
    assert json.loads(json.dumps(reply["result"]["tools"])) == json.loads(json.dumps(SPECS))
