"""The intake feedback corpus: every false positive or miss found in use becomes a small JSON case here, written red
first, and stays as a regression. See docs/intake.md ("Advisory first, and how misses feed back").

Case file shape (all text is synthetic and benign; invisible characters are written as JSON \\uXXXX escapes, binary
files as {"base64": "..."}):
    {"name": str, "kind": "false_positive" | "miss", "reason": str,
     "files": {"rel/path": "text" | {"base64": "..."}},
     "expect": [{"rule": str, "confidence": "low|medium|high", "file": str}],      # optional
     "expect_none": ["rule id", ...]}                                              # optional
"""
import base64
import json
from pathlib import Path

import pytest

from code_guardian import intake, intake_rules
from intake_helpers import mk

CASES = sorted((Path(__file__).resolve().parent / "intake_cases").glob("*.json"))


def _load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_there_is_a_seed_corpus():
    assert len(CASES) >= 4


@pytest.mark.parametrize("path", CASES, ids=lambda p: p.stem)
def test_case(path, tmp_path):
    case = _load(path)
    assert {"name", "kind", "reason", "files"} <= set(case) and case["kind"] in ("false_positive", "miss")
    assert case.get("expect") or case.get("expect_none"), "a case must assert something"
    files = {rel: (base64.b64decode(v["base64"]) if isinstance(v, dict) else v) for rel, v in case["files"].items()}
    res = intake.scan(mk(tmp_path / "repo", files))
    for want in case.get("expect", []):
        assert want["rule"] in intake_rules.RULES
        assert any(f["rule"] == want["rule"] and f["confidence"] == want["confidence"] and f["file"] == want["file"]
                   for f in res["findings"]), (want, [(f["rule"], f["confidence"], f["file"]) for f in res["findings"]])
    for rule in case.get("expect_none", []):
        assert rule in intake_rules.RULES
        assert [f for f in res["findings"] if f["rule"] == rule] == [], rule
