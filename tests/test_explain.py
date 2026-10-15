"""--explain against a stub model on loopback: it adds a labelled explanation, sends findings only, never changes the
score, and fails soft."""
import json
import os
import socket
import subprocess
import sys

import make_risky
from conftest import FIXTURES, HTTP, tailnet

from code_guardian import explain, report

OLLAMA_REPLY = {"message": {"role": "assistant", "content": "Grade F: a key is in the code. Remove it first."}}
OPENAI_REPLY = {"choices": [{"message": {"role": "assistant", "content": "Grade A: nothing to fix."}}]}


def strip(rep):
    rep = json.loads(json.dumps(rep))
    rep.pop("explanation", None)
    rep["notes"] = [n for n in rep["notes"] if not n.startswith("explain")]
    return rep


def closed_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_ollama_explanation_never_changes_the_report(stub, tmp_path):
    model = stub({("POST", "/api/chat"): (200, OLLAMA_REPLY, 0)})
    path = str(make_risky.build(tmp_path / "risky"))
    plain = report.scan(path)
    explained = report.scan(path, explain=True, env={"CODE_GUARDIAN_LLM_URL": model.url + "/api/chat",
                                                     "CODE_GUARDIAN_LLM_MODEL": "qwen3:8b"})
    assert explained["explanation"] == {"label": "model explanation (not part of the score)",
                                        "text": OLLAMA_REPLY["message"]["content"]}
    assert strip(explained) == strip(plain)
    assert explained["scores"] == plain["scores"] and explained["findings"] == plain["findings"]
    assert [n for n in explained["notes"] if n.startswith("explain")][0].startswith("explain: ollama answered in")


def test_only_findings_are_sent(stub, tmp_path):
    model = stub({("POST", "/api/chat"): (200, OLLAMA_REPLY, 0)})
    path = make_risky.build(tmp_path / "risky")
    report.scan(str(path), explain=True, env={"CODE_GUARDIAN_LLM_URL": model.url, "CODE_GUARDIAN_LLM_MODEL": "m"})
    assert model.paths() == ["/api/chat"]
    body = model.requests[0][2]
    assert body["model"] == "m" and body["stream"] is False
    sent = json.loads(body["messages"][1]["content"])
    assert set(sent) == {"scores", "findings", "hygiene"}
    assert set(sent["scores"]) == {"safe", "works", "complete", "overall", "grade"}
    assert all(set(f) == {"code", "level", "node", "summary"} for f in sent["findings"])
    raw = json.dumps(body)
    for source_line in (path / "risky" / "runner.py").read_text(encoding="utf-8").splitlines():
        if source_line.strip():
            assert source_line.strip() not in raw
    assert ("sk-" + "A" * 24) not in raw and '"evidence"' not in raw


def test_openai_compatible(stub):
    model = stub({("POST", "/v1/chat/completions"): (200, OPENAI_REPLY, 0)})
    rep = report.scan(str(FIXTURES / "clean_repo"), explain=True,
                      env={"CODE_GUARDIAN_LLM_URL": model.url + "/v1", "CODE_GUARDIAN_LLM_MODEL": "local",
                           "CODE_GUARDIAN_LLM_KEY": "not-a-real-key"})
    assert rep["explanation"]["text"] == "Grade A: nothing to fix."
    assert model.paths() == ["/v1/chat/completions"]


def test_fails_soft_when_unset_or_unreachable():
    path = str(FIXTURES / "clean_repo")
    plain = report.scan(path)
    unset = report.scan(path, explain=True, env={})
    dead = report.scan(path, explain=True, env={"CODE_GUARDIAN_LLM_URL": "http://127.0.0.1:%d/api/chat" % closed_port(),
                                                "CODE_GUARDIAN_LLM_MODEL": "m", "CODE_GUARDIAN_LLM_TIMEOUT": "5"})
    for rep in (unset, dead):
        assert "explanation" not in rep
        assert strip(rep) == strip(plain)
        assert len(rep["notes"]) == len(plain["notes"]) + 1
    assert unset["notes"][-1] == "explain skipped: CODE_GUARDIAN_LLM_URL is not set"
    assert dead["notes"][-1].startswith("explain skipped: the model at 127.0.0.1:")


def test_server_error_and_empty_reply_fail_soft(stub):
    for reply in ((500, {"error": "boom"}, 0), (200, {"message": {"content": ""}}, 0), (200, "not json", 0)):
        model = stub({("POST", "/api/chat"): reply})
        text, note = explain.explain({"findings": []}, {"CODE_GUARDIAN_LLM_URL": model.url, "CODE_GUARDIAN_LLM_MODEL": "m"})
        assert text is None and note.startswith("explain skipped:")


def test_cli_explain_label_and_same_exit_code(stub, tmp_path):
    model = stub({("POST", "/api/chat"): (200, OLLAMA_REPLY, 0)})
    path = make_risky.build(tmp_path / "risky")
    env = dict(os.environ, CODE_GUARDIAN_LLM_URL=model.url, CODE_GUARDIAN_LLM_MODEL="m")
    r = subprocess.run([sys.executable, "-m", "code_guardian", "scan", str(path), "--explain"],
                       capture_output=True, text=True, timeout=120, env=env)
    assert r.returncode == 1
    assert "model explanation (not part of the score):\n  Grade F: a key is in the code." in r.stdout
    assert "Overall   31/100  grade F" in r.stdout


def test_endpoint_detection():
    host = HTTP + tailnet(2)
    assert explain.endpoint(host + ":11434") == ("ollama", host + ":11434/api/chat")
    assert explain.endpoint(host + ":1234/v1/") == ("openai", host + ":1234/v1/chat/completions")
    for bad in ("ftp" + "://example.com/api/chat", HTTP + "example.com/other"):
        try:
            explain.endpoint(bad)
        except ValueError:
            continue
        raise AssertionError(bad)
