"""A URL literal is an egress target, and a URL can be a credential: a Slack or Discord webhook path, a signed
query string, `user:password@host`. The egress inventory must say where the code talks to without reprinting the
secret that lets anyone else talk to it (the README promises output with no secret values, and `explain` POSTs
these findings to the configured model).

Fingerprints are computed from the source line, not from what the report prints, so redacting the printed target
does not invalidate a baseline written before this change. Both halves are checked here.
"""
import json
import subprocess
import sys

from code_guardian import baseline, report, scanners

# Built at runtime: the self-scan reads string literals, and these are test input, not this project's egress.
HTTP = "http" + "s://"
WEBHOOK = HTTP + "hooks.slack.com/services/T000/B000/XXXXSECRETXXXX"
SIGNED = HTTP + "api.example.org/v1?api_key=abcd1234SECRETvalue"
USERINFO = HTTP + "user:hunter2SECRET@api.example.org/v1"
SOURCE = """import urllib.request


def notify():
    urllib.request.urlopen("%s")


def fetch():
    return urllib.request.urlopen("%s")


def login():
    return urllib.request.urlopen("%s")
""" % (WEBHOOK, SIGNED, USERINFO)


def _repo(tmp_path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "net.py").write_text(SOURCE, encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "urlsec"\nversion = "0.1.0"\n', encoding="utf-8")
    (tmp_path / "README.md").write_text("# urlsec\n", encoding="utf-8")
    return tmp_path


def test_no_secret_from_a_url_literal_reaches_the_report(tmp_path):
    rep = report.scan(str(_repo(tmp_path)))
    text = json.dumps(rep)
    assert "SECRET" not in text, [e["target"] for e in rep["egress"]]
    assert "hunter2" not in text
    targets = [e["target"] for e in rep["egress"] if e["kind"] == "url"]
    assert sorted(targets) == sorted([
        HTTP + "hooks.slack.com/services/<redacted>",
        HTTP + "api.example.org/v1?api_key=<redacted>",
        HTTP + "<redacted>@api.example.org/v1",
    ]), targets


def test_the_cli_and_the_mcp_server_print_the_same_redacted_targets(tmp_path):
    root = str(_repo(tmp_path))
    run = subprocess.run([sys.executable, "-m", "code_guardian", "scan", root, "--json"],
                         capture_output=True, text=True, timeout=120)
    assert "SECRET" not in run.stdout, run.stdout[:2000]
    msgs = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
             "params": {"name": "scan", "arguments": {"path": root}}}]
    mcp = subprocess.run([sys.executable, "-m", "code_guardian.mcp_server"],
                         input="\n".join(json.dumps(m) for m in msgs) + "\n",
                         capture_output=True, text=True, timeout=120)
    assert "SECRET" not in mcp.stdout, mcp.stdout[:2000]


def test_the_text_report_redacts_the_egress_inventory(tmp_path):
    rep = report.scan(str(_repo(tmp_path)))
    assert "SECRET" not in report.render(rep)
    assert "<redacted>" in report.render(rep)


def test_fingerprints_still_come_from_the_source_line(tmp_path):
    """redact() is untouched, so normalise(source line) -- and every fingerprint in an existing baseline -- is the
    same before and after the targets are redacted."""
    for url in (WEBHOOK, SIGNED):
        line = '    urllib.request.urlopen("%s")' % url
        assert scanners.redact(line) == line
        assert baseline.normalise(line) == line.strip()
    root = _repo(tmp_path)
    rep = report.scan(str(root))
    egress = [f for f in rep["findings"] if f["code"] == "net.egress" and "url" in f["evidence"][0]]
    assert len(egress) == 3, egress
    lines = (root / "pkg" / "net.py").read_text(encoding="utf-8").splitlines()
    for finding in egress:
        rel, lineno = baseline.split_node(finding["node"])
        assert finding["fingerprint"] == baseline.fingerprint(
            finding["code"], finding["level"], rel, lines[lineno - 1]), finding["node"]


def test_a_baseline_marks_every_redacted_finding_known(tmp_path):
    root = str(_repo(tmp_path))
    rep = report.scan(root)
    fingerprints = baseline.document(rep["findings"], "test")["fingerprints"]
    (tmp_path / "base.json").write_text(json.dumps({"tool": "code-guardian", "version": "test",
                                                    "fingerprints": fingerprints}), encoding="utf-8")
    again = report.scan(root, baseline=str(tmp_path / "base.json"))
    assert [f for f in again["findings"] if f["new"]] == []


def test_redact_url_keeps_the_destination_and_is_idempotent():
    once = scanners.redact_url(SIGNED)
    assert once == HTTP + "api.example.org/v1?api_key=<redacted>"
    assert scanners.redact_url(once) == once
    plain = HTTP + "api.example.org/v1/status"
    assert scanners.redact_url(plain) == plain
    assert scanners.redact_url("not a url") == "not a url"
