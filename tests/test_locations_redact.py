"""Every deduction cites all its evidence (locations), and nothing secret or personal reaches any output: one
redact() is applied on every output path (JSON, text, Markdown, SARIF, MCP)."""
import json
import subprocess
import sys

from code_guardian import mcp_server, outputs, report, scanners, score
from code_guardian.finding import make_finding
from make_risky import mixed_body


def f(code, level, node):
    return make_finding(code, "partial", level, node, "s")


def test_each_check_row_lists_every_location_sorted():
    rows = score.dimension([f("fs.outside", "WARN", "b.py:10"), f("fs.outside", "WARN", "b.py:9"),
                            f("fs.outside", "WARN", "a.py:30")], "safe")["checks"]
    assert rows[0]["locations"] == ["a.py:30", "b.py:9", "b.py:10"] and rows[0]["more"] == 0
    assert rows[0]["first"] == "a.py:30"


def test_locations_cap_at_20_plus_more():
    many = [f("net.egress", "WARN", "m.py:%d" % i) for i in range(1, 26)]
    row = score.dimension(many, "safe")["checks"][0]
    assert row["count"] == 25 and len(row["locations"]) == 20 and row["more"] == 5
    assert row["locations"][0] == "m.py:1" and row["locations"][-1] == "m.py:20"


def test_text_report_lists_up_to_three_locations(tmp_path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "a.py").write_text("import os\n" + "os.system('ls')\n" * 5, encoding="utf-8")
    text = report.render(report.scan(str(tmp_path)))
    line = [ln for ln in text.splitlines() if "exec.shell WARN" in ln][0]
    assert line.rstrip().endswith("at pkg/a.py:2, pkg/a.py:3, pkg/a.py:4 (+2 more)"), line


def planted():
    key = "sk-" + mixed_body("locations_redact", 30)
    email = "alice.doe" + "@" + "corp-mail.org"
    return key, email


def leaky_repo(root):
    key, email = planted()
    (root / "app").mkdir()
    (root / "app" / "__init__.py").write_text("", encoding="utf-8")
    (root / "app" / "hook.py").write_text(
        "import os\nHOOK = 'http://hooks.corp-mail.org/x?token=%s&to=%s'\n"
        "def save():\n    open('/srv/%s/out.txt', 'w')\n" % (key, email, email), encoding="utf-8")
    return key, email


def test_planted_key_and_email_appear_in_no_output(tmp_path):
    key, email = leaky_repo(tmp_path)
    rep = report.scan(str(tmp_path))
    assert any(f["code"] == "net.egress" for f in rep["findings"])  # the line is reported...
    assert any(f["code"] == "secret.key" for f in rep["findings"])
    texts = {
        "json": json.dumps(rep),
        "text": report.render(rep),
        "markdown": outputs.to_markdown(rep),
        "sarif": json.dumps(outputs.to_sarif(rep)),
        "mcp": json.dumps(mcp_server.default_tools()["scan"]({"path": str(tmp_path)})),
    }
    cli = subprocess.run([sys.executable, "-m", "code_guardian", "scan", str(tmp_path), "--json"], capture_output=True,
                         text=True, timeout=120)
    texts["cli"] = cli.stdout + cli.stderr
    for name, text in texts.items():
        assert key not in text, name  # ...but the value never is
        assert email not in text, name
        assert "<redacted" in text, name


def test_redact_masks_shapes_and_leaves_ordinary_text():
    key, email = planted()
    assert scanners.redact("url https://x.org/?k=%s and %s" % (key, email)) == \
        "url https://x.org/?k=<redacted key> and <redacted email>"
    assert scanners.redact("os.system runs a command") == "os.system runs a command"
    assert scanners.redact(scanners.redact(key)) == "<redacted key>"


def test_secret_evidence_is_never_raw_even_when_a_check_puts_it_there():
    key, _ = planted()
    raw = "Xy9" + "kP2mQ7vR4tL8wN3bZ6cJ"
    rep = {"findings": [make_finding("secret.key", "partial", "FAIL", "a.py:1", "s", evidence=["value: " + raw, key])],
           "hygiene": {"findings": [], "notes": []}, "notes": [], "egress": []}
    out = report.redact_report(rep)
    assert raw not in json.dumps(out) and key not in json.dumps(out)
    assert rep["findings"][0]["evidence"][1] == key  # the input report is not modified
