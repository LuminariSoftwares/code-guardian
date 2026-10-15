"""Provider key shapes (AWS, Stripe, Slack, Hugging Face), *_KEY / *_TOKEN names with high-entropy values, and
exec.dynamic FAIL when eval/exec run user input. Every key-shaped string is built by concatenation at runtime so this
file stays clean under the privacy workflow and its own self-scan."""
import pytest

from code_guardian import report, scanners, score

AWS_ID = "AKIA" + "Q7XZ" * 4
AWS_SECRET = "Zk8vR2mQ+pL5/xN9" * 2 + "tW3cY6hB"          # 40 characters of [A-Za-z0-9/+]
STRIPE_BODY = "a1B2c3D4e5F6g7H8"                          # 16 characters
SLACK = "xox" + "b-" + "123456789012-123456789012-" + "aB3dE5fG7hJ9kL1mN3pQ5rS7"
HF = "hf" + "_" + "aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgH"  # 34 letters
ANTHROPIC = "sk-" + "ant-api03-" + "Qm7Zr2Kp9Lx4" * 3
HIGH = "aZ3kP9mQ2vR7tY5wX1bN8cL4dF6gH0jSaZ3k"            # 36 characters, entropy ~4.9


def text_hits(text, rel="a.txt", python=False):
    return [(f["level"], f["summary"]) for f in scanners.scan_secret_text(rel, text, python)]


def levels(text, **kw):
    return [lv for lv, _ in text_hits(text, **kw)]


@pytest.mark.parametrize("text, expected", [
    # AWS access key ID: (AKIA|ASIA) + 16 of [0-9A-Z], a whole token
    ("key = %s\n" % AWS_ID, ["FAIL"]),
    ("id: '%s'\n" % ("ASIA" + "Q7XZ" * 4), ["FAIL"]),
    ("key = %s\n" % AWS_ID[:-1], []),                                 # 15 characters after the prefix
    ("key = %s\n" % (AWS_ID + "Q"), []),                              # 17: not a whole token
    ("key = X%s\n" % AWS_ID, []),                                     # not at a token boundary
    ("key = %s\n" % ("AKIA" + "q7xz" * 4), []),                       # lower case is not an AWS key ID
    ("key = %s\n" % ("AKIA" + "IOSFODNN7" + "EXAMPLE"), []),          # AWS's documented sample calls itself one
    # Stripe: sk_live_ / rk_live_ + 16 or more is FAIL; sk_test_ is INFO
    ("STRIPE = '%s'\n" % ("sk_" + "live_" + STRIPE_BODY), ["FAIL"]),
    ("STRIPE = '%s'\n" % ("rk_" + "live_" + STRIPE_BODY + "xyz"), ["FAIL"]),
    ("STRIPE = '%s'\n" % ("sk_" + "test_" + STRIPE_BODY), ["INFO"]),
    ("STRIPE = '%s'\n" % ("sk_" + "live_" + STRIPE_BODY[:-1]), []),  # 15 characters
    ("STRIPE = '%s'\n" % ("pk_" + "live_" + STRIPE_BODY), []),       # publishable keys are public
    # Slack: xox[abprs]- tokens
    ("SLACK=%s\n" % SLACK, ["FAIL"]),
    ("SLACK=%s\n" % SLACK.replace("xoxb", "xoxp"), ["FAIL"]),
    ("SLACK=%s\n" % SLACK.replace("xoxb", "xoxz"), []),              # not a Slack token type
    ("see the %s prefix\n" % ("xox" + "b-"), []),                    # the prefix alone
    # Hugging Face: hf_ + 30 or more letters
    ("HF_TOKEN=%s\n" % HF, ["FAIL"]),
    ("HF_TOKEN=%s\n" % HF[:32], []),                                 # 29 letters
    ("from x import %s\n" % ("hf" + "_hub_download"), []),           # an identifier, not a token
    # Anthropic keys are covered by the sk- shape
    ("ANTHROPIC_API_KEY=%s\n" % ANTHROPIC, ["FAIL"]),
])
def test_provider_key_shapes(text, expected):
    assert levels(text) == expected


def test_provider_shapes_are_redacted_and_named():
    hits = scanners.scan_secret_text("a.env", "A=%s\nB=%s\nC=%s\nD=%s\n" % (AWS_ID, SLACK, HF, ANTHROPIC), False)
    assert [f["summary"].split(" shape")[0] for f in hits] == ["AWS access key ID", "Slack token", "Hugging Face token",
                                                             "sk- key"]
    for value in (AWS_ID, SLACK, HF, ANTHROPIC):
        assert value not in repr(hits)


@pytest.mark.parametrize("text, rel, expected", [
    ("aws_secret_access_key = %s\n" % AWS_SECRET, "credentials", ["FAIL"]),       # the ~/.aws/credentials format
    ("AWS_SECRET_ACCESS_KEY=%s\n" % AWS_SECRET, ".env", ["FAIL"]),
    ("  secret_for_aws: '%s'\n" % AWS_SECRET, "deploy.yml", ["FAIL"]),             # either order
    ("aws_secret_value = \"%s\"\n" % AWS_SECRET, "conf.py", ["FAIL"]),            # Python too
    ("aws_secret_access_key = %s\n" % AWS_SECRET[:-1], "credentials", []),         # 39 characters
    ("aws_secret_access_key = %s\n" % (AWS_SECRET + "Q"), "credentials", []),      # 41 characters
    ("aws_region_value = %s\n" % AWS_SECRET, "credentials", []),                   # no "secret" in the name
    ("my_secret_value = %s\n" % AWS_SECRET, "credentials", []),                    # no "aws" in the name
    ("aws_secret_access_key = %s\n" % ("wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLEKEY"), "credentials", []),
])
def test_aws_secret_key_assigned_to_an_aws_secret_name(text, rel, expected):
    assert levels(text, rel=rel, python=rel.endswith(".py")) == expected


@pytest.mark.parametrize("src, n", [
    ('AWS_KEY = "%s"\n' % HIGH, 1),
    ('SLACK_TOKEN = "%s"\n' % HIGH, 1),
    ('client(service_token="%s")\n' % HIGH, 1),
    ('cfg = {"upload_key": "%s"}\n' % HIGH, 1),
    ('CACHE_KEY = "user_profile_cache_v2"\n', 0),          # low entropy: a name, not a credential
    ('SORT_KEY = "name"\n', 0),
    ('PAGE_TOKEN = "%s"\n' % HIGH[:19], 0),                 # too short
    ('SLACK_TOKEN = "fake%s"\n' % HIGH, 0),                 # calls itself fake
    ('SLACK_TOKEN = "%s"\n' % "abcdefghijklmnopqrstuvwx0123", 0),  # every character distinct: an alphabet
    ('TOKEN_URL = "%s"\n' % HIGH, 0),                       # the name does not end in _KEY or _TOKEN
    ('keyboard_key = os.environ["K"]\n', 0),
])
def test_key_and_token_names_with_high_entropy_values(src, n):
    pf = scanners.PyFile("m.py", src.encode("utf-8"), src)
    assert len(scanners.scan_password_literals(pf)) == n


def exec_levels(src):
    pf = scanners.PyFile("m.py", src.encode("utf-8"), src)
    return sorted(((f["level"], f["node"]) for f in scanners.scan_exec_dynamic(pf)),
                  key=lambda t: int(t[1].rsplit(":", 1)[1]))


def test_eval_of_user_input_is_fail():
    src = ("import os, sys\nfrom flask import request\n"
           "def a():\n    eval(input('> '))\n"                                   # 4
           "def b():\n    expr = sys.argv[1]\n    return eval(expr)\n"           # 7
           "def c():\n    code = compile(request.form['c'], 'f', 'exec')\n    exec(code)\n"  # 9 compile, 10 exec
           "def d():\n    exec(os.environ['HOOK'])\n"                            # 12
           "def e(x):\n    eval(x)\n"                                            # 14: a parameter, not a source
           "def f():\n    eval('1 + 1')\n")                                     # 16: a literal
    assert exec_levels(src) == [("FAIL", "m.py:4"), ("FAIL", "m.py:7"), ("WARN", "m.py:9"), ("FAIL", "m.py:10"),
                                ("FAIL", "m.py:12"), ("WARN", "m.py:14")]
    pf = scanners.PyFile("m.py", src.encode("utf-8"), src)
    fail = [f for f in scanners.scan_exec_dynamic(pf) if f["level"] == "FAIL"][0]
    assert "runs code typed by the user" in fail["summary"]


def test_only_the_code_text_is_judged_not_compiles_filename():
    # flask's shell command: the *path* comes from the environment (PYTHONSTARTUP), the code text from a file
    src = ("import os\ndef shell():\n    startup = os.environ.get('PYTHONSTARTUP')\n"
           "    with open(startup) as f:\n        eval(compile(f.read(), startup, 'exec'), {})\n"
           "def bad():\n    exec(compile(input(), '<stdin>', 'exec'))\n")
    assert exec_levels(src) == [("WARN", "m.py:5"), ("WARN", "m.py:5"), ("FAIL", "m.py:7"), ("WARN", "m.py:7")]


def test_untainted_eval_stays_warn():
    assert exec_levels("def g(src):\n    return eval(src)\nexec(open('x').read())\n") == [
        ("WARN", "m.py:2"), ("WARN", "m.py:3")]


def test_weights():
    assert score.TABLES["safe"][("exec.dynamic", "FAIL")] == 30
    assert score.TABLES["safe"][("exec.dynamic", "WARN")] == 10
    assert score.TABLES["safe"][("secret.key", "INFO")] == 0


def put(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def build_leaky(root):
    """Triggering fixture: one of each new shape, a *_TOKEN literal and eval of input()."""
    put(root, "app/settings.py", 'AWS_ACCESS_KEY_ID = "%s"\nSTRIPE_KEY = "%s"\nSLACK_TOKEN = "%s"\nHF = "%s"\n'
        'UPLOAD_TOKEN = "%s"\nSTRIPE_TEST = "%s"\n' % (AWS_ID, "sk_" + "live_" + STRIPE_BODY, SLACK, HF, HIGH,
                                                      "sk_" + "test_" + STRIPE_BODY))
    put(root, "app/calc.py", "def main():\n    print(eval(input('> ')))\n")
    put(root, ".env", "AWS_SECRET_ACCESS_KEY=%s\n" % AWS_SECRET)
    put(root, "tests/test_calc.py", 'KEY = "%s"\nUPLOAD_TOKEN = "%s"\ndef test_x():\n    assert eval(input())\n' % (AWS_ID, HIGH))
    return root


def build_near_miss(root):
    """Clean fixture: every near-miss above, in product code."""
    put(root, "app/settings.py", 'AWS_SAMPLE = "%s"\nSTRIPE = "%s"\nPUBLISHABLE = "%s"\nCACHE_KEY = "user_profile_cache_v2"\n'
        'HF_MODEL = "%s"\n' % ("AKIA" + "IOSFODNN7" + "EXAMPLE", "sk_" + "live_" + STRIPE_BODY[:-1],
                               "pk_" + "live_" + STRIPE_BODY, "hf" + "_hub_download"))
    put(root, "app/calc.py", "def main(expr):\n    return eval(expr)\n")
    return root


def safe_rows(rep):
    return {(r["code"], r["level"]): r["count"] for r in rep["dimensions"]["safe"]["checks"]}


def test_leaky_fixture_end_to_end(tmp_path):
    rep = report.scan(str(build_leaky(tmp_path / "leaky")))
    secrets = sorted((f["node"], f["level"]) for f in rep["findings"] if f["code"] == "secret.key")
    assert secrets == [(".env:1", "FAIL"), ("app/settings.py:1", "FAIL"), ("app/settings.py:2", "FAIL"),
                       ("app/settings.py:3", "FAIL"), ("app/settings.py:4", "FAIL"), ("app/settings.py:5", "FAIL"),
                       ("app/settings.py:6", "INFO"),
                       ("tests/test_calc.py:1", "FAIL"),   # a provider key shape is leaked wherever it sits
                       ("tests/test_calc.py:2", "INFO")]   # a name-based literal in a test is reported at INFO
    execs = sorted((f["node"], f["level"]) for f in rep["findings"] if f["code"] == "exec.dynamic")
    assert execs == [("app/calc.py:2", "FAIL"), ("tests/test_calc.py:4", "INFO")]
    rows = safe_rows(rep)
    assert rows[("secret.key", "FAIL")] == 7 and rows[("exec.dynamic", "FAIL")] == 1
    assert rep["scores"]["capped"] is True


def test_near_miss_fixture_has_no_secret_or_exec_fail(tmp_path):
    rep = report.scan(str(build_near_miss(tmp_path / "near")))
    assert [f for f in rep["findings"] if f["code"] == "secret.key"] == []
    assert [(f["level"], f["node"]) for f in rep["findings"] if f["code"] == "exec.dynamic"] == [("WARN", "app/calc.py:2")]


def test_one_secret_finding_per_line(tmp_path):
    put(tmp_path, "app/k.py", 'SLACK_TOKEN = "%s"\napi_key = "%s"\n' % (SLACK, "sk-" + "B" * 30))
    rep = report.scan(str(tmp_path))
    hits = [(f["node"], f["summary"].split(" ")[0]) for f in rep["findings"] if f["code"] == "secret.key"]
    assert hits == [("app/k.py:1", "Slack"), ("app/k.py:2", "sk-")]   # the shape wins over the name
