"""Each scanner on its own, with exact findings. URLs and key shapes are built by concatenation so this file stays
clean under its own self-scan and the privacy workflow."""
import pytest

from conftest import HTTP as H, tailnet
from make_risky import mixed_body

from code_guardian import manifests, scanners

KEY = "sk-" + mixed_body("scanners_key", 30)


def run(fn, src):
    pf = scanners.PyFile("m.py", src.encode("utf-8"), src)
    return sorted(((f["code"], f["level"], f["node"]) for f in fn(pf)), key=lambda t: int(t[2].rsplit(":", 1)[1]))


@pytest.mark.parametrize("text, hits", [
    ("token = '%s'\n" % KEY, 1),
    ("# old key: %s\n" % ("ghp_" + mixed_body("scanners_ghp", 20)), 1),
    ("x = '%s'\n" % ("AIza" + mixed_body("scanners_aiza", 30)), 1),
    ("-----BEGIN " + "OPENSSH PRIVATE KEY-----\n", 1),
    ("sk-short\n", 0),
    ("ask-" + "e" * 20 + "\n", 0),  # not at a token boundary
])
def test_secret_text_shapes(text, hits):
    assert len(scanners.scan_secret_text("a.txt", text, python=True)) == hits


def test_secret_text_password_outside_python_only():
    line = 'password: "%s"\n' % ("s3cret" + "-value")
    assert [f["node"] for f in scanners.scan_secret_text("c.yml", line, python=False)] == ["c.yml:1"]
    assert scanners.scan_secret_text("c.py", line, python=True) == []  # Python passwords come from the AST scanner


@pytest.mark.parametrize("src, n", [
    ('DB_PASSWORD = "%s"\n' % ("pa55" + "word!"), 1),
    ('connect(password="%s")\n' % ("pa55" + "word!"), 1),
    ('cfg = {"api_key": "%s"}\n' % ("abcd" + "1234"), 1),
    ('password = ""\n', 0),
    ('password = "<set me>"\n', 0),
    ('api_key = "OPENAI_API_KEY"\n', 0),  # an env-var name, not a value
    ('password = os.environ["PW"]\n', 0),
    ('token_type = "bearer"\n', 0),
    ('env(ANTHROPIC_API_KEY="sk-ant-mock")\n', 0),  # calls itself a mock
    ('password = "dummy-pass"\n', 0),
])
def test_password_literals(src, n):
    assert len(run(scanners.scan_password_literals, src)) == n


def test_exec_dynamic():
    src = "eval(x)\nexec('print(1)')\ncompile(src, 'f', 'exec')\n__import__(name)\n__import__('os')\nimport re\nre.compile(p)\n"
    assert run(scanners.scan_exec_dynamic, src) == [
        ("exec.dynamic", "WARN", "m.py:1"), ("exec.dynamic", "WARN", "m.py:3"), ("exec.dynamic", "WARN", "m.py:4")]


def test_exec_shell_taint():
    src = ("import os, sys, subprocess\n"
           "def a():\n    os.system('make')\n"
           "def b():\n    cmd = 'ls ' + sys.argv[1]\n    subprocess.call(cmd, shell=True)\n"
           "def c():\n    os.popen(os.environ['CMD'])\n"
           "def d():\n    subprocess.run(['ls', '-l'])\n"
           "def e(user):\n    subprocess.run(user, shell=False)\n")
    assert run(scanners.scan_exec_shell, src) == [
        ("exec.shell", "WARN", "m.py:3"), ("exec.shell", "FAIL", "m.py:6"), ("exec.shell", "FAIL", "m.py:8")]


def test_deser():
    src = ("import pickle, marshal, yaml, torch\nfrom yaml import CSafeLoader\n"
           "pickle.loads(b)\nmarshal.loads(b)\nyaml.load(s, CSafeLoader)\nyaml.unsafe_load(s)\n"
           "yaml.safe_load(s)\ntorch.load(f, weights_only=False)\n")
    assert [n for _, _, n in run(scanners.scan_deser, src)] == ["m.py:3", "m.py:4", "m.py:6", "m.py:8"]


def test_egress_classification():
    src = ("A = '%spypi.org/a'\nB = 'https://example.com/b'\nC = '%slocalhost:8080'\n"
           "D = '%s%s:11434/api'\nE = f'%s{host}:{port}/api'\nF = '%s:8000'\n"
           "G = 'https://%s/x'\n" % (H, H, H, tailnet(7), H, tailnet(9), tailnet(10)))
    found = [(lv, n) for _, lv, n in run(scanners.scan_egress, src)]
    # public plain http WARN; https INFO; loopback INFO; tailnet/private addresses INFO (local network);
    # plain http to a runtime host WARN
    assert found == [("WARN", "m.py:1"), ("INFO", "m.py:2"), ("INFO", "m.py:3"), ("INFO", "m.py:4"),
                     ("WARN", "m.py:5"), ("INFO", "m.py:6"), ("INFO", "m.py:7")]


@pytest.mark.parametrize("host, scheme, level", [
    ("pypi.org", "http", "WARN"), ("pypi.org", "https", "INFO"), ("gpu-box", "http", "INFO"),
    ("example.com", "http", "INFO"), ("stub.invalid", "http", "INFO"), ("api.example.org", "http", "INFO"),
    ("nas.lan", "http", "INFO"), ("printer.local", "http", "INFO"), ("{}", "http", "WARN"), ("%s", "https", "INFO"),
    ("localhost", "http", "INFO"), ("::1", "http", "INFO"),
])
def test_classify_host(host, scheme, level):
    assert scanners.classify_host(scheme, host)[0] == level


def test_public_ip_is_warn_even_over_https():
    public = ".".join(["1"] * 4)  # a well-known public resolver; built at runtime, like every address in tests
    assert scanners.classify_host("https", public) == ("WARN", "public IP address")
    assert [lv for _, lv, _ in run(scanners.scan_egress, "PEER = '%s'\n" % public)] == ["WARN"]
    assert scanners.classify_host("http", tailnet(3)) == ("INFO", "local-network address")


def test_egress_calls():
    src = ("import socket, httpx\nimport urllib.request as ur\nimport sqlite3\n"
           "ur.urlopen(u)\nhttpx.Client()\ns = socket.socket()\ns.connect(addr)\nsqlite3.connect('db')\n")
    assert [n for _, _, n in run(scanners.scan_egress, src)] == ["m.py:4", "m.py:5", "m.py:7"]


def test_bind_all():
    src = ("app.run(host='0.0.0.0')\nuvicorn.run(app, host='::')\nlisten_addr = '0.0.0.0'\n"
           "sock.bind(('127.0.0.1', 80))\nif h == '0.0.0.0':\n    pass\n")
    assert [n for _, _, n in run(scanners.scan_bind_all, src)] == ["m.py:1", "m.py:2", "m.py:3"]


def test_tls_off():
    src = ("import ssl, requests\nfrom ssl import CERT_NONE\nrequests.get(u, verify=True)\nrequests.get(u, verify=False)\n"
           "ssl._create_default_https_context = ssl._create_unverified_context\nctx.verify_mode = CERT_NONE\n")
    assert [n for _, _, n in run(scanners.scan_tls_off, src)] == ["m.py:4", "m.py:5", "m.py:6"]


def test_obfuscation():
    hexblob = "0123456789abcdef" * 13
    src = ("import zlib, base64\n"
           "data = zlib.decompress(base64.b64decode(blob))\n"
           "exec(data)\n"
           "eval(compile(x, 'f', 'exec'))\n"
           "H = '%s'\n"
           "S = 'just a long sentence with spaces that is not a blob at all, however long it might grow to be in time'\n"
           % hexblob)
    assert run(scanners.scan_obfuscation, src) == [("obfuscation", "FAIL", "m.py:3"), ("obfuscation", "WARN", "m.py:5")]


def test_fs_outside():
    src = ("import os, shutil\nfrom pathlib import Path\n"
           "Path('/var/log/x').write_text(t)\nos.remove(os.path.join('/etc', name))\n"
           "shutil.copy(src, '~/.bashrc')\nopen(f'../{name}', 'w')\nopen('data/out.txt', 'w')\n"
           "Path('data').mkdir()\nopen(path, 'w')\n")
    assert [n for _, _, n in run(scanners.scan_fs_outside, src)] == ["m.py:3", "m.py:4", "m.py:5", "m.py:6"]


def test_every_finding_is_likely_and_short():
    src = "import os\nos.system('x' * 500)\neval(y)\n"
    for code, fn in scanners.PY_SCANNERS:
        for f in fn(scanners.PyFile("m.py", src.encode(), src)):
            assert f["confidence"] == "LIKELY" and len(f["summary"]) <= 120


def test_manifest_npm_hooks_and_pins():
    pkg = '{"scripts": {"preinstall": "a", "install": "b", "build": "c"}, "devDependencies": {"x": ">=1"}}'
    found = sorted((f["code"], f["level"]) for f in manifests.scan_manifest("package.json", pkg))
    assert found == [("deps.unpinned", "INFO"), ("install.hook", "WARN"), ("install.hook", "WARN")]


def test_manifest_pyproject_backend_path():
    text = '[build-system]\nbuild-backend = "b"\nbackend-path = ["."]\n[project]\ndependencies = ["a<2"]\n'
    assert [(f["code"], f["node"]) for f in manifests.scan_manifest("pyproject.toml", text)] == [
        ("install.hook", "pyproject.toml:3")]
