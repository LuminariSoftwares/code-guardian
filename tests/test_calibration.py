"""False-positive fixes found by scanning well-known clean projects (see calibration.md). Each test reproduces the
pattern in a tiny repo: red before the fix, green after."""
import ast

from code_guardian import report, scanners, works
from make_risky import mixed_body


def write(root, files):
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text, encoding="utf-8")
    return report.scan(str(root))


def levels(rep, code):
    return sorted((f["level"], f["node"]) for f in rep["findings"] if f["code"] == code)


def test_safe_findings_in_test_code_are_info(tmp_path):
    rep = write(tmp_path, {
        "pkg/__init__.py": "",
        "tests/test_x.py": "import pickle, requests\ndef test_x():\n    password = 'hunter2hunter2'\n"
                           "    requests.get('https://example.com', verify=False)\n    assert pickle.loads(b'')\n",
        "tests/certs/server.key": "-----BEGIN " + "RSA PRIVATE KEY-----\nabc\n",
    })
    assert levels(rep, "tls.off") == [("INFO", "tests/test_x.py:4")]
    assert levels(rep, "deser.unsafe") == [("INFO", "tests/test_x.py:5")]
    assert levels(rep, "secret.key") == [("INFO", "tests/certs/server.key:1"), ("INFO", "tests/test_x.py:3")]
    tls = [f for f in rep["findings"] if f["code"] == "tls.off"][0]
    assert tls["evidence"][-1] == "in test code: reported at INFO (was FAIL)"
    assert rep["scores"]["safe"] == 100 and not rep["scores"]["capped"]


def test_key_shapes_and_decoded_exec_stay_fail_even_in_tests(tmp_path):
    rep = write(tmp_path, {
        "tests/conftest.py": "import base64\nexec(base64.b64decode(PAYLOAD))\nKEY = '%s'\n" % ("sk-" + mixed_body("calibration_conftest", 30)),
    })
    assert levels(rep, "obfuscation") == [("FAIL", "tests/conftest.py:2")]
    assert levels(rep, "secret.key") == [("FAIL", "tests/conftest.py:3")]


def test_tls_off_only_when_the_caller_asks_is_warn():
    src = ("import ssl\ndef ctx(verify=True):\n    if verify is False:\n        c = ssl.SSLContext()\n"
           "        c.check_hostname = False\n        c.verify_mode = ssl.CERT_NONE\n    return c\n"
           "def always():\n    c = ssl.SSLContext()\n    c.check_hostname = False\n")
    pf = scanners.PyFile("m.py", src.encode(), src)
    assert sorted((f["level"], f["node"]) for f in scanners.scan_tls_off(pf)) == [
        ("FAIL", "m.py:10"), ("WARN", "m.py:5"), ("WARN", "m.py:6")]
    warn = [f for f in scanners.scan_tls_off(pf) if f["level"] == "WARN"][0]
    assert warn["summary"] == "TLS certificate checking can be switched off by the caller (check_hostname = False)"


def test_an_alphabet_is_not_high_entropy():
    src = "LETTERS = '%s'\nTOKEN = '%s'\n" % ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                                                   "aZ3kQ9xP2mL8vB7nC4rT6yH1jK5wE0qUaZ3kQ9xPpP2mL8")
    pf = scanners.PyFile("m.py", src.encode(), src)
    assert [f["node"] for f in scanners.scan_obfuscation(pf)] == ["m.py:2"]


def test_import_behind_a_flag_set_by_a_guarded_import():
    tree = ast.parse("try:\n    import simplejson as json\n    has_simplejson = True\nexcept ImportError:\n"
                     "    import json\n    has_simplejson = False\nif has_simplejson:\n"
                     "    from simplejson import JSONDecodeError\nimport numpy\n")
    assert works.unresolved_imports("pkg/compat.py", tree, set(), set()) == [(9, "numpy")]


def test_test_files_are_not_checked_for_undeclared_imports(tmp_path):
    rep = write(tmp_path, {"pkg/__init__.py": "import numpy\n", "tests/test_a.py": "import site_app\nimport hypothesis\n"
                           "def test_a():\n    assert site_app\n"})
    assert [f["node"] for f in rep["findings"] if f["code"] == "works.import_unresolved"] == ["pkg/__init__.py:1"]


def test_scripts_resolve_next_to_their_own_pyproject(tmp_path):
    rep = write(tmp_path, {
        "examples/demo/pyproject.toml": '[project]\nname = "demo"\n[project.scripts]\ndemo = "demo:cli"\nbad = "demo:nope"\n',
        "examples/demo/demo.py": "def cli():\n    pass\n",
        "pyproject.toml": '[project]\nname = "x"\nversion = "1"\nrequires-python = ">=3.11"\n[project.scripts]\n'
                          'x = "pkg.cli:main"\n',
        "src/pkg/__init__.py": "", "src/pkg/cli.py": "def main():\n    pass\n",
    })
    assert [(f["node"], f["summary"]) for f in rep["findings"] if f["code"] == "works.entry_missing"] == [
        ("examples/demo/pyproject.toml:5", "script 'bad' points at demo:nope, but demo defines no nope")]


def test_env_example_is_for_applications_only(tmp_path):
    lib = write(tmp_path / "lib", {"lib/__init__.py": "import os\nCOLOR = os.environ.get('NO_COLOR')\n"})
    assert levels(lib, "complete.env_example") == []
    app = write(tmp_path / "app", {"app.py": "import os\nCOLOR = os.environ.get('APP_TOKEN')\n", "Dockerfile": "FROM x\n"})
    assert levels(app, "complete.env_example") == [("WARN", "app.py:2")]


def test_documentation_samples_are_info(tmp_path):
    rep = write(tmp_path, {
        "pkg/__init__.py": "",
        "docs/auth.md": '>>> auth = BasicAuth(username="alice", password="s3cr3t-alice9")\n',
        "README.rst": 'Use ``api_key: "k3y-from-dashboard"`` in the config.\n',
        "docs/keys.md": "KEY=%s\n" % ("ghp_" + mixed_body("calibration_docs", 30)),
    })
    assert levels(rep, "secret.key") == [("FAIL", "docs/keys.md:1"), ("INFO", "README.rst:1"), ("INFO", "docs/auth.md:1")]


def test_a_value_that_names_its_field_is_a_placeholder():
    for value in ("secret", "password", "pass", "Password"):
        assert scanners.scan_secret_text("c.yml", 'password: "%s"\n' % value, python=False) == [], value
    assert len(scanners.scan_secret_text("c.yml", 'password: "%s"\n' % ("s3" + "cr3t-value"), python=False)) == 1


def test_pytest_fixtures_named_test_are_not_tests():
    tree = ast.parse("import pytest\n"
                     "@pytest.fixture\ndef test_apps():\n    yield\n"
                     "@pytest.fixture(scope='module')\ndef test_db():\n    return 1\ndef test_real():\n    pass\n")
    assert works.test_no_assert("tests/conftest.py", tree) == (8, 1, ["test_real"])


def test_xml_namespace_uris_are_not_egress():
    src = "SVG = 'http://www.w3.org/2000/svg'\nSOAP = 'http://schemas.xmlsoap.org/soap/envelope/'\nX = 'http://pypi.org/x'\n"
    pf = scanners.PyFile("m.py", src.encode(), src)
    assert [(f["level"], f["node"]) for f in scanners.scan_egress(pf)] == [("INFO", "m.py:1"), ("INFO", "m.py:2"),
                                                                          ("WARN", "m.py:3")]


def test_docs_are_not_checked_for_undeclared_imports(tmp_path):
    rep = write(tmp_path, {"pkg/__init__.py": "", "docs/conf.py": "import docutils\n"})
    assert [f for f in rep["findings"] if f["code"] == "works.import_unresolved"] == []


def test_star_reexports_and_double_bindings_are_followed():
    from code_guardian import orphans
    trees = {"pkg/__init__.py": ast.parse("from ._client import *\ntry:\n    from ._main import main\n"
                                          "except ImportError:\n    def main():\n        raise SystemExit(1)\n"),
             "pkg/_client.py": ast.parse("__all__ = ['Client']\nclass _Base:\n    pass\nclass Client(_Base):\n    pass\n"),
             "pkg/_main.py": ast.parse("def main():\n    _helper()\ndef _helper():\n    pass\n")}
    h = orphans.analyse(trees, {"goal": "", "entry_points": ["pkg:main", "pkg:Client"], "keep": []})
    assert h["findings"] == []


def test_a_library_public_api_counts_as_entry_points(tmp_path):
    rep = write(tmp_path, {
        "pyproject.toml": '[project]\nname = "lib"\nversion = "1"\nrequires-python = ">=3.11"\nlicense = "MIT"\n',
        "lib/__init__.py": "", "lib/utils.py": "def public_helper():\n    return _used()\ndef _used():\n    return 1\n"
                                               "def _unused():\n    return 2\nclass Api:\n    def call(self):\n        pass\n",
        "lib/_private.py": "def hidden():\n    pass\n",
        "tests/test_lib.py": "from lib.utils import public_helper\ndef test_x():\n    assert public_helper() == 1\n",
    })
    h = rep["hygiene"]
    assert h["source"] == "inferred (library public API)"
    assert sorted((f["code"], f["evidence"][0]) for f in h["findings"]) == [
        ("orphan.dead", "name: lib._private"), ("orphan.dead", "name: lib.utils._unused")]


def test_an_application_does_not_get_public_api_roots(tmp_path):
    rep = write(tmp_path, {"Dockerfile": "FROM x\n", "app/__init__.py": "",
                           "app/__main__.py": "from app.core import run\nrun()\n",
                           "app/core.py": "def run():\n    pass\ndef unused_public():\n    pass\n"})
    assert [f["evidence"][0] for f in rep["hygiene"]["findings"]] == ["name: app.core.unused_public"]


def test_module_dunders_reexports_and_registered_handlers_are_reached():
    from code_guardian import orphans
    trees = {
        "lib/__init__.py": ast.parse("from ._transports import *\nfrom ._client import Client\n"
                                     "def __getattr__(name):\n    raise AttributeError(name)\n"),
        "lib/_transports.py": ast.parse("__all__ = ['Transport']\nclass Transport:\n    def handle(self):\n"
                                        "        return _Stream()\nclass _Stream:\n    pass\n"),
        "lib/_client.py": ast.parse("class Client:\n    def send(self):\n        return _helper()\n"
                                    "def _helper():\n    return 1\ndef _really_unused():\n    return 2\n"),
    }
    h = orphans.analyse(trees, None, library=True)
    assert [f["evidence"][0] for f in h["findings"]] == ["name: lib._client._really_unused"]


def test_functions_registered_by_a_decorator_are_reached():
    from code_guardian import orphans
    trees = {"app.py": ast.parse("from fastapi import FastAPI\napp = FastAPI()\n"
                                 "@app.post('/x')\ndef handler():\n"
                                 "    return compute()\ndef compute():\n    return 1\ndef unused():\n    return 2\n"
                                 "def main():\n    pass\nif __name__ == '__main__':\n    main()\n")}
    h = orphans.analyse(trees)
    assert [(f["code"], f["evidence"][0]) for f in h["findings"]] == [("orphan.dead", "name: app.unused")]


def test_same_name_definitions_are_merged_not_overwritten():
    from code_guardian import orphans
    trees = {"m.py": ast.parse("class R:\n"
                               "    @property\n    def enc(self):\n        return _known()\n"
                               "    @enc.setter\n    def enc(self, v):\n        self._v = v\n"
                               "def _known():\n    return 1\ndef main():\n    return R().enc\n"
                               "if __name__ == '__main__':\n    main()\n")}
    assert orphans.analyse(trees)["findings"] == []
