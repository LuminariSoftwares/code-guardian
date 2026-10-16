"""AI-leftover checks (works.todo_stub, works.commented_code, works.dead_flag) and privacy checks
(privacy.pii_log, privacy.pii_prompt). Each is a pattern AI-assisted code leaves behind."""
import json

from code_guardian import leftovers, report, scanners


def scan(root, files):
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text, encoding="utf-8")
    return report.scan(str(root))


def found(rep, code):
    return sorted((f["level"], f["node"]) for f in rep["findings"] if f["code"] == code)


APP_MAIN = "from app import core\n\nif __name__ == '__main__':\n    core.run()\n"


# ------------------------------------------------------------------ works.todo_stub

def test_todo_stub_reachable_from_an_entry_point(tmp_path):
    rep = scan(tmp_path, {
        "app/__init__.py": "",
        "app/__main__.py": APP_MAIN,
        "app/core.py": ('def run():\n    load()\n    save()\n    parse()\n\n'
                        'def load():\n    pass\n\n'
                        'def save():\n    """Save it."""\n    raise NotImplementedError\n\n'
                        'def parse():\n    ...\n\n'
                        'def unused():\n    pass\n\n'
                        'def real():\n    return 1\n'),
    })
    assert found(rep, "works.todo_stub") == [("WARN", "app/core.py:13"), ("WARN", "app/core.py:6"),
                                             ("WARN", "app/core.py:9")]
    stub = [f for f in rep["findings"] if f["node"] == "app/core.py:6"][0]
    assert stub["summary"] == "app.core.load is a stub (its body is only pass) and an entry point reaches it"


def test_abstract_methods_protocols_and_overloads_are_not_stubs(tmp_path):
    rep = scan(tmp_path, {
        "app/__init__.py": "",
        "app/__main__.py": APP_MAIN,
        "app/core.py": ('import abc\nfrom typing import Protocol, overload\n\n'
                        'class Base(abc.ABC):\n    @abc.abstractmethod\n    def go(self):\n        pass\n\n'
                        'class Reader(Protocol):\n    def read(self) -> str:\n        ...\n\n'
                        'class Shape:\n    def area(self):\n        raise NotImplementedError\n\n'
                        'class Square(Shape):\n    def area(self):\n        return 4\n\n'
                        '@overload\ndef f(x: int) -> int: ...\n@overload\ndef f(x: str) -> str: ...\n'
                        'def f(x):\n    return x\n\n'
                        'def run():\n    Base.go\n    Reader.read\n    Square().area()\n    Shape().area()\n    f(1)\n'),
    })
    assert found(rep, "works.todo_stub") == []


def test_no_entry_points_means_no_stub_claims(tmp_path):
    rep = scan(tmp_path, {"lib.py": "def todo():\n    pass\n"})
    assert found(rep, "works.todo_stub") == []


# ------------------------------------------------------------------ works.commented_code

def test_commented_code_once_per_file_with_a_count(tmp_path):
    block = "# x = load()\n# if x:\n#     save(x)\n# for i in range(3):\n#     print(i)\n"
    prose = "# This module loads the data.\n# It is called on start.\n# Keep it fast.\n# No network here.\n# Ok.\n"
    rep = scan(tmp_path, {"app/__init__.py": "",
                          "app/a.py": prose + "\nA = 1\n\n" + block + "\nB = 2\n\n" + block + "C = 3\n",
                          "app/b.py": "# x = 1\n# y = 2\nZ = 3\n"})
    hits = [f for f in rep["findings"] if f["code"] == "works.commented_code"]
    assert [(f["level"], f["node"]) for f in hits] == [("INFO", "app/a.py:9")]
    assert hits[0]["summary"] == "2 blocks of commented-out code (5+ lines that parse as Python)"
    assert rep["scores"]["works"] == report.scan(str(tmp_path))["scores"]["works"]


def test_trivial_comment_words_are_not_code():
    lines = ["# TODO", "# fixme", "# note", "# see", "# above"]
    assert leftovers.commented_code("a.py", "\n".join(lines) + "\nx = 1\n") is None


# ------------------------------------------------------------------ works.dead_flag

def test_dead_flag_is_a_module_level_boolean_never_read(tmp_path):
    rep = scan(tmp_path, {"app/__init__.py": "",
                          "app/conf.py": "USE_CACHE = True\nDEBUG = False\nVERBOSE = False\nRETRIES = 3\n",
                          "app/run.py": "from app.conf import DEBUG\nfrom app import conf\n\nif DEBUG or conf.VERBOSE:\n"
                                        "    print('x')\n"})
    assert found(rep, "works.dead_flag") == [("INFO", "app/conf.py:1")]


# ------------------------------------------------------------------ privacy.pii_log / privacy.pii_prompt

def codes(src, fn):
    pf = scanners.PyFile("t.py", src.encode("utf-8"), src)
    return sorted((f["code"], f["level"], f["node"]) for f in fn(pf))


def test_pii_into_a_log_or_print():
    src = ("import logging\nlog = logging.getLogger(__name__)\n\n"
           "def signup(user_email, phone_number, name):\n"
           "    logging.info('new user %s', user_email)\n"
           "    log.debug(f'call {phone_number}')\n"
           "    contact = user_email\n"
           "    print('sending to', contact)\n"
           "    print('hello', name)\n"
           "    log.info('sent %d emails', 3)\n")
    assert codes(src, scanners.scan_pii_log) == [("privacy.pii_log", "WARN", "t.py:5"),
                                                ("privacy.pii_log", "WARN", "t.py:6"),
                                                ("privacy.pii_log", "WARN", "t.py:8")]


def test_pii_name_matching():
    assert all(scanners.pii_name(n) for n in ("email", "user_email", "phoneNumber", "ssn", "dob", "date_of_birth",
                                              "birthday", "home_address", "passport_no", "credit_card",
                                              "card_number", "iban", "ip_address", "clientIpAddress"))
    assert not any(scanners.pii_name(n) for n in ("emails_sent", "server_address", "bind_address", "mac_address",
                                                  "addressee", "cardinal", "phones_count", "name"))


def test_pii_into_an_llm_prompt():
    src = ("def ask(client, user, ssn):\n"
           "    client.chat.completions.create(model='m', messages=[{'role': 'user', 'content': user.email}])\n"
           "    prompt = 'customer ssn: ' + ssn\n"
           "    client.generate(prompt)\n"
           "    client.complete(prompt='hello')\n"
           "    client.chat(messages=[{'role': 'user', 'content': 'hi'}])\n")
    assert codes(src, scanners.scan_pii_prompt) == [("privacy.pii_prompt", "WARN", "t.py:2"),
                                                   ("privacy.pii_prompt", "WARN", "t.py:4")]


def test_privacy_findings_are_safe_scored_and_info_in_tests(tmp_path):
    rep = scan(tmp_path, {"app/__init__.py": "",
                          "app/m.py": "import logging\ndef f(email):\n    logging.info(email)\n",
                          "tests/test_m.py": "def test_f(email='a'):\n    print(email)\n    assert email\n"})
    assert found(rep, "privacy.pii_log") == [("INFO", "tests/test_m.py:2"), ("WARN", "app/m.py:3")]
    assert rep["scores"]["safe"] == 95
    ev = [f for f in rep["findings"] if f["code"] == "privacy.pii_log" and f["level"] == "WARN"][0]["evidence"]
    assert ev == ["name: email", "sink: logging.info"]
    assert "privacy.pii_log" in json.dumps(rep["weights"])


def test_calibration_patterns_are_not_stubs(tmp_path):
    """Found by scanning the calibration repos (calibration.md): each is a deliberate no-op, not a leftover.
    Protocol[T] (requests, flask), dunder no-ops (click __exit__, flask __enter__), null objects (rich NullFile,
    requests MockRequest) and click group callbacks."""
    rep = scan(tmp_path, {
        "app/__init__.py": "",
        "app/__main__.py": APP_MAIN,
        "app/core.py": ('import typing as t\nimport click\nfrom typing import Protocol, TypeVar\nT = TypeVar("T")\n\n'
                        'class SupportsRead(Protocol[T]):\n    def read(self) -> T: ...\n\n'
                        'class Proxy(t.Protocol[T]):\n    def get(self) -> T: ...\n\n'
                        'class KeepOpen:\n    def __enter__(self):\n        return self\n'
                        '    def __exit__(self, *a):\n        pass\n\n'
                        'class NullFile:\n    def flush(self):\n        pass\n\n'
                        'class MockRequest:\n    def add_header(self, k, v):\n        raise NotImplementedError("no")\n\n'
                        '@click.group()\ndef cli():\n    pass\n\n'
                        'def run():\n    SupportsRead.read\n    Proxy.get\n    with KeepOpen():\n        pass\n'
                        '    NullFile().flush()\n    MockRequest().add_header(1, 2)\n    cli()\n'),
    })
    assert found(rep, "works.todo_stub") == []
