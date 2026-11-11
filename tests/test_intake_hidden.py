"""Repo intake, item 2: hidden code. Synthetic, benign strings only."""
import base64
import hashlib

from code_guardian import intake, intake_rules as R
from intake_helpers import mk, of


def scan(tmp_path, files):
    return intake.scan(mk(tmp_path / "repo", files))


def blob(n=420):
    raw = b"".join(hashlib.sha256(b"seed%d" % i).digest() for i in range(n // 40 + 2))
    return base64.b64encode(raw).decode()[:n]


def test_entropy_helper():
    assert R.entropy("A" * 100) == 0
    assert R.entropy("ab" * 50) == 1.0
    assert R.entropy(blob(400)) > 5


# ---- very long lines ---------------------------------------------------------------------------------------------

def test_very_long_code_lines(tmp_path):
    long_line = "var a = 1; " * 300 + "\n"
    res = scan(tmp_path, {"app.js": long_line, "lib.min.js": long_line, "data.json": '{"a": "%s"}\n' % ("x" * 5000),
                          "short.js": "var a = 1; " * 100 + "\n", "t.py": "x = [" + "1, " * 900 + "]\n"})
    got = {f["file"]: (f["confidence"], f["line"]) for f in of(res, "hidden.long_line")}
    assert got == {"app.js": ("medium", 1), "lib.min.js": ("low", 1), "t.py": ("medium", 1)}
    assert of(res, "hidden.long_line")[0]["match"].startswith("(3300 characters) var a = 1;")


# ---- whitespace padding ------------------------------------------------------------------------------------------

def test_code_pushed_far_right_with_padding(tmp_path):
    pad = " " * 250
    res = scan(tmp_path, {
        "a.js": "var ok = 1;" + pad + "eval(payload);\nvar fine = 2;\n",
        "b.py": "x = 1" + "\t" * 200 + "; y = 2\n",
        "c.py": pad + "z = 3\n",
        "d.py": "x = 1\n" + " " * 300 + "\n",
        "e.py": "x = 1" + " " * 20 + "# comment\n",
    })
    got = {f["file"]: (f["confidence"], f["line"]) for f in of(res, "hidden.whitespace_pad")}
    assert got == {"a.js": ("high", 1), "b.py": ("medium", 1), "c.py": ("medium", 1)}
    m = of(res, "hidden.whitespace_pad")[0]["match"]
    assert "[250 whitespace characters]" in m and "eval(payload);" in m and m.startswith("var ok = 1;")


# ---- oversized single source file --------------------------------------------------------------------------------

def test_oversized_source_file(tmp_path):
    res = scan(tmp_path, {"big.py": "x = 1\n" * 200_000, "ok.py": "x = 1\n" * 1000, "big.json": "1\n" * 700_000})
    assert [(f["file"], f["confidence"]) for f in of(res, "hidden.oversized_file")] == [("big.py", "medium")]
    assert "1.2 MB" in of(res, "hidden.oversized_file")[0]["match"]


# ---- high-entropy blobs ------------------------------------------------------------------------------------------

def test_high_entropy_blob(tmp_path):
    b = blob(420)
    res = scan(tmp_path, {
        "a.py": 'PAYLOAD = "%s"\n' % b,
        "b.py": 'PAD = "%s"\n' % ("A" * 420),
        "c.css": 'src: url("data:font/woff2;base64,%s")\n' % b,
        "d.py": '# %s\n' % "the quick brown fox jumps over the lazy dog " * 12,
        "e.txt": "%s\n" % b,
    })
    got = {f["file"]: (f["confidence"], f["line"]) for f in of(res, "hidden.high_entropy")}
    assert got == {"a.py": ("medium", 1)}
    assert "420 chars" in of(res, "hidden.high_entropy")[0]["match"] and "bits/char" in of(res, "hidden.high_entropy")[0]["match"]


# ---- encoded data fed to exec / eval -----------------------------------------------------------------------------

def test_blob_fed_to_exec(tmp_path):
    b = blob(120)
    res = scan(tmp_path, {
        "a.py": "import base64\nexec(base64.b64decode('%s'))\n" % b,
        "b.js": "eval(atob('%s'));\n" % b,
        "c.py": "import zlib, base64\nexec(zlib.decompress(base64.b64decode('%s')))\n" % b,
        "d.py": "exec(bytes.fromhex('%s'))\n" % "6f73".ljust(60, "0"),
        "e.js": "eval(Buffer.from('%s', 'base64').toString());\n" % b,
        "f.py": "import base64\nvalue = base64.b64decode('%s')\nprint(value)\n" % b,
        "g.py": "exec(open('plan.txt').read())\n",
        "h.py": "import base64\nexec(base64.b64decode(data))\n",
        "i.ps1": "iex ([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s')))\n" % b,
    })
    got = {f["file"]: (f["confidence"], f["line"]) for f in of(res, "hidden.blob_to_exec")}
    assert got == {"a.py": ("high", 2), "b.js": ("high", 1), "c.py": ("high", 2), "d.py": ("high", 1),
                   "e.js": ("high", 1), "h.py": ("medium", 2), "i.ps1": ("high", 1)}
