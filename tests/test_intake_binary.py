"""Repo intake, item 4: Windows executables (MZ/PE) and other binaries under the wrong name, and embedded executables."""
import base64
import struct

from code_guardian import intake
from intake_helpers import mk, of


def pe(extra=600):
    """A minimal, harmless byte string with a valid DOS header and a PE signature (not runnable, not real malware)."""
    head = bytearray(b"MZ" + b"\0" * 62)
    head[0x3C:0x40] = struct.pack("<I", 0x80)
    return bytes(head) + b"\0" * 64 + b"PE\0\0" + b"\0" * extra


ELF = b"\x7fELF" + b"\x02\x01\x01" + b"\0" * 200
MACHO = bytes([0xCF, 0xFA, 0xED, 0xFE]) + b"\0" * 200
JAVA_CLASS = bytes([0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 0x34]) + b"\0" * 100


def scan(tmp_path, files):
    return intake.scan(mk(tmp_path / "repo", files))


def test_executables_under_non_executable_names_are_high(tmp_path):
    res = scan(tmp_path, {"img/logo.png": pe(), "docs/readme.txt": ELF, "a/photo.jpg": MACHO, "invoice.pdf.exe": pe(),
                          "data.json": pe()})
    got = {f["file"]: f["confidence"] for f in of(res, "binary.disguised_executable")}
    assert got == {"img/logo.png": "high", "docs/readme.txt": "high", "a/photo.jpg": "high", "invoice.pdf.exe": "high",
                   "data.json": "high"}
    f = [x for x in of(res, "binary.disguised_executable") if x["file"] == "img/logo.png"][0]
    assert "Windows executable (PE)" in f["match"] and f["match"].startswith("4d5a")


def test_embedded_executables_by_kind(tmp_path):
    res = scan(tmp_path, {"tools/setup.exe": pe(), "lib/native.dll": pe(), "lib/native.so": ELF, "bin/server": ELF,
                          "Fake.class": JAVA_CLASS, "plain.bin": b"\x00\x01\x02" * 50, "text.txt": "MZ is a prefix\n"})
    got = {f["file"]: f["confidence"] for f in of(res, "binary.embedded_executable")}
    assert got == {"tools/setup.exe": "medium", "lib/native.dll": "low", "lib/native.so": "low", "bin/server": "medium"}
    assert of(res, "binary.disguised_executable") == []


def test_an_executable_hidden_as_text_inside_a_source_file(tmp_path):
    b64 = base64.b64encode(pe(2000)).decode()
    hexed = pe(2000).hex()
    res = scan(tmp_path, {"loader.py": 'DATA = "%s"\n' % b64, "notes.txt": "%s\n" % hexed, "ok.py": 'DATA = "%s"\n' % base64.b64encode(b"hi" * 400).decode()})
    got = {f["file"]: f["confidence"] for f in of(res, "binary.embedded_executable")}
    assert got == {"loader.py": "high", "notes.txt": "high"}
    assert "base64" in of(res, "binary.embedded_executable")[0]["summary"] or "hex" in of(res, "binary.embedded_executable")[0]["summary"]
