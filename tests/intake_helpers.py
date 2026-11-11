"""Helpers for the repo-intake tests. Every fixture is built at test time from benign strings: nothing here is real
malware, nothing is downloaded, and the invisible characters are made with chr() so this file (and the project's own
self-scan) never contains them."""
import os

ZWSP = chr(0x200B)
RLO = chr(0x202E)
TAG_A = chr(0xE0041)


def mk(root, files):
    """Create {relative path: str or bytes} under root; return root as a string."""
    root = str(root)
    for rel, data in files.items():
        full = os.path.join(root, *rel.split("/"))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as fh:
            fh.write(data if isinstance(data, bytes) else data.encode("utf-8"))
    return root


def rules_of(result):
    return sorted({f["rule"] for f in result["findings"]})


def of(result, rule):
    return [f for f in result["findings"] if f["rule"] == rule]
