"""The threat score: a fixed weight per (code, level), summed and capped. No model, no randomness, no clock.

Public contract:
    WEIGHTS                        # {(code, level): points}; anything not listed weighs 0
    weight(finding) -> int
    grade(score) -> "A".."F"       # A 0-9 · B 10-24 · C 25-49 · D 50-74 · F 75+
    threat(findings, top=5) -> {"score", "raw", "grade", "top": [{"weight", "code", "level", "node", "summary"}]}
    node_key(node) -> sortable key for "file:line"
"""

import sys

from .finding import make_finding, summarize

# Documented in the README's scanner table: change both together.
WEIGHTS = {
    ("secret.key", "FAIL"): 40,
    ("exec.dynamic", "WARN"): 10,
    ("exec.shell", "WARN"): 10,
    ("exec.shell", "FAIL"): 30,
    ("deser.unsafe", "WARN"): 10,
    ("net.egress", "INFO"): 0,
    ("net.egress", "WARN"): 2,
    ("net.bind_all", "WARN"): 5,
    ("tls.off", "FAIL"): 25,
    ("install.hook", "WARN"): 15,
    ("obfuscation", "WARN"): 10,
    ("obfuscation", "FAIL"): 40,
    ("fs.outside", "WARN"): 3,
    ("deps.unpinned", "INFO"): 0,
}
GRADES = ((75, "F"), (50, "D"), (25, "C"), (10, "B"), (0, "A"))
CAP = 100


def weight(f):
    return WEIGHTS.get((f.get("code"), f.get("level")), 0)


def grade(score):
    for floor, letter in GRADES:
        if score >= floor:
            return letter
    return "A"


def node_key(node):
    """("pkg/a.py", 12) for "pkg/a.py:12", so line 9 sorts before line 10."""
    path, _, line = str(node).rpartition(":")
    return (path, int(line)) if line.isdigit() else (str(node), 0)


def sort_findings(findings):
    return sorted(findings, key=lambda f: (node_key(f["node"]), f["code"], f["summary"]))


def threat(findings, top=5):
    raw = sum(weight(f) for f in findings)
    score = min(CAP, raw)
    ranked = sorted((f for f in findings if weight(f) > 0), key=lambda f: (-weight(f), node_key(f["node"]), f["code"]))
    return {"score": score, "raw": raw, "grade": grade(score),
            "top": [{"weight": weight(f), "code": f["code"], "level": f["level"], "node": f["node"],
                     "summary": f["summary"]} for f in ranked[:top]]}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if "--selftest" in argv:
        return selftest()
    sys.stderr.write("usage: python -m code_guardian.score --selftest\n")
    return 2


def selftest():
    def f(code, level, node):
        return make_finding(code, "partial", level, node, "s")

    many = [f("secret.key", "FAIL", "a.py:%d" % i) for i in range(1, 4)]
    mixed = [f("net.egress", "INFO", "a.py:1"), f("fs.outside", "WARN", "b.py:10"), f("fs.outside", "WARN", "b.py:9"),
             f("tls.off", "FAIL", "c.py:2"), f("unknown.code", "FAIL", "d.py:1")]
    t = threat(mixed)
    checks = [
        ("grades", [grade(s) for s in (0, 9, 10, 24, 25, 49, 50, 74, 75, 100)] ==
         ["A", "A", "B", "B", "C", "C", "D", "D", "F", "F"]),
        ("sum", t["raw"] == 31 and t["score"] == 31 and t["grade"] == "C"),
        ("cap", threat(many)["raw"] == 120 and threat(many)["score"] == 100 and threat(many)["grade"] == "F"),
        ("top_order", [x["node"] for x in t["top"]] == ["c.py:2", "b.py:9", "b.py:10"]),
        ("top_limit", len(threat(many, top=2)["top"]) == 2),
        ("empty", threat([]) == {"score": 0, "raw": 0, "grade": "A", "top": []}),
        ("node_key", node_key("x/y.py:10") == ("x/y.py", 10) and node_key("odd") == ("odd", 0)),
        ("weights_levels", all(level in ("OK", "INFO", "WARN", "FAIL") for _, level in WEIGHTS)),
    ]
    return summarize("score", checks)


if __name__ == "__main__":
    sys.exit(main())
