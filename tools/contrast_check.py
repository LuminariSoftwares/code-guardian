"""Check the page's colour pairs against WCAG 2.x contrast (plan P76 contract C10).

Reads the :root custom properties of the stylesheet given as the argument, computes the WCAG 2.x relative luminance
of each, and checks every foreground/background pair the page draws: text >= 4.5:1, large labels and non-text marks
>= 3:1. Standard library only.

    python tools/contrast_check.py code_guardian/ui/app.css
    -> "ok: <n> pairs ..." and exit 0, or one line per failing pair and exit 1
"""
import re
import sys

TEXT = 4.5
LARGE = 3.0
# Every text colour the page uses, on every surface it is drawn on. The level colours and the accent are also used
# for small text (the level word on a card, links), so they are held to the text ratio, not only the large one.
TEXT_FG = ("--text", "--muted", "--high", "--medium", "--low", "--ok", "--accent")
TEXT_BG = ("--bg", "--surface", "--surface-2")
PAIRS = ([(fg, bg, TEXT, "text") for fg in TEXT_FG for bg in TEXT_BG]
         + [("--text", "--hl", TEXT, "text on the jumped-to line"),
            ("--muted", "--hl", TEXT, "line number on the jumped-to line"),
            ("--on-accent", "--accent", TEXT, "text on the main button")]
         + [(fg, bg, LARGE, "large label") for fg in ("--high", "--medium", "--low", "--ok", "--accent")
            for bg in ("--bg", "--surface")]
         + [("--focus", bg, LARGE, "focus ring") for bg in TEXT_BG])


def root_tokens(css):
    """{name: value} from the first :root block; {} when there is none."""
    m = re.search(r":root\s*\{(.*?)\}", css, re.S)
    if not m:
        return {}
    return {k: v.strip() for k, v in re.findall(r"(--[\w-]+)\s*:\s*([^;]+);", m.group(1))}


def parse(value):
    """(r, g, b) from #rgb, #rrggbb or rgb(r, g, b); None for anything else."""
    v = value.strip().lower()
    m = re.fullmatch(r"#([0-9a-f]{3}|[0-9a-f]{6})", v)
    if m:
        h = m.group(1)
        if len(h) == 3:
            h = "".join(c * 2 for c in h)
        return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))
    m = re.fullmatch(r"rgb\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*\)", v)
    if m and all(int(x) <= 255 for x in m.groups()):
        return tuple(int(x) for x in m.groups())
    return None


def luminance(rgb):
    def channel(x):
        x = x / 255.0
        return x / 12.92 if x <= 0.04045 else ((x + 0.055) / 1.055) ** 2.4
    r, g, b = (channel(x) for x in rgb)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def ratio(a, b):
    hi, lo = sorted((luminance(a), luminance(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def check(css):
    """(passed, failed): lists of (fg, bg, need, got, use); got is None when a token is missing or unreadable."""
    tokens = root_tokens(css)
    passed, failed = [], []
    for fg, bg, need, use in PAIRS:
        a, b = parse(tokens.get(fg, "")), parse(tokens.get(bg, ""))
        got = None if a is None or b is None else ratio(a, b)
        (passed if got is not None and got >= need else failed).append((fg, bg, need, got, use))
    return passed, failed


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        sys.stderr.write("usage: python tools/contrast_check.py path/to/app.css\n")
        return 2
    with open(argv[0], encoding="utf-8") as fh:
        passed, failed = check(fh.read())
    if failed:
        for fg, bg, need, got, use in failed:
            shown = "missing or not #rrggbb" if got is None else "%.2f:1" % got
            print("fail: %s on %s is %s, needs %.1f:1 (%s)" % (fg, bg, shown, need, use))
        print("%d of %d pairs fail" % (len(failed), len(PAIRS)))
        return 1
    low = min(passed, key=lambda p: p[3] / p[2])
    print("ok: %d pairs meet WCAG 2.x contrast (text >= %.1f:1, large labels >= %.1f:1); closest: %s on %s %.2f:1"
          % (len(passed), TEXT, LARGE, low[0], low[1], low[3]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
