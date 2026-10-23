"""Check the page's colour pairs against WCAG 2.x contrast (plan P76 contract C10, P78 contract C2).

Reads the colour tokens of every palette in the stylesheet given as the argument -- the bare :root block ("dark") and
each :root[data-theme="..."] block -- computes the WCAG 2.x relative luminance of each, and checks every
foreground/background pair the page draws in each palette: text >= 4.5:1, large labels and non-text marks >= 3:1.
Standard library only.

    python tools/contrast_check.py code_guardian/ui/app.css
    -> "ok: <n> pairs in <k> palettes" and exit 0, or one line per failing pair naming its palette and exit 1
"""
import re
import sys

TEXT = 4.5
LARGE = 3.0
# Every text colour the page uses, on every surface it is drawn on. The level colours and the accent are also used
# for small text (the level word on a card, links), so they are held to the text ratio, not only the large one.
TEXT_FG = ("--text", "--muted", "--high", "--medium", "--low", "--ok", "--none", "--accent")
TEXT_BG = ("--bg", "--surface", "--surface-2")
PAIRS = ([(fg, bg, TEXT, "text") for fg in TEXT_FG for bg in TEXT_BG]
         + [("--text", "--hl", TEXT, "text on the jumped-to line"),
            ("--muted", "--hl", TEXT, "line number on the jumped-to line"),
            ("--on-accent", "--accent", TEXT, "text on the main button")]
         + [(fg, bg, LARGE, "large label") for fg in ("--high", "--medium", "--low", "--ok", "--none", "--accent")
            for bg in ("--bg", "--surface")]
         + [("--focus", bg, LARGE, "focus ring") for bg in TEXT_BG]
         # the Luminari mark sits in the header (--surface) and may sit on the page (--bg); its colours are --brand-*
         + [("--brand-3", bg, LARGE, "brand mark") for bg in ("--bg", "--surface")])
BLOCK = re.compile(r':root(?:\[data-theme="([^"]*)"\])?\s*\{(.*?)\}', re.S)


def blocks(css):
    """[(name, tokens), ...] for every palette, in file order: "dark" for the bare :root, the attribute value for
    :root[data-theme="..."]; tokens is {name: value}. [] when the file has no palette."""
    return [(theme or "dark", {k: v.strip() for k, v in re.findall(r"(--[\w-]+)\s*:\s*([^;]+);", body)})
            for theme, body in BLOCK.findall(css)]


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
    """(passed, failed): lists of (palette, fg, bg, need, got, use); got is None when a token is missing or
    unreadable. A file with no palette fails every pair."""
    passed, failed = [], []
    for name, tokens in blocks(css) or [("dark", {})]:
        for fg, bg, need, use in PAIRS:
            a, b = parse(tokens.get(fg, "")), parse(tokens.get(bg, ""))
            got = None if a is None or b is None else ratio(a, b)
            (passed if got is not None and got >= need else failed).append((name, fg, bg, need, got, use))
    return passed, failed


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        sys.stderr.write("usage: python tools/contrast_check.py path/to/app.css\n")
        return 2
    with open(argv[0], encoding="utf-8") as fh:
        css = fh.read()
    passed, failed = check(css)
    if failed:
        for name, fg, bg, need, got, use in failed:
            shown = "missing or not #rrggbb" if got is None else "%.2f:1" % got
            print("fail: %s: %s on %s is %s, needs %.1f:1 (%s)" % (name, fg, bg, shown, need, use))
        print("%d of %d pairs fail" % (len(failed), len(passed) + len(failed)))
        return 1
    low = min(passed, key=lambda p: p[4] / p[3])
    print("ok: %d pairs in %d palettes" % (len(passed), len(blocks(css))))
    print("closest: %s: %s on %s %.2f:1 (needs %.1f:1)" % (low[0], low[1], low[2], low[4], low[3]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
