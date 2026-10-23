# 0008. Settings live in the browser; dark is the default; the address is stable

Status: accepted (unreleased, plan P78 section S1). Recorded 2026-10-23.

## Context

`code-guardian ui` was dark only, one text size, and its address changed on every start (`--port 0`, any free port).
The people it is for use an AI to write code and cannot read code well; some of them cannot read small light-on-dark
text, or want a light page, and they should not have to set that up again each time. A setting has to be kept
somewhere, and the page has no server-side user: the server is one process on `127.0.0.1` with a per-run token
([0007](0007-plain-language-layer-never-scores.md)).

## Decision

**Settings live in the browser.** The page keeps three choices, theme (`dark` or `light`), text size (`normal`,
`larger`, `largest`) and the Luminari name (`on` or `off`), as one JSON object under `localStorage["cg.settings"]`.
It is read inside `try/catch`: a browser that refuses storage, an empty store, text that is not JSON and a value the
page does not know all mean the defaults, and the panel still works for the visit. The key is the only thing the page
stores; the token is never written. The server reads and writes no settings file: the choice belongs to a person's
browser profile, not to the machine that runs code-guardian, and nothing about it crosses the network. Adding a
setting later is one entry in `SETTINGS` in `app.js` and one `<fieldset data-setting>` in `index.html`.

**Dark is the default and the page never detects the system theme.** `<html data-theme="dark" data-size="normal">`
is what a page with no saved choice shows, with no script at all. Light is something a person chooses in Settings.
There is no `prefers-color-scheme` query for light anywhere in the page (a test greps for it), so the pictures in
the docs are what a first-time reader sees, whatever their operating system is set to. The `<meta name="color-scheme">`
follows the theme, so the browser draws its own controls and scroll bars to match.

**Both palettes pass one gate.** `app.css` has two token blocks, `:root` (dark) and `:root[data-theme="light"]`, with
the same 19 names; every colour the page draws is a token, none is written anywhere else. `tools/contrast_check.py`
checks every pair the page draws in every block (text 4.5:1, large labels and marks 3:1) and prints
`ok: <n> pairs in <k> palettes`, or one line per failing pair naming its palette. Font sizes are `rem`, so the three
text sizes are one `font-size` on `<html>` (`100%`, `112.5%`, `125%`).

**The default port exists so the browser keeps its settings.** `localStorage` belongs to an origin, and the port is
part of it: a page served from a different port starts with nothing. `make_server()` therefore tries `8765` to
`8775` in order and only then any free port; `make_server(port=0)` and `--port N` are unchanged, and so is the
printed `code-guardian ui: open http://127.0.0.1:<port>/#t=<token>` line. Walking on is what lets two copies run at
once; the second one has its own address and so its own, empty, settings.

**Port reuse differs on Windows.** A server that closes a connection first leaves that port in TIME_WAIT for about a
minute. On Linux and macOS a restart cannot bind it again unless the listening socket sets `SO_REUSEADDR`, so
without it a restart lands on the next port and every setting is lost; with it, a restart gets the same port back.
POSIX `SO_REUSEADDR` never lets two listeners share a port, so a port that is in use is still skipped. On Windows
`SO_REUSEADDR` means something else: it lets another process bind the port while this one is listening. Windows
does not block a bind because of TIME_WAIT in the first place, so it is left off there:
`allow_reuse_address = os.name != "nt"`.

**The Luminari mark is markup, and its slot is empty.** The name is an `<a id="luminari">` with a plain link and
`rel="noopener noreferrer"` in the page header, beside an `<svg id="luminari-mark">` that holds nothing yet and takes
no room until it does. A mark will be drawn inside it as inline SVG and coloured through classes from
`--brand-1`, `--brand-2` and `--brand-3`; it carries no colours of its own, which keeps it inside the gate and the
CSP (`img-src 'self'`, no inline styles). The link is never fetched. The third Settings choice hides it.

**Settings are applied before the first paint.** The CSP forbids an inline script, so the usual trick of setting the
theme from the `<head>` is not available. `app.js` is loaded in the `<head>` with `defer blocking="render"` and applies
the saved choices before it does anything else. A deferred script alone ran after the first paint in 3 of 60 loads
in Chromium (a one-frame dark flash for someone who chose light); with `blocking="render"` the same measurement gave
0 of 60. A browser that does not know `blocking` treats the script as `defer`.

## Alternatives

- **A settings file written by the server:** one file per machine, shared by everyone who uses that account, and a
  place on disk the page's server otherwise never writes to (it only makes per-scan temporary copies). Rejected.
- **Follow the operating system's light/dark setting:** the choice is made for a person, and the screenshots and docs
  stop describing what they see. Rejected; light stays a choice.
- **A cookie:** sent with every request and visible to the server, which has no use for it. Rejected.
- **Keep the random port and carry the settings in the link's fragment:** the fragment holds a per-run token on
  purpose and changes each time. Rejected.
- **One fixed port, failing when it is taken:** breaks the second copy and any other program on that port. The walk
  costs nothing.
- **Loosen the CSP to allow one inline script:** it would end the page's "no inline script, no outside request" rule
  for a single frame. Rejected.

## Consequences

- Settings do not follow a person to another browser, profile or computer, and clearing site data resets them.
- Two copies running at once, or a busy `8765`, mean a different address and so empty settings for that run. If all
  eleven are busy the server falls back to any free port; the page works, it just does not remember.
- A restart gets the same port back on Linux, macOS and Windows; `tests/test_ui_page.py` pins that with a real
  connection and the acceptance file with a real browser.
- Every new colour is a token in two blocks, or the acceptance test for the same 19 names fails; every new pair that
  the page draws goes into `PAIRS` in the gate.
- The panel's last line says more options will come; each one is one `SETTINGS` entry and one fieldset, and a
  value the page does not know is the default, so an older saved object never breaks a newer page.
