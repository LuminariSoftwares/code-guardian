# 0009. The folder window runs in a child process; some folders are refused; re-open never reads; loopback only

Status: accepted (unreleased, plan P78 section S4). Recorded 2026-10-23.

## Context

`code-guardian ui` asked for a folder by its typed or pasted path. The people it is for use an AI to write code and
cannot read code well; many of them do not know how to copy a folder's path, and some will pick the first folder they
recognise, such as `C:\`, their home folder or Downloads. Checking one of those reads thousands of files that are not
a project, takes minutes, and puts the names of private files on the screen. Two questions follow: how a browser page
can open the computer's own folder window, and which folders the app should not check as a whole. A third was asked
alongside them: whether the page could be opened from a phone.

## Decision

**The folder window is the computer's own, opened in a child process.** A page cannot open a folder window on the
machine that runs the server, so `POST /api/browse` does it: it runs
`[sys.executable, "-I", "-c", DIALOG_SOURCE, start or home]` with `capture_output=True, text=True, encoding="utf-8", timeout=600`.
`DIALOG_SOURCE` is a constant in `ui.py` of at most 25 lines that imports `tkinter`, makes a hidden root window,
raises it to the top (`-topmost`, `update`, `lift`, `focus_force`) and calls `tkinter.filedialog.askdirectory`. It
prints the folder and exits 0, or exits 1 when the window was closed without a choice, 3 when this Python has no
`tkinter`, 4 when there is no display to open a window on. The child writes the folder as UTF-8 and the server reads
it as UTF-8, so a folder name in any language comes through. The server maps 0 to the folder, 1 and a timeout to `{"path": null, "cancelled": true}`, 3 and 4
to `501 no_dialog` with the reason, and anything else to `501` with the exit code.

It is a child process because tkinter wants to own the main thread of the process that imports it, and the server
answers every request on its own thread (`ThreadingHTTPServer`). Importing tkinter there would tie a GUI loop to
a request thread and, on macOS, fail outright. In a child, the server's threads never touch tkinter: a request thread
waits on the child and every other request keeps being answered. `-I` keeps the child from reading the current folder
or `PYTHON*` variables. Only one window is open at a time: a module lock, and a second request while one is open gets
`409 busy`. The runner is `Server.dialog_runner` (default `subprocess.run`), so tests and `ui --selftest` pass a fake
and never open a real window; the real one is clicked by the owner on Windows (plan P76 S6).

**Some folders are refused, before anything is read.** `refuse.refused(path)` (plan P78 C5, S4a) returns one plain
sentence for a folder nobody should check as a whole, or `None`. It is applied in three places: `Server.scan`, which
answers `400 {"error": "refused", "detail": <sentence>}` before it lists or reads anything and before the check is
added to the list of checks; the folder Browse returns, as `{"path": ..., "refused": <sentence>}`; and
`code-guardian ui PATH`, which prints `code-guardian: <sentence>` and exits 2 before it opens a socket. A path that is
an existing single file is never refused. `code-guardian scan` is not changed: a person who types a command line in a
terminal has chosen the folder on purpose, and CI scans its checkout root.

The order is fixed and the first match wins: a whole drive (a drive letter, a UNC share, `/`, any mount point); the
home folder; a folder that contains the home folder (`/home`, `C:\Users`); Downloads, Desktop and Documents directly
under home, `XDG_DOWNLOAD_DIR` and the OneDrive root; then the operating system's own folders (`/usr`, `/etc`,
`/System`, `C:\Windows`, Program Files, ProgramData and the like). A folder *inside* Downloads or Documents is allowed:
that is where many projects live.

Deliberately not on the list: `/tmp`, `/var`, `/opt`, `/private/var`, `%TEMP%` and AppData. Temporary folders live
there on macOS and Windows (the tests and the single-file copy use them), and a project may live in `/opt`. Refusing
them would refuse real projects; the list is for the folders a beginner picks by mistake, not every folder that is not
a project.

**Re-open never reads files, and `POST /api/scan` is the only route that reads a folder.** Every way of checking a
folder, the typed path, the Browse answer and the folder named on the command line, ends in the same `Server.scan`,
so the refusal is in one place and cannot be skipped. `/api/browse` only names a folder; it does not read it. Re-opening
an earlier check (built in section S5) shows what was kept from that check and does not list or read the folder
again; reading it again is "Check again", which is `POST /api/scan`, refusal included.

**The server keeps binding `127.0.0.1`.** `HOST = "127.0.0.1"` is unchanged: nothing listens on any other address.
Using the page from a phone is done with a tunnel the person already trusts (for example an SSH or VPN tunnel to their
own computer) that ends on `127.0.0.1` there; the Host / Origin guard and the per-run token still apply. A listener
beyond loopback would need TLS, real authentication and a decision about who may open a folder window on the computer;
that is a separate opt-in decision, a candidate for v1.2, not part of this one.

## Alternatives

- **A folder picker in the page (`<input type="file" webkitdirectory>`):** the browser uploads the files instead of
  naming the folder, and the server would have to receive a copy of a whole project. Rejected.
- **Import tkinter in the server process:** ties a GUI loop to a request thread; fails on macOS. Rejected.
- **A third-party picker, Electron, or a PowerShell / `osascript` shell-out:** a dependency or a second language for
  one window, and `dependencies = []` stays empty. Rejected; if the window cannot come to the front, Browse is dropped
  and the refusals ship without it.
- **Warn instead of refuse:** a person who cannot read code clicks through a warning. The refusal says what to pick
  instead.
- **Refuse in `code-guardian scan` too:** breaks CI and scripts that scan a checkout at `/` in a container. Rejected.
- **Listen on all interfaces for the phone:** anyone on the same network could reach a page that reads folders. Not
  without TLS and authentication, and not in this decision.

## Consequences

- A Python without tkinter (some Linux packages, some embedded builds) answers `501`; the page hides Browse for the
  session and says to paste the path instead. Pasting always works.
- A folder window left open holds the lock for up to ten minutes; a second Browse in that time is `409 busy`, and the
  page says a window is already open.
- A project placed directly at a drive root or a mount point is refused; the sentence asks for the folder it is in.
- `ui --selftest` checks the 501, 409 and refusal paths through a fake runner; it never starts a process.
- Reaching the page from a phone stays a tunnel the person sets up; the app documents nothing beyond loopback.
