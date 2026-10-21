"""code-guardian command line.

    code-guardian scan PATH [--json | --sarif | --markdown] [--goal FILE] [--explain] [--online] [--fail-on LEVEL]
                           [--baseline FILE] [--history [--history-depth N]]
    code-guardian baseline PATH [--out FILE] [--goal FILE]     # default FILE: PATH/code-guardian.baseline.json
    code-guardian diff BEFORE.json AFTER.json [--json]         # exit 1 when anything regressed
    code-guardian plan PATH [--top 10] [--json] [--goal FILE]  # Markdown by default
    code-guardian orphans PATH [--json] [--goal FILE] [--fail-on LEVEL]
    code-guardian init [PATH] [--force]
    code-guardian mcp                      # the MCP server on stdio (same as code-guardian-mcp)

Exit codes: 0 nothing at or above --fail-on (default FAIL); 1 findings at or above it; 2 usage or parse error;
3 (scan only) the scan is incomplete (PARTIAL or INVALID) and nothing is at or above --fail-on; coverage alone
(no Python source, or mostly other languages) is reported as PARTIAL but never gives 3.
scan gates on every scored finding (Safe, Works, Complete); orphans gates on the hygiene findings.
"""

import argparse
import json
import os
import shutil
import sys
import tempfile

from . import __version__, baseline, goal, outputs, report, verify
from .finding import summarize
from .scanners import redact_report


def _parser():
    p = argparse.ArgumentParser(prog="code-guardian", description="Is this codebase safe to run, and is all of it used?")
    p.add_argument("--version", action="version", version="code-guardian %s" % __version__)
    sub = p.add_subparsers(dest="command")
    fail_on = {"default": "FAIL", "type": str.upper, "choices": ["INFO", "WARN", "FAIL"],
               "help": "exit 1 when any finding is at or above this level (default FAIL)"}
    s = sub.add_parser("scan", help="Safe, Works and Complete scores, findings, egress inventory and orphan hygiene")
    s.add_argument("path")
    fmt = s.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="print the report as JSON")
    fmt.add_argument("--sarif", action="store_true", help="print SARIF 2.1.0 (for GitHub code scanning)")
    fmt.add_argument("--markdown", action="store_true", help="print a Markdown report (for a PR comment or job summary)")
    s.add_argument("--goal", metavar="FILE", help="goal contract (default PATH/%s if present)" % goal.FILENAME)
    s.add_argument("--explain", action="store_true", help="add a plain-English explanation from a local model")
    s.add_argument("--online", action="store_true",
                   help="ask PyPI whether unknown dependency names exist (network; off by default)")
    s.add_argument("--baseline", metavar="FILE",
                   help="mark findings new or known against FILE (from `code-guardian baseline`); --fail-on then "
                        "counts new findings only, the scores still count all of them")
    s.add_argument("--history", action="store_true",
                   help="also check the lines git history added for key shapes (runs git log, read-only)")
    s.add_argument("--history-depth", type=int, default=500, metavar="N",
                   help="with --history: how many recent commits to read (default 500)")
    s.add_argument("--fail-on", **fail_on)
    b = sub.add_parser("baseline", help="write the fingerprints of every current finding (commit the file)")
    b.add_argument("path")
    b.add_argument("--out", metavar="FILE", help="where to write it (default PATH/%s)" % baseline.FILENAME)
    b.add_argument("--goal", metavar="FILE")
    d = sub.add_parser("diff", help="what a change fixed and broke: compare two scan --json reports by fingerprint")
    d.add_argument("before")
    d.add_argument("after")
    d.add_argument("--json", action="store_true")
    pl = sub.add_parser("plan", help="what to fix next: each check row's estimated gain if fixed, best first")
    pl.add_argument("path")
    pl.add_argument("--top", type=int, default=10, help="how many rows (default 10)")
    pl.add_argument("--json", action="store_true", help="JSON instead of Markdown")
    pl.add_argument("--goal", metavar="FILE")
    o = sub.add_parser("orphans", help="code nothing reachable from the entry points uses")
    o.add_argument("path")
    o.add_argument("--json", action="store_true")
    o.add_argument("--goal", metavar="FILE")
    o.add_argument("--fail-on", **fail_on)
    i = sub.add_parser("init", help="write a starter %s with the inferred entry points" % goal.FILENAME)
    i.add_argument("path", nargs="?", default=".")
    i.add_argument("--force", action="store_true", help="overwrite an existing goal file")
    return p


def init(path, force=False, out=print):
    """Write PATH/code-guardian.goal.toml with the inferred entry points. --force replaces an existing file and keeps
    its goal sentence, keep and exclude lists."""
    root = report._root(path)
    target = os.path.join(root, goal.FILENAME)
    old = None
    if os.path.exists(target):
        if not force:
            raise report.UsageError("%s already exists (use --force to overwrite)" % goal.FILENAME)
        old = goal.load(target)
    entries = report.orphans(root, infer=True)["entry_points"]
    sentence = (old or {}).get("goal") or "Describe in one sentence what this project is for."
    with open(target, "w", encoding="utf-8") as fh:
        fh.write(goal.render(sentence, entries, (old or {}).get("keep", ()), (old or {}).get("exclude", ())))
    out("wrote %s with %d inferred entry point(s):" % (goal.FILENAME, len(entries)))
    for e in entries:
        out("  " + e)
    if not entries:
        out("no entry points found: add them by hand as module:function")
    return 0


def write_baseline(path, out=None, goal_file=None, echo=print):
    """Scan PATH and write the sorted fingerprints of every finding (scored and hygiene) to out."""
    rep = report.scan(path, goal_file)
    target = out or os.path.join(report._root(path), baseline.FILENAME)
    doc = baseline.document(rep["findings"] + rep["hygiene"]["findings"], __version__)
    with open(target, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(doc, indent=1) + "\n")
    echo("wrote %s with %d fingerprint(s) (scan status %s)" % (target, len(doc["fingerprints"]), rep["status"]))
    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["mcp"]:  # `code-guardian mcp` starts the same server as `code-guardian-mcp`
        from . import mcp_server
        return mcp_server.main(argv[1:])
    if argv[:1] == ["--selftest"]:
        return selftest()
    args = _parser().parse_args(argv)
    try:
        if args.command == "scan":
            if args.history_depth < 1:
                raise report.UsageError("--history-depth must be at least 1")
            rep = report.scan(args.path, args.goal, explain=args.explain, online=args.online, baseline=args.baseline,
                              history=args.history, history_depth=args.history_depth)
            if args.json:
                sys.stdout.write(json.dumps(redact_report(rep), indent=1) + "\n")
            elif args.sarif:
                sys.stdout.write(json.dumps(outputs.to_sarif(rep), indent=1) + "\n")
            elif args.markdown:
                sys.stdout.write(outputs.to_markdown(rep))
            else:
                sys.stdout.write(report.render(rep))
            return report.exit_code(rep["findings"], args.fail_on, report.gate_status(rep), rep.get("baseline"))
        if args.command == "diff":
            try:
                result = verify.diff(verify.load_report(args.before), verify.load_report(args.after))
            except (OSError, ValueError) as exc:
                raise report.UsageError("cannot diff: %s" % exc) from None
            sys.stdout.write(json.dumps(redact_report(result), indent=1) + "\n" if args.json
                             else verify.render_diff(redact_report(result)))
            return verify.diff_exit(result)
        if args.command == "plan":
            result = redact_report(verify.plan(report.scan(args.path, args.goal), args.top))
            sys.stdout.write(json.dumps(result, indent=1) + "\n" if args.json else verify.plan_markdown(result))
            return 0
        if args.command == "baseline":
            return write_baseline(args.path, args.out, args.goal)
        if args.command == "orphans":
            hyg = report.orphans(args.path, args.goal)
            sys.stdout.write(json.dumps(redact_report(hyg), indent=1) + "\n" if args.json else report.render_orphans(hyg))
            return report.exit_code(hyg["findings"], args.fail_on)
        if args.command == "init":
            return init(args.path, args.force)
    except (report.UsageError, goal.GoalError) as exc:
        sys.stderr.write("code-guardian: %s\n" % exc)
        return 2
    _parser().print_help(sys.stderr)
    return 2


def selftest():
    import contextlib
    import io

    tmp = tempfile.mkdtemp()
    try:
        os.makedirs(os.path.join(tmp, "app"))
        with open(os.path.join(tmp, "app", "run.py"), "w", encoding="utf-8") as fh:
            fh.write("import requests\ndef main():\n    requests.get('https://example.com', verify=False)\n"
                     "if __name__ == '__main__':\n    main()\n")

        def run(*argv):
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                try:
                    code = main(list(argv))
                except SystemExit as exc:
                    code = exc.code
            return code, out.getvalue()

        empty = os.path.join(tmp, "empty")
        os.makedirs(empty)
        scan_code, scan_json = run("scan", tmp, "--json")
        with open(os.path.join(tmp, "s.json"), "w", encoding="utf-8") as fh:
            fh.write(scan_json)
        init_code, _ = run("init", tmp)
        again, _ = run("init", tmp)
        forced, _ = run("init", tmp, "--force")
        checks = [
            ("scan_fail_exit_1", scan_code == 1 and json.loads(scan_json)["scores"]["safe"] == 75),
            ("fail_on_case_insensitive", run("scan", tmp, "--fail-on", "fail")[0] == 1),
            ("orphans_exit_0", run("orphans", tmp)[0] == 0),
            ("usage_exit_2", run("scan")[0] == 2 and run("scan", os.path.join(tmp, "nope"))[0] == 2),
            ("bad_level_exit_2", run("scan", tmp, "--fail-on", "LOUD")[0] == 2),
            ("init", init_code == 0 and goal.load(os.path.join(tmp, goal.FILENAME))["entry_points"] == ["app.run:__main__"]),
            ("init_no_overwrite", again == 2 and forced == 0),
            ("empty_exit_3", run("scan", empty)[0] == 3),
            ("baseline_gate", run("baseline", tmp, "--out", os.path.join(tmp, "b.json"))[0] == 0
             and run("scan", tmp, "--baseline", os.path.join(tmp, "b.json"), "--fail-on", "INFO")[0] == 0),
            ("plan", run("plan", tmp, "--top", "1")[0] == 0 and "estimated gain if fixed" in run("plan", tmp)[1].lower()),
            ("diff_self", run("diff", os.path.join(tmp, "s.json"), os.path.join(tmp, "s.json"))[0] == 0
             and run("diff", os.path.join(tmp, "s.json"), os.path.join(tmp, "s.json"))[1].startswith("verdict: unchanged")),
            ("bad_goal_exit_2", run("scan", tmp, "--goal", os.path.join(tmp, "missing.toml"))[0] == 2),
        ]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return summarize("cli", checks)


if __name__ == "__main__":
    sys.exit(main())
