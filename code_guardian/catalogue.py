"""The check catalogue: every finding code, what it means, how to fix it, and when it can be wrong.

SARIF rules and the Markdown output read it; tests/test_readme_sync.py checks the README catalogue against it.

Public contract:
    CATALOGUE = {code: {"title", "means", "fix", "false_positives"}}
"""

import sys

from .finding import summarize


def _e(title, means, fix, false_positives):
    return {"title": title, "means": means, "fix": fix, "false_positives": false_positives}


CATALOGUE = {
    # Safe
    "secret.key": _e(
        "Secret in the source",
        "An API-key shape, a private-key block or a password-like literal is written into a file.",
        "Move it to an environment variable or a secret store, and rotate it: it is in the history.",
        "Test fixtures and documentation samples; values that call themselves fake (mock, dummy, example) are skipped."),
    "exec.dynamic": _e(
        "Code built at runtime",
        "eval, exec or compile runs a non-literal string, or __import__ loads a module named at runtime.",
        "Use a parser, a lookup table or ast.literal_eval; import modules by name.",
        "Plugin loaders and REPL-style tools use these on purpose."),
    "exec.shell": _e(
        "Shell command",
        "os.system, os.popen or subprocess with shell=True; FAIL when the command text comes from input, the environment "
        "or the network.",
        "Pass an argument list without shell=True; validate any outside value against an allow-list.",
        "Fixed command strings in build scripts are WARN, not FAIL; taint is tracked one function deep."),
    "deser.unsafe": _e(
        "Unsafe deserialisation",
        "pickle, marshal, yaml.load without SafeLoader, or torch.load without weights_only=True can run code hidden in "
        "the data.",
        "Load only files you created, or use a data-only format (json, safetensors, yaml.safe_load).",
        "Caches the program writes and reads itself are lower risk."),
    "net.egress": _e(
        "Network egress",
        "The egress inventory: every URL and IP literal and every network call site. WARN for a public IP, or plain "
        "http/ws/ftp to a public name or to a host set at runtime.",
        "Use https, and confirm each destination is expected.",
        "Local-network and documentation hosts stay INFO; a URL in a help string is still inventoried."),
    "net.bind_all": _e(
        "Listens on every interface",
        "A server binds 0.0.0.0 or ::, so other machines can reach it.",
        "Bind to 127.0.0.1 unless other machines must connect.",
        "Containers usually must bind 0.0.0.0; a test that asserts the bind is refused still matches."),
    "tls.off": _e(
        "TLS checking switched off",
        "verify=False, ssl._create_unverified_context, CERT_NONE or check_hostname = False.",
        "Remove it; point at a CA bundle if the certificate is private.",
        "Rare: code that deliberately probes broken servers."),
    "install.hook": _e(
        "Code runs on install",
        "setup.py cmdclass or install-command subclasses, package.json preinstall/install/postinstall, or an in-tree "
        "build backend.",
        "Read what the hook runs before installing; prefer packages without install-time code.",
        "Projects that compile extensions legitimately customise build commands."),
    "obfuscation": _e(
        "Obfuscated code",
        "exec/eval of base64, zlib, marshal or hex-decoded data (FAIL); long encoded blobs or high-entropy literals (WARN).",
        "Decode the payload offline and read what it does before running anything.",
        "Embedded icons, test vectors and hashes can look like blobs."),
    "fs.outside": _e(
        "Writes outside the project",
        "A write, delete or move aimed at an absolute path, the home directory or a .. escape.",
        "Write under the project or under a path the user passes in.",
        "Tools whose job is to write to /tmp or a user config folder."),
    "deps.unpinned": _e(
        "Unpinned dependency",
        "A dependency with no pin and no upper bound.",
        "Pin it (==) or cap it (< next major).",
        "Libraries often prefer open ranges on purpose; INFO, never scored."),
    "supply.unknown_package": _e(
        "Unknown or invented package",
        "Offline: the name is not in the bundled list of known packages (INFO). Online: PyPI has no such project (FAIL), "
        "or it is new or has a single release (WARN).",
        "Check the name is the one you meant; remove names an assistant invented; run with --online.",
        "Offline misses are common for less-known real packages, which is why they are INFO. Existing is not safe."),
    "supply.lookalike": _e(
        "Lookalike package name",
        "The name is one or two edits away from a known package without being it: the typosquatting pattern.",
        "Check you meant the well-known package.",
        "Real packages with names close to a popular one."),
    # Works
    "works.syntax": _e(
        "File does not parse",
        "ast.parse rejects the file, so it cannot be imported or run (INFO when the project needs a newer Python than "
        "the one scanning).",
        "Fix the syntax error; port Python 2 code to Python 3.",
        "Files kept on purpose for another interpreter, or templates with a .py name."),
    "works.import_unresolved": _e(
        "Import nothing provides",
        "An absolute import that is not in the standard library, not in the repo and not a declared dependency.",
        "Declare the distribution that provides it, or guard an optional import with try/except ImportError.",
        "Packages pulled in only by another dependency (they work by accident); import names the mapping table misses."),
    "works.relative_missing": _e(
        "Relative import to nothing",
        "from .x import y points at a module (or a package name) the repo does not have.",
        "Fix the module path or add the missing module.",
        "Modules generated at build time."),
    "works.tests_missing": _e(
        "No tests",
        "There are no test files at all.",
        "Add a tests/ folder with at least one test per entry point.",
        "Tests kept in another repository."),
    "works.test_no_assert": _e(
        "Tests that check nothing",
        "Test functions with no assert, no pytest.raises/warns, no self.assert* and no call to an asserting helper.",
        "Assert on the result; use pytest.raises for expected errors.",
        "Smoke tests that only check nothing raises; helpers defined in another file."),
    "works.entry_missing": _e(
        "Command points at nothing",
        "A [project.scripts] (or setup.cfg console script) target module:function is not in the tree.",
        "Point the script at an existing module:function.",
        "Modules generated at build time."),
    "orphan.dead": _e(
        "Dead code",
        "A function, class or module nothing reachable from the entry points uses.",
        "Delete it, or list it in keep if something loads it by name.",
        "Code loaded by name (plugins, entry points of other tools); add those to keep."),
    "orphan.test_only": _e(
        "Used only by tests",
        "Only tests reach this code; the product never does.",
        "Delete it with its tests, or call it from the product.",
        "Test helpers kept in the package on purpose."),
    "orphan.uncertain": _e(
        "Maybe used dynamically",
        "getattr/globals/importlib with a computed name, or a string registry, could reach it.",
        "List it in keep if it is loaded by name; otherwise delete it.",
        "It is reported as uncertain precisely because the parse cannot tell."),
    # Complete
    "complete.license_missing": _e(
        "No licence file",
        "There is no LICENSE, LICENCE, COPYING or UNLICENSE file at the root.",
        "Add a LICENSE file.",
        "Licences kept only in a subfolder."),
    "complete.license_undeclared": _e(
        "Licence not declared",
        "Packaging metadata exists but declares no licence.",
        "Add license = \"...\" (or license-files) to [project].",
        "Licences declared only by a build plugin."),
    "complete.readme_missing": _e(
        "No README",
        "There is no README at the root.",
        "Add a README.md that says what it is, how to install it and how to use it.",
        "README kept under docs/ only."),
    "complete.readme_short": _e(
        "README too short",
        "The README is under 200 bytes.",
        "Describe what it does, how to install it and how to use it.",
        "A README that only links to full documentation."),
    "complete.readme_sections": _e(
        "README lacks install or usage",
        "A README of 200+ bytes with no install heading or no usage heading.",
        "Add an Install heading and a Usage heading.",
        "Headings worded differently from the words the check knows."),
    "complete.ci_missing": _e(
        "No CI",
        "No CI configuration was found.",
        "Add a CI workflow that runs the tests on each change.",
        "CI configured outside the repository."),
    "complete.metadata": _e(
        "Incomplete metadata",
        "pyproject.toml [project] lacks name, version (or dynamic) or requires-python.",
        "Add the missing keys to [project].",
        "None known."),
    "complete.lockfile": _e(
        "Application without a lockfile",
        "The repo is an application (a Dockerfile, a __main__.py without scripts, or a web app object) and has no "
        "lockfile.",
        "Commit a lockfile (uv lock, poetry lock or pip-compile).",
        "Libraries are never asked for one; an example app outside examples/ can make a library look like an app."),
    "complete.env_example": _e(
        "No .env.example",
        "The code reads environment variables but there is no .env.example listing them.",
        "Add a .env.example with every variable and a safe placeholder.",
        "Libraries that read only optional, well-known variables (NO_COLOR, TERM)."),
    "deps.declared_unused": _e(
        "Declared but never imported",
        "A runtime dependency nothing in the repo imports.",
        "Remove it, or note why it is needed (a plugin or a runner).",
        "Plugins and runners loaded by other tools; INFO, never scored."),
    "check.crashed": _e(
        "A check crashed",
        "One of code-guardian's own checks raised on this file; the rest of the scan ran.",
        "Report it at github.com/LuminariSoftwares/code-guardian/issues with the file if you can share it.",
        "It is a code-guardian bug, never a finding about your code."),
}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if "--selftest" in argv:
        from . import score
        codes = {c for table in score.TABLES.values() for c, _ in table}
        checks = [
            ("covers_every_scored_code", codes <= set(CATALOGUE)),
            ("four_fields", all(set(e) == {"title", "means", "fix", "false_positives"} for e in CATALOGUE.values())),
            ("short_titles", all(len(e["title"]) <= 40 for e in CATALOGUE.values())),
        ]
        return summarize("catalogue", checks)
    sys.stderr.write("usage: python -m code_guardian.catalogue --selftest\n")
    return 2


if __name__ == "__main__":
    sys.exit(main())
