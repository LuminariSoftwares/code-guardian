# Releasing code-guardian-mcp

A release is published to PyPI by GitHub, not from a computer. When you publish a GitHub Release, the workflow
`.github/workflows/release.yml` builds the package, checks it, and uploads it to PyPI with a signed record
(provenance) of the commit it came from. There is no PyPI password or token stored anywhere: PyPI is told once to
trust this workflow, and the workflow is handed a short-lived pass each time it runs.

## One time: tell PyPI to trust the workflow (the owner does this)

1. Sign in at https://pypi.org and open the project `code-guardian-mcp`, then **Manage**, then **Publishing**.
2. Add a trusted publisher of type **GitHub**, with exactly these fields:
   - Owner: `LuminariSoftwares`
   - Repository name: `code-guardian`
   - Workflow name: `release.yml`
   - Environment name: `pypi`
3. In the GitHub repository, open **Settings**, then **Environments**, and create an environment named `pypi`.
   Adding yourself as a required reviewer is optional but recommended: each publish then waits for your click.

Until step 2 is done, a published release fails at the publish step and nothing reaches PyPI.

## Each release

1. Change the version to the new number in `pyproject.toml`, `code_guardian/__init__.py`,
   `code_guardian/mcp_server.py` and both `"version"` fields in `server.json`; update the release line, the
   `--version` sample, the pinned Action ref and the pre-commit `rev` in `README.md`; add a section for it to
   `CHANGELOG.md`.
2. Open a pull request, wait for the checks to pass, and merge it.
3. On GitHub, open **Releases**, then **Draft a new release**. Create the tag `v<version>` on `main` (for 0.4.2 that
   is `v0.4.2`) and publish the release.
4. Open the **Actions** tab and watch the `release` run. The build job fails if the tag is not `v` plus the version in
   `pyproject.toml`; fix the tag or the version and publish again. If the `pypi` environment asks for a review,
   approve it.
5. When it is green, check https://pypi.org/project/code-guardian-mcp/ shows the new version.

## Trying it without publishing

Pull requests that change `release.yml` or `pyproject.toml` run the build and the checks and stop there. You can also
start the `release` workflow by hand from the **Actions** tab: with **dry_run** ticked (the default) it only builds
and checks. Unticking it publishes, and only works when started on a `v<version>` tag.
