# Publishing

Releases are published to PyPI by `.github/workflows/publish.yaml` using [Trusted Publishing](https://docs.pypi.org/trusted-publishers/): GitHub Actions exchanges a short-lived OIDC token for upload rights, so no API token is stored anywhere.

## One-time setup

These steps are done once, before the first release.

### GitHub

1. Create the repository `Dr-Blank/aioayla-lan` and push `main`.
2. In the repository, open Settings > Environments > New environment and create an environment named `pypi`.
3. Optional hardening for the `pypi` environment: under Deployment branches and tags, choose Selected branches and tags and add a tag rule `v*`; add yourself as a required reviewer if every upload should wait for a manual approval.

### PyPI

1. Sign in to pypi.org and open Your account > Publishing (<https://pypi.org/manage/account/publishing/>).
2. Under Add a new pending publisher, choose GitHub and fill in:

| Field | Value |
| --- | --- |
| PyPI Project Name | `aioayla-lan` |
| Owner | `Dr-Blank` |
| Repository name | `aioayla-lan` |
| Workflow name | `publish.yaml` |
| Environment name | `pypi` |

A pending publisher reserves nothing until it is used: the project is created on the first successful upload, and the pending publisher then becomes a normal trusted publisher of that project.

## Before the first push

CI installs with `uv sync --locked`, so commit a lockfile: run `uv lock` and commit `uv.lock`.

## Releasing

1. Run `script/release.sh <major|minor|patch|X.Y.Z>` (or the VS Code task Release: Bump Version & Tag). It sets the version in `pyproject.toml` and `uv.lock`, commits `chore(release): vX.Y.Z`, and creates the annotated `vX.Y.Z` tag. Nothing is pushed. For the first release the version is already `0.1.0`, so run `script/release.sh 0.1.0` to tag it without a bump.
2. Push with `git push --follow-tags origin main` (or the task Release: Push Tags to Origin).
3. The Publish workflow checks that the tag matches `pyproject.toml`, runs the prek hooks (`.pre-commit-config.yaml`) and pytest, builds the sdist and wheel, uploads them to PyPI, and then creates the GitHub release with both files attached.

The release notes list the commits since the previous tag grouped by Conventional Commits type (`script/release_notes.sh`), followed by GitHub's generated notes for merged pull requests, categorised by label per `.github/release.yml`.

If a run fails after the tag is pushed, re-run it for the existing tag with `gh workflow run publish.yaml -f tag=vX.Y.Z` (or the task Release: Publish Now). An existing GitHub release gets its files replaced instead of being created again.

The Home Assistant integration pins an exact version of this library, so a release it depends on has to be live on PyPI before the integration's own CI can install it.
