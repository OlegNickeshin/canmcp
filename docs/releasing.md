# Releasing CanMCP

The GitHub repository is <https://github.com/OlegNickeshin/canmcp>.
The intended PyPI distribution name is `canmcp`.

## Build and verify

From a clean checkout of the release commit, use Python 3.11 or newer:

```sh
python -m venv .venv
source .venv/bin/activate
python -m pip install '.[dev,release]'
python -m pytest
ruff check .
ruff format --check .
python -m build --outdir release-dist
python -m twine check --strict release-dist/*
```

Use a fresh output directory for every version. Match the version in `pyproject.toml` and
`canmcp/__init__.py` to the release tag. Test the built wheel from outside the source directory
before uploading it. Release assets should include the wheel, source archive, and SHA-256 sums.

## Publish to PyPI

Publication requires a PyPI account with a verified email address, the account's required
authentication setup, and permission to publish the project. For the first upload, PyPI needs
an account-scoped API token because the project does not yet exist. Subsequent tokens can be
restricted to `canmcp`. Review the
[official packaging guide](https://packaging.python.org/en/latest/tutorials/packaging-projects/#uploading-the-distribution-archives).

Twine can ask for the API token in the local terminal with hidden input:

```sh
python -m twine upload --repository-url https://upload.pypi.org/legacy/ \
  --username __token__ release-dist/canmcp-0.2.0-py3-none-any.whl \
  release-dist/canmcp-0.2.0.tar.gz
```

Do not put a token in a commit, release body, issue, chat, or command-line argument. A local
`~/.pypirc` is another supported option; keep it outside the repository and readable only by
its owner. See the [.pypirc specification](https://packaging.python.org/en/latest/specifications/pypirc/).

After the upload, verify the version on PyPI and install `canmcp==0.2.0` into a fresh environment
using `https://pypi.org/simple/`. Remove the pending-publication notice from the README only
after the upload has succeeded. PyPI does not allow reusing an uploaded distribution filename.

[Trusted Publishing](https://docs.pypi.org/trusted-publishers/) is the preferred future
automation path. It requires a configured PyPI publisher and a working CI runner. A pending
publisher alone does not reserve a package name or publish the package. If GitHub Actions is
blocked by an account billing issue, a verified local upload can still publish the release.
