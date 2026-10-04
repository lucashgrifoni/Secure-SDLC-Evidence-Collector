# Rolling back a bad release

This project's own control catalog asks every release it evaluates for a
`rollback_plan`. This is ours.

There is no server to roll back. What ships is a package on PyPI, an image on
GHCR, and a set of signed assets on a GitHub Release, so "rollback" means
stopping new consumers from resolving the bad version — not restoring a system.
That also means backup, restore, RPO and RTO have no object here: nothing is
stateful, and a consumer who already installed the bad version rolls back by
pinning, not by anything we do.

## The one thing that cannot be undone

**Do not delete the release on PyPI.** Deletion looks like the obvious fix and
it is the worst available option, because PyPI's rules are stricter than most
people expect:

> "PyPI does not allow for a filename to be reused, even once a project has
> been deleted and recreated." — [PyPI help](https://pypi.org/help/)

> "Deletion of a project, release or file on PyPI is permanent and
> irreversible, without exception." — same

So deleting `2.5.1` does not free `2.5.1`. It burns the version number
permanently, and anyone who had pinned it now gets a resolution failure instead
of a working install. The correct tool is yanking.

## Yank, then publish forward

[PEP 592](https://peps.python.org/pep-0592/) defines yanking as a way to
"effectively delete a file, without breaking things for people who have pinned
to exactly a specific version". A yanked release:

- is skipped by resolvers doing normal range resolution;
- is **still installable** by an exact `==` pin, with a warning, so pipelines
  that pinned it keep working while their owners react;
- can be un-yanked, since the flag is not permanent.

That is exactly the semantics a bad release needs. The procedure:

1. **Yank the bad version.** PyPI web UI → the project → *Manage* →
   *Releases* → the version → *Options* → *Yank*. Give a reason; it is shown to
   anyone who installs the pinned version.
2. **Publish the fix as a new version.** Never reuse the yanked number — see
   above. `release-please` will open the version-bump PR; merging it cuts the
   tag and `publish-pypi.yml` does the rest.
3. **Say why.** Edit the GitHub Release notes of the bad version to point at
   the fix. The release notes are the first thing someone lands on from a
   changelog link.

If the bad version leaked a secret or shipped malicious content, the yank is the
first step and not the whole response — go to `SECURITY.md`, and treat any
credential the pipeline touched as exposed.

## The container image

GHCR tags are mutable, so an image is easier: re-point the affected tag at the
last good digest, or delete the bad tag outright. Consumers pinning by digest
(`@sha256:…`) are unaffected either way, which is the reason to pin by digest.

## The GitHub Release assets

Assets can be removed or replaced without touching the tag. Note that removing
a signed asset does not invalidate its signature — anyone who already downloaded
the wheel plus its `.sig` and `.pem` can still verify it. Yanking on PyPI is
what actually changes what new consumers get.

## Rebuilding a release to compare it

To investigate a bad release you can rebuild its wheel and sdist from the tag
and check them against the published files. The publish job builds both on
`ubuntu-latest` with Python 3.12 and `SOURCE_DATE_EPOCH` set to the commit time
of the tag, then passes the sdist through `scripts/normalize_sdist.py`. That
script sets every tar entry newer than `SOURCE_DATE_EPOCH` back to it, sets
modes to 0755 for directories and executables and 0644 for everything else,
resets owners, and writes the gzip header with the epoch and no file name. The
wheel is not repacked: setuptools already stamps its entries with
`SOURCE_DATE_EPOCH`.

This describes a run started by pushing the tag, which is how release-please
publishes. A run started by hand with `workflow_dispatch` saves the `tag`
input but checks out the ref the run was started from, and takes
`SOURCE_DATE_EPOCH` from that commit. If it was started from `main` with an
older tag as input, its assets come from the `main` commit, and a rebuild from
the tag will not match them. Check the run's trigger and commit before reading
a mismatch as tampering.

The job builds everything twice from the same checkout and compares the
hashes. A wheel mismatch fails the release; an sdist mismatch is only a warning
until a real release has confirmed the normalisation.

To match the published files, your rebuild has to repeat the job's conditions:

- **Build on Linux.** On Windows, setuptools writes `PKG-INFO`, its egg-info
  copy and `setup.cfg` with CRLF line endings, and the wheel gets the same CRLF
  in `METADATA` plus Windows file attributes on every entry. Neither the sdist
  nor the wheel can match, whatever else you do. A Linux container on a Windows
  machine is fine.
- **Build from a fresh clone made inside Linux, with umask 022.** The wheel
  keeps each file's mode from the checkout, so files at 0664 instead of 0644
  give a different wheel even on Linux. The sdist keeps the executable bit, so
  a Windows checkout seen through a bind mount, WSL's `/mnt/c` or a network
  share, where every file looks executable, gives a different sdist. The sdist
  also keeps mtimes older than `SOURCE_DATE_EPOCH`, so a working tree whose
  files predate the tag commit does not match either; a fresh clone gives every
  file a newer mtime.
- **Set `SOURCE_DATE_EPOCH` to the tag's commit time**, as the job does with
  `git log -1 --pretty=%ct`.
- **Use the same setuptools.** The workflow does not pin it, and the wheel
  names the version in its `*.dist-info/WHEEL` file
  (`Generator: setuptools (A.B.C)`), so any other version gives a different
  wheel.

For example, inside `docker run --rm -it python:3.12 bash`:

```sh
TAG=vX.Y.Z          # the release to rebuild
SETUPTOOLS=A.B.C    # from "Generator: setuptools (A.B.C)" in the published wheel
umask 022
git clone --depth 1 --branch "$TAG" \
  https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector.git src
cd src
export SOURCE_DATE_EPOCH="$(git log -1 --pretty=%ct)"
python -m pip install build wheel "setuptools==$SETUPTOOLS"
python -m build --no-isolation --wheel --sdist --outdir dist
python scripts/normalize_sdist.py dist
sha256sum dist/*
```

`--no-isolation` makes the build use the setuptools you pinned. The job builds
in an isolated environment instead; with the same setuptools version both give
the same bytes. Compare the two hashes with the SHA-256 digests PyPI lists for
the release files, or with `sha256sum` of the wheel and sdist attached to the
GitHub Release. Tags older than `scripts/normalize_sdist.py` published an sdist
that was never normalised, so for those skip that step and compare only the
wheel.

## What is not covered

- **A confirmed sdist rebuild.** The sdist normalisation has not yet been
  checked against a published release, and the job's own sdist check still
  only warns on a mismatch. If your hashes differ, compare the archives member
  by member (line endings and file modes are the usual cause) before treating
  the difference as tampering.
- **A rehearsal.** This procedure has not been executed against a real release.
  Yanking is reversible and the steps above are all documented vendor
  behaviour, but no one here has done it under pressure.
