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

## What is not covered

- **Rebuilding the exact bad artifact to investigate it.** The wheel is
  reproducible from the tagged commit; the sdist is not — its gzip header and
  its generated files (`PKG-INFO`, `setup.cfg`, egg-info) carry build-time
  timestamps. Compare wheels, not sdists.
- **A rehearsal.** This procedure has not been executed against a real release.
  Yanking is reversible and the steps above are all documented vendor
  behaviour, but no one here has done it under pressure.
