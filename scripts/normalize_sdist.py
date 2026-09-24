"""Repack every sdist in a directory so the same tree always gives the same bytes.

Usage: SOURCE_DATE_EPOCH=<seconds> python scripts/normalize_sdist.py DIST_DIR

setuptools honours SOURCE_DATE_EPOCH for the files it copies from the
repository but not for the ones it generates (PKG-INFO, setup.cfg, the
egg-info, the root directory), and the gzip header keeps the wall-clock time
of the build. This script rewrites each ``*.tar.gz``:

* every entry's mtime is clamped to SOURCE_DATE_EPOCH (older ones are kept);
* modes become 0755 for directories and executables and 0644 otherwise, so
  the umask of the checkout does not leak into the archive;
* owner and group are reset to 0 with empty names;
* entries keep their order and their bytes;
* the gzip header carries SOURCE_DATE_EPOCH and no file name.

It exits 2 without touching anything when SOURCE_DATE_EPOCH is unset or not
an integer, so a release never ships an sdist normalised to a made-up time.
"""

from __future__ import annotations

import gzip
import io
import os
import sys
import tarfile
from pathlib import Path


def normalize(sdist: Path, epoch: int) -> None:
    """Rewrite ``sdist`` in place with clamped mtimes and a fixed gzip header."""
    raw = io.BytesIO()
    with (
        tarfile.open(sdist, "r:gz") as source,
        tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as target,
    ):
        for member in source.getmembers():
            member.mtime = min(int(member.mtime), epoch)
            # The checkout's umask decides 0644 vs 0600; only "executable or
            # not" is part of the source, so keep that and fix the rest.
            member.mode = 0o755 if member.isdir() or member.mode & 0o111 else 0o644
            member.uid = member.gid = 0
            member.uname = member.gname = ""
            member.pax_headers = {}
            body = source.extractfile(member) if member.isfile() else None
            target.addfile(member, body)
    staged = sdist.with_name(sdist.name + ".tmp")
    with (
        staged.open("wb") as fh,
        gzip.GzipFile(filename="", mode="wb", fileobj=fh, mtime=epoch, compresslevel=9) as gz,
    ):
        gz.write(raw.getvalue())
    staged.replace(sdist)


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: normalize_sdist.py DIST_DIR", file=sys.stderr)
        return 2
    try:
        epoch = int(os.environ["SOURCE_DATE_EPOCH"])
    except (KeyError, ValueError):
        print("SOURCE_DATE_EPOCH must be set to an integer.", file=sys.stderr)
        return 2
    sdists = sorted(Path(argv[0]).glob("*.tar.gz"))
    for sdist in sdists:
        normalize(sdist, epoch)
        print(f"normalized {sdist}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
