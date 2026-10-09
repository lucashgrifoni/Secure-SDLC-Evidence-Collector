"""Repack every sdist in a directory so the same tree always gives the same bytes.

Usage: SOURCE_DATE_EPOCH=<seconds> python scripts/normalize_sdist.py DIST_DIR

setuptools honours SOURCE_DATE_EPOCH for the files it copies from the
repository but not for the ones it generates (PKG-INFO, setup.cfg, the
egg-info, the root directory), and the gzip header keeps the wall-clock time
of the build. This script rewrites each ``*.tar.gz``:

* every entry's mtime is set to SOURCE_DATE_EPOCH;
* modes become 0755 for directories, 0777 for links and 0644 for files;
  this Python distribution has no executable files in its source contract;
* owner and group are reset to 0 with empty names;
* entries are sorted by name and their payload bytes are preserved;
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
    """Rewrite the Python sdist with canonical metadata and unchanged payloads."""
    if not 0 <= epoch <= 0xFFFFFFFF:
        raise ValueError("SOURCE_DATE_EPOCH must be between 0 and 4294967295.")
    raw = io.BytesIO()
    with (
        tarfile.open(sdist, "r:gz") as source,
        tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as target,
    ):
        for member in sorted(source.getmembers(), key=lambda entry: entry.name):
            member.mtime = epoch
            member.mode = 0o755 if member.isdir() else 0o777 if member.issym() else 0o644
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
    if not 0 <= epoch <= 0xFFFFFFFF:
        print("SOURCE_DATE_EPOCH must be between 0 and 4294967295.", file=sys.stderr)
        return 2
    sdists = sorted(Path(argv[0]).glob("*.tar.gz"))
    if not sdists:
        print("No *.tar.gz distributions found.", file=sys.stderr)
        return 2
    for sdist in sdists:
        normalize(sdist, epoch)
        print(f"normalized {sdist}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
