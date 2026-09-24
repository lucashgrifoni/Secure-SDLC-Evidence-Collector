"""`scripts/normalize_sdist.py`: the sdist is byte-identical across builds.

Two builds of the same tree with the same SOURCE_DATE_EPOCH gave the same
wheel and a different sdist: the gzip header keeps the wall-clock time and
setuptools stamps the files it generates (PKG-INFO, egg-info, the root
directory) with the build time. The release workflow repacks the sdist with
this script so a verifier rebuilding from source gets the published bytes.
"""

from __future__ import annotations

import gzip
import importlib.util
import io
import tarfile
import time
from pathlib import Path
from types import ModuleType

import pytest

_EPOCH = 1_780_000_000


def _script() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "normalize_sdist", Path("scripts/normalize_sdist.py")
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sdist(path: Path, *, stamp: int, header_time: int) -> Path:
    """A small sdist whose generated entries carry `stamp` as mtime."""
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
        root = tarfile.TarInfo("pkg-1.0")
        root.type = tarfile.DIRTYPE
        root.mtime = stamp
        root.mode = 0o755
        tar.addfile(root)
        for name, body, mtime in (
            ("pkg-1.0/PKG-INFO", b"Metadata-Version: 2.4\nName: pkg\n", stamp),
            ("pkg-1.0/src/pkg/__init__.py", b"VALUE = 1\n", _EPOCH - 100),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(body)
            info.mtime = mtime
            info.uid, info.gid, info.uname, info.gname = 1001, 121, "runner", "docker"
            tar.addfile(info, io.BytesIO(body))
    with (
        path.open("wb") as fh,
        gzip.GzipFile(filename="pkg-1.0.tar", mode="wb", fileobj=fh, mtime=header_time) as gz,
    ):
        gz.write(raw.getvalue())
    return path


def test_two_builds_become_byte_identical(tmp_path: Path) -> None:
    first = _sdist(tmp_path / "a" / "pkg-1.0.tar.gz", stamp=_EPOCH + 50, header_time=_EPOCH + 51)
    second = _sdist(tmp_path / "b" / "pkg-1.0.tar.gz", stamp=_EPOCH + 90, header_time=_EPOCH + 97)
    assert first.read_bytes() != second.read_bytes()

    script = _script()
    script.normalize(first, _EPOCH)
    script.normalize(second, _EPOCH)

    assert first.read_bytes() == second.read_bytes()


def test_contents_survive_and_no_entry_is_newer_than_the_epoch(tmp_path: Path) -> None:
    sdist = _sdist(tmp_path / "pkg-1.0.tar.gz", stamp=_EPOCH + 50, header_time=int(time.time()))
    _script().normalize(sdist, _EPOCH)

    header = sdist.read_bytes()[:10]
    # RFC 1952: bytes 4-7 are MTIME (little endian); FLG (byte 3) has no FNAME bit.
    assert int.from_bytes(header[4:8], "little") == _EPOCH
    assert header[3] & 0x08 == 0
    with tarfile.open(sdist, "r:gz") as tar:
        members = tar.getmembers()
        assert [m.name for m in members] == [
            "pkg-1.0",
            "pkg-1.0/PKG-INFO",
            "pkg-1.0/src/pkg/__init__.py",
        ]
        assert max(m.mtime for m in members) <= _EPOCH
        # An older mtime from the repository is kept, not raised to the epoch.
        assert tar.getmember("pkg-1.0/src/pkg/__init__.py").mtime == _EPOCH - 100
        assert {(m.uid, m.gid, m.uname, m.gname) for m in members} == {(0, 0, "", "")}
        member = tar.extractfile("pkg-1.0/PKG-INFO")
        assert member is not None
        assert member.read() == b"Metadata-Version: 2.4\nName: pkg\n"


def test_the_command_needs_source_date_epoch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    sdist = _sdist(tmp_path / "pkg-1.0.tar.gz", stamp=_EPOCH, header_time=_EPOCH)
    before = sdist.read_bytes()
    assert _script().main([str(tmp_path)]) == 2
    assert sdist.read_bytes() == before
