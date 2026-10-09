"""Odd or hostile input must end as a ParseError, never as a crash.

The local collector records a file as a collection error only when its parser
raises ``ParseError``, ``OSError`` or a pydantic ``ValidationError``. Anything
else escapes every frame up to ``main()``, which exits 3 and discards every
other artifact in the directory. Each case below reached ``main()`` on 4.0.0
through a different hole: a bare ``ValueError`` from pyexpat or PyYAML, a
``RecursionError`` during detection, an ``AttributeError``/``TypeError`` from a
shape the parser assumed, or a value the bundle could not serialize.

Direct callers (``exceptions validate``, ``vex``, the Python API) get the same
benefit, so the assertions are on the parsers, with collector-level checks for
the paths that run during detection.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from evidence_collector.collectors.local import LocalArtifactCollector, LocalCollectionReport
from evidence_collector.domain.models import ReleaseContext
from evidence_collector.parsers._common import ParseError
from evidence_collector.parsers.junit import parse_junit

_GOOD_OSV = (
    '{"results": [{"packages": [{"package": {"name": "lodash", "version": '
    '"4.17.20", "ecosystem": "npm"}, "vulnerabilities": [{"id": "GHSA-1", '
    '"aliases": ["CVE-2020-8203"]}]}]}]}'
)


def _release() -> ReleaseContext:
    return ReleaseContext(release_id="1.0.0", commit_sha="abcdef1234567890")


def _collect_beside_good_osv(
    tmp_path: Path, name: str, content: str | bytes
) -> LocalCollectionReport:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "osv.json").write_text(_GOOD_OSV, encoding="utf-8")
    target = artifacts / name
    if isinstance(content, bytes):
        target.write_bytes(content)
    else:
        target.write_text(content, encoding="utf-8")
    return LocalArtifactCollector(_release(), artifacts_dirs=[artifacts]).collect()


# ---------------------------------------------------------------------------
# D10 — JUnit XML declaring an encoding pyexpat cannot decode
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("encoding", ["Shift_JIS", "windows-31j"])
def test_junit_with_an_undecodable_xml_encoding_is_a_parse_error(
    tmp_path: Path, encoding: str
) -> None:
    """pyexpat raises a bare ValueError for a multi-byte encoding it does not
    support, and LookupError for a codec name Python does not know."""
    path = tmp_path / "report.xml"
    path.write_text(
        f'<?xml version="1.0" encoding="{encoding}"?>'
        '<testsuite name="t" tests="1"><testcase name="a"/></testsuite>',
        encoding="ascii",
    )
    with pytest.raises(ParseError, match=r"report\.xml"):
        parse_junit(path)
