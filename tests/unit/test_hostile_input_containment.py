"""One malformed artifact must never discard the rest of the evidence.

The collector guards ingestion with `except (ParseError, OSError)`, so any other
exception escapes every frame between the parser and `main()` and aborts the
whole run. Three that a scanner or an attacker can put in a directory did
exactly that: the scans had all been produced, and the run ended with no
bundle, no report and no summary because one file was malformed.

Detection is where they land, not parsing: every candidate file is read by the
`_looks_like_*` probes before any parser claims it, so guarding only the
parsers would leave the hole open.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from evidence_collector.collectors.local import LocalArtifactCollector
from evidence_collector.domain.models import ReleaseContext

_GOOD_OSV = (
    '{"results": [{"packages": [{"package": {"name": "lodash", "version": '
    '"4.17.20", "ecosystem": "npm"}, "vulnerabilities": [{"id": "GHSA-1", '
    '"aliases": ["CVE-2020-8203"]}]}]}]}'
)

# `defusedxml` blocks this and raises EntitiesForbidden — the XXE guard doing
# its job, and taking the run down with it. A DTD does not have to be hostile;
# plenty of real JUnit producers emit one.
_XXE_JUNIT = (
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x "y">]>'
    '<testsuite name="t" tests="1"><testcase name="a"/></testsuite>'
)

# `json.load` recurses once per nesting level, so this exhausts the stack.
_DEEPLY_NESTED_JSON = "[" * 60_000 + "]" * 60_000

# CPython caps int(str) at 4300 digits (CVE-2020-10735) and `json.load` raises
# a bare ValueError — not a JSONDecodeError — for a longer numeric literal.
_OVERLONG_INT_JSON = '{"runs": [], "n": ' + "9" * 5000 + "}"


def _release() -> ReleaseContext:
    return ReleaseContext(release_id="1.0.0", commit_sha="abcdef1234567890")


# Explicit ids: pytest derives one from the parameter value and exports it in
# PYTEST_CURRENT_TEST, and a 60,000-character payload overflows the 32,767-char
# environment variable limit on Windows.
@pytest.mark.parametrize(
    ("name", "content", "expected_reason"),
    [
        ("hostile.xml", _XXE_JUNIT, "Unsafe XML construct rejected"),
        ("deep.json", _DEEPLY_NESTED_JSON, "nested too deeply"),
        ("bigint.json", _OVERLONG_INT_JSON, "Invalid JSON value"),
    ],
    ids=["xxe-entity", "deeply-nested-json", "overlong-int-literal"],
)
def test_one_hostile_artifact_does_not_discard_the_others(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    name: str,
    content: str,
    expected_reason: str,
) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "osv.json").write_text(_GOOD_OSV, encoding="utf-8")
    (artifacts / name).write_text(content, encoding="utf-8")

    with caplog.at_level(logging.CRITICAL):
        report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts]).collect()

    # The good artifact survives — this is the whole point.
    assert len(report.evidence) == 1

    # And the bad one is reported rather than silently dropped.
    assert len(report.errors) == 1
    assert report.errors[0].path.name == name
    assert expected_reason in report.errors[0].reason


def test_a_directory_of_only_hostile_files_still_returns_a_report(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Even with nothing salvageable, the run must end in a verdict, not a crash."""
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "a.xml").write_text(_XXE_JUNIT, encoding="utf-8")
    (artifacts / "b.json").write_text(_DEEPLY_NESTED_JSON, encoding="utf-8")
    (artifacts / "c.json").write_text(_OVERLONG_INT_JSON, encoding="utf-8")

    with caplog.at_level(logging.CRITICAL):
        report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts]).collect()

    assert report.evidence == []
    assert len(report.errors) == 3
