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

import base64
import json
import logging
from pathlib import Path

import pytest

from evidence_collector.collectors.local import LocalArtifactCollector, LocalCollectionReport
from evidence_collector.domain.models import ReleaseContext
from evidence_collector.parsers._common import ParseError, load_yaml_or_json
from evidence_collector.parsers._intoto import decode_b64_statement
from evidence_collector.parsers.garak import parse_garak
from evidence_collector.parsers.junit import parse_junit
from evidence_collector.parsers.sarif import parse_sarifs

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


# ---------------------------------------------------------------------------
# D11 — YAML scalars PyYAML's SafeLoader turns into a bare ValueError
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        "generated_at: 2026-04-10T24:00:00Z",
        "approved_at: 2026-04-31T10:00:00Z",
        "generated_at: 2026-04-10T10:00:00+25:00",
        "count: " + "9" * 5000,
    ],
    ids=["hour-24", "april-31", "tz-plus-25", "overlong-int"],
)
def test_yaml_scalar_that_safeloader_cannot_construct_is_a_parse_error(
    tmp_path: Path, line: str
) -> None:
    path = tmp_path / "attestation.yaml"
    path.write_text(f"evidence_type: release_approval\n{line}\n", encoding="utf-8")
    with pytest.raises(ParseError, match=r"attestation\.yaml"):
        load_yaml_or_json(path)


def test_attestation_with_an_impossible_date_is_recorded_not_fatal(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    attestations = tmp_path / "attestations"
    attestations.mkdir()
    (attestations / "bad.yaml").write_text(
        "evidence_type: release_approval\nproducer: p\nsubject_ref: r\n"
        "generated_at: 2026-04-31T10:00:00Z\n",
        encoding="utf-8",
    )
    (attestations / "good.yaml").write_text(
        "evidence_type: release_approval\nproducer: p\nsubject_ref: r\n", encoding="utf-8"
    )
    with caplog.at_level(logging.CRITICAL):
        report = LocalArtifactCollector(_release(), attestations_dirs=[attestations]).collect()
    assert len(report.evidence) == 1
    assert [e.path.name for e in report.errors] == ["bad.yaml"]


# ---------------------------------------------------------------------------
# D15 — DSSE payload nested deeply enough to exhaust the stack
# ---------------------------------------------------------------------------

_DEEP_PAYLOAD = base64.b64encode(("[" * 3000 + "]" * 3000).encode()).decode()


def test_decode_b64_statement_returns_none_for_a_deeply_nested_payload() -> None:
    assert decode_b64_statement(_DEEP_PAYLOAD) is None


def test_deeply_nested_dsse_payload_does_not_abort_the_run(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    envelope = json.dumps({"payloadType": "application/vnd.in-toto+json", "payload": _DEEP_PAYLOAD})
    with caplog.at_level(logging.CRITICAL):
        report = _collect_beside_good_osv(tmp_path, "build.intoto.json", envelope)
    paths = [e.raw.artifact_path for e in report.evidence if e.raw is not None]
    assert any(p and p.endswith("osv.json") for p in paths), paths


# ---------------------------------------------------------------------------
# D16 — SARIF tool.driver that is not an object
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("driver", ["semgrep", ["semgrep"], 5], ids=["str", "list", "int"])
def test_sarif_driver_that_is_not_an_object_falls_back_to_unknown_tool(
    tmp_path: Path, driver: object
) -> None:
    path = tmp_path / "scan.sarif"
    path.write_text(
        json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": driver}, "results": []}]}),
        encoding="utf-8",
    )
    parsed = parse_sarifs(path)
    assert [p.tool_name for p in parsed] == ["unknown-sarif-tool"]


# ---------------------------------------------------------------------------
# D17 — garak: non-finite counts and unreadable JSONL records
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("literal", ["Infinity", "-Infinity", "NaN"])
def test_garak_digest_with_a_non_finite_count_is_not_fatal(tmp_path: Path, literal: str) -> None:
    path = tmp_path / "garak.report.jsonl"
    path.write_text(
        '{"entry_type": "init", "garak_version": "0.9"}\n'
        f'{{"entry_type": "digest", "probe": "p.a", "attempts": {literal}, "hits": {literal}}}\n'
        '{"entry_type": "digest", "probe": "p.b", "attempts": 4, "hits": 1}\n',
        encoding="utf-8",
    )
    parsed = parse_garak(path)
    by_probe = {p.probe: p for p in parsed.probes}
    assert (by_probe["p.b"].attempts, by_probe["p.b"].hits) == (4, 1)
    assert (by_probe["p.a"].attempts, by_probe["p.a"].hits) == (0, 0)


@pytest.mark.parametrize(
    "garbled",
    ["[" * 60_000 + "]" * 60_000, '{"n": ' + "9" * 5000 + "}"],
    ids=["deeply-nested", "overlong-int"],
)
def test_garak_skips_a_garbled_record_as_its_docstring_promises(
    tmp_path: Path, garbled: str
) -> None:
    path = tmp_path / "garak.report.jsonl"
    path.write_text(
        garbled + "\n" + '{"entry_type": "digest", "probe": "p.b", "attempts": 4, "hits": 1}\n',
        encoding="utf-8",
    )
    parsed = parse_garak(path)
    assert [p.probe for p in parsed.probes] == ["p.b"]
