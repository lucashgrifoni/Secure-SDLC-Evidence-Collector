"""T6.7 — Unit tests for the multi-VEX consumer (OpenVEX + CycloneDX + CSAF)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from evidence_collector.domain.enums import (
    ConfidenceLevel,
    EvidenceStatus,
    EvidenceType,
    ReleaseStatus,
    SubjectType,
)
from evidence_collector.domain.models import (
    Application,
    EvidenceBundle,
    EvidenceSource,
    NormalizedEvidence,
    ReleaseContext,
    Summary,
)
from evidence_collector.exporters.vex import (
    MergeConflictPolicy,
    VexMergeConflictError,
    build_openvex,
    merge_consumed_vex,
)
from evidence_collector.parsers._common import ParseError
from evidence_collector.parsers.vex import parse_vex


def _bundle_with_cve(cve_id: str) -> EvidenceBundle:
    evidence = NormalizedEvidence(
        evidence_id="sca-1",
        evidence_type=EvidenceType.SCA_SCAN,
        source=EvidenceSource(name="trivy", kind="sca"),
        producer="trivy",
        subject_type=SubjectType.ARTIFACT,
        subject_ref="acme/api@1.0",
        status=EvidenceStatus.GENERATED,
        confidence=ConfidenceLevel.HIGH,
        release_id="2026.05.19",
        commit_sha="abcdef1234567890",
        cve_ids=[cve_id],
    )
    return EvidenceBundle(
        bundle_id="bundle-vex-merge-test",
        application=Application(name="acme-api", repository="acme/api"),
        release=ReleaseContext(release_id="2026.05.19", commit_sha="abcdef1234567890"),
        evidence=[evidence],
        control_evaluations=[],
        gaps=[],
        exceptions=[],
        summary=Summary(
            total_controls=0,
            controls_met=0,
            controls_partial=0,
            controls_missing=0,
            controls_waived=0,
            controls_not_applicable=0,
            release_status=ReleaseStatus.READY,
            evidence_coverage_score=0,
            confidence_score=0,
        ),
    )


def test_parse_openvex_extracts_statements(tmp_path: Path) -> None:
    vex_path = tmp_path / "vendor.openvex.json"
    vex_path.write_text(
        json.dumps(
            {
                "@context": "https://openvex.dev/ns/v0.2.0",
                "statements": [
                    {
                        "vulnerability": {"name": "CVE-2024-1111"},
                        "status": "not_affected",
                        "justification": "vulnerable_code_not_present",
                    },
                    {
                        "vulnerability": {"name": "CVE-2024-2222"},
                        "status": "affected",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    statements = parse_vex(vex_path)
    assert len(statements) == 2
    by_cve = {s.cve_id: s for s in statements}
    assert by_cve["CVE-2024-1111"].status == "not_affected"
    assert by_cve["CVE-2024-1111"].source_shape == "openvex"


def test_parse_cyclonedx_vex_translates_state(tmp_path: Path) -> None:
    vex_path = tmp_path / "vendor.cdx.json"
    vex_path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.7",
                "vulnerabilities": [
                    {
                        "id": "CVE-2024-3333",
                        "analysis": {
                            "state": "not_affected",
                            "justification": "code_not_reachable",
                            "detail": "Function never called.",
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    statements = parse_vex(vex_path)
    assert len(statements) == 1
    assert statements[0].status == "not_affected"
    assert statements[0].source_shape == "cyclonedx-vex"


def test_parse_csaf_translates_product_status(tmp_path: Path) -> None:
    vex_path = tmp_path / "vendor.csaf.json"
    vex_path.write_text(
        json.dumps(
            {
                "document": {"category": "csaf_vex", "title": "vendor advisory"},
                "vulnerabilities": [
                    {
                        "cve": "CVE-2024-4444",
                        "product_status": {"known_not_affected": ["product-1"]},
                    },
                    {
                        "cve": "CVE-2024-5555",
                        "product_status": {"known_affected": ["product-1"]},
                        "threats": [{"details": "Used in active campaigns."}],
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    statements = parse_vex(vex_path)
    by_cve = {s.cve_id: s for s in statements}
    assert by_cve["CVE-2024-4444"].status == "not_affected"
    assert by_cve["CVE-2024-5555"].status == "affected"
    assert "active campaigns" in (by_cve["CVE-2024-5555"].detail or "")


def test_parse_vex_rejects_unknown_shape(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text('{"foo": "bar"}', encoding="utf-8")
    with pytest.raises(ParseError):
        parse_vex(bad)


def test_merge_last_wins_overrides_bundle_statement() -> None:
    bundle = _bundle_with_cve("CVE-2024-1111")
    doc = build_openvex(bundle)
    # Bundle gave the CVE ``under_investigation``; vendor says not_affected.
    consumed = list(parse_vex_inline_openvex("CVE-2024-1111", "not_affected"))
    merged = merge_consumed_vex(doc, bundle, consumed, policy=MergeConflictPolicy.LAST_WINS)
    statements = merged["statements"]
    cve_statement = next(s for s in statements if s["vulnerability"]["name"] == "CVE-2024-1111")
    assert cve_statement["status"] == "not_affected"


def test_merge_first_wins_keeps_bundle_statement() -> None:
    bundle = _bundle_with_cve("CVE-2024-1111")
    doc = build_openvex(bundle)
    consumed = list(parse_vex_inline_openvex("CVE-2024-1111", "not_affected"))
    merged = merge_consumed_vex(doc, bundle, consumed, policy=MergeConflictPolicy.FIRST_WINS)
    statements = merged["statements"]
    cve_statement = next(s for s in statements if s["vulnerability"]["name"] == "CVE-2024-1111")
    # Bundle's ``under_investigation`` preserved.
    assert cve_statement["status"] == "under_investigation"


def test_merge_fail_raises_on_disagreement() -> None:
    bundle = _bundle_with_cve("CVE-2024-1111")
    doc = build_openvex(bundle)
    consumed = list(parse_vex_inline_openvex("CVE-2024-1111", "not_affected"))
    with pytest.raises(VexMergeConflictError):
        merge_consumed_vex(doc, bundle, consumed, policy=MergeConflictPolicy.FAIL)


def test_merge_adds_new_cves_not_in_bundle() -> None:
    bundle = _bundle_with_cve("CVE-2024-1111")
    doc = build_openvex(bundle)
    consumed = list(parse_vex_inline_openvex("CVE-2024-9999", "fixed"))
    merged = merge_consumed_vex(doc, bundle, consumed, policy=MergeConflictPolicy.LAST_WINS)
    cve_ids = sorted(s["vulnerability"]["name"] for s in merged["statements"])
    assert cve_ids == ["CVE-2024-1111", "CVE-2024-9999"]


def parse_vex_inline_openvex(cve_id: str, status: str):
    """Helper: build VexStatement(s) without writing files."""
    from evidence_collector.parsers.vex import VexStatement

    yield VexStatement(
        cve_id=cve_id,
        status=status,
        justification=(
            "vulnerable_code_not_present" if status == "not_affected" else None
        ),
        source_shape="openvex",
        source_path="<test>",
    )
