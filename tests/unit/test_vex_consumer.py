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
from evidence_collector.parsers.vex import VexStatement, parse_vex

_RELEASE_PURL = "pkg:generic/acme/api@2026.05.19"


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
        justification=("vulnerable_code_not_present" if status == "not_affected" else None),
        source_shape="openvex",
        source_path="<test>",
        products=(_RELEASE_PURL,),
    )


def _openvex_file(tmp_path: Path, products: list[object], cve: str = "CVE-2024-1111") -> Path:
    path = tmp_path / "vendor.openvex.json"
    path.write_text(
        json.dumps(
            {
                "@context": "https://openvex.dev/ns/v0.2.0",
                "statements": [
                    {
                        "vulnerability": {"name": cve},
                        "products": products,
                        "status": "not_affected",
                        "justification": "vulnerable_code_not_present",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def _status_of(document: dict[str, object], cve: str) -> object:
    statements = document["statements"]
    assert isinstance(statements, list)
    return next(s["status"] for s in statements if s["vulnerability"]["name"] == cve)


def test_a_statement_about_another_product_does_not_silence_the_release_cve(
    tmp_path: Path,
) -> None:
    """A VEX for an unrelated package used to match on the CVE id alone."""
    bundle = _bundle_with_cve("CVE-2024-1111")
    consumed = parse_vex(_openvex_file(tmp_path, [{"@id": "pkg:npm/totally-unrelated@1.0.0"}]))
    skipped: list[VexStatement] = []
    merged = merge_consumed_vex(build_openvex(bundle), bundle, consumed, skipped=skipped)
    assert _status_of(merged, "CVE-2024-1111") == "under_investigation"
    assert len(skipped) == 1


def test_a_statement_naming_a_declared_release_product_applies(tmp_path: Path) -> None:
    bundle = _bundle_with_cve("CVE-2024-1111")
    consumed = parse_vex(_openvex_file(tmp_path, [{"@id": "pkg:pypi/acme-api@1.4.0"}]))
    merged = merge_consumed_vex(
        build_openvex(bundle), bundle, consumed, products=["pkg:pypi/acme-api@1.4.0"]
    )
    assert _status_of(merged, "CVE-2024-1111") == "not_affected"


def test_a_versionless_product_covers_every_version_but_another_version_does_not(
    tmp_path: Path,
) -> None:
    bundle = _bundle_with_cve("CVE-2024-1111")
    versionless = parse_vex(_openvex_file(tmp_path, ["pkg:pypi/acme-api"]))
    merged = merge_consumed_vex(
        build_openvex(bundle), bundle, versionless, products=["pkg:pypi/acme-api@1.4.0"]
    )
    assert _status_of(merged, "CVE-2024-1111") == "not_affected"

    other_version = parse_vex(_openvex_file(tmp_path, ["pkg:pypi/acme-api@1.3.0"]))
    merged = merge_consumed_vex(
        build_openvex(bundle), bundle, other_version, products=["pkg:pypi/acme-api@1.4.0"]
    )
    assert _status_of(merged, "CVE-2024-1111") == "under_investigation"


def test_a_statement_that_names_no_product_is_skipped(tmp_path: Path) -> None:
    bundle = _bundle_with_cve("CVE-2024-1111")
    consumed = parse_vex(_openvex_file(tmp_path, []))
    skipped: list[VexStatement] = []
    merged = merge_consumed_vex(build_openvex(bundle), bundle, consumed, skipped=skipped)
    assert _status_of(merged, "CVE-2024-1111") == "under_investigation"
    assert len(skipped) == 1


def test_cyclonedx_affects_and_justification_reach_openvex_vocabulary(tmp_path: Path) -> None:
    """CycloneDX justifications were copied verbatim, outside the OpenVEX enum."""
    vex_path = tmp_path / "vendor.cdx.json"
    vex_path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "vulnerabilities": [
                    {
                        "id": "CVE-2024-1111",
                        "affects": [{"ref": "pkg:pypi/acme-api@1.4.0"}],
                        "analysis": {
                            "state": "not_affected",
                            "justification": "code_not_reachable",
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    bundle = _bundle_with_cve("CVE-2024-1111")
    consumed = parse_vex(vex_path)
    assert consumed[0].products == ("pkg:pypi/acme-api@1.4.0",)
    merged = merge_consumed_vex(
        build_openvex(bundle), bundle, consumed, products=["pkg:pypi/acme-api@1.4.0"]
    )
    statement = next(
        s for s in merged["statements"] if s["vulnerability"]["name"] == "CVE-2024-1111"
    )
    assert statement["justification"] == "vulnerable_code_not_in_execute_path"
    assert "source justification=code_not_reachable" in statement["status_notes"]


def test_csaf_product_ids_resolve_to_purls_from_the_product_tree(tmp_path: Path) -> None:
    vex_path = tmp_path / "vendor.csaf.json"
    vex_path.write_text(
        json.dumps(
            {
                "document": {"category": "csaf_vex", "title": "vendor advisory"},
                "product_tree": {
                    "branches": [
                        {
                            "product": {
                                "product_id": "ACME-API-1.4.0",
                                "name": "acme-api 1.4.0",
                                "product_identification_helper": {
                                    "purl": "pkg:pypi/acme-api@1.4.0"
                                },
                            }
                        }
                    ]
                },
                "vulnerabilities": [
                    {
                        "cve": "CVE-2024-1111",
                        "product_status": {"known_not_affected": ["ACME-API-1.4.0"]},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    consumed = parse_vex(vex_path)
    assert consumed[0].products == ("ACME-API-1.4.0", "pkg:pypi/acme-api@1.4.0")


def test_a_versionless_purl_keeps_its_qualifiers(tmp_path: Path) -> None:
    """Dropping qualifiers let an image from another registry match the release."""
    bundle = _bundle_with_cve("CVE-2024-1111")
    release = "pkg:docker/acme/api@1.0?repository_url=registry-b"
    other_registry = parse_vex(
        _openvex_file(tmp_path, ["pkg:docker/acme/api?repository_url=registry-a"])
    )
    merged = merge_consumed_vex(build_openvex(bundle), bundle, other_registry, products=[release])
    assert _status_of(merged, "CVE-2024-1111") == "under_investigation"

    same_registry = parse_vex(
        _openvex_file(tmp_path, ["pkg:docker/acme/api?repository_url=registry-b"])
    )
    merged = merge_consumed_vex(build_openvex(bundle), bundle, same_registry, products=[release])
    assert _status_of(merged, "CVE-2024-1111") == "not_affected"


def _csaf_file(tmp_path: Path, product_tree: dict[str, object], status: dict[str, object]) -> Path:
    path = tmp_path / "vendor.csaf.json"
    path.write_text(
        json.dumps(
            {
                "document": {"category": "csaf_vex", "title": "vendor advisory"},
                "product_tree": product_tree,
                "vulnerabilities": [{"cve": "CVE-2024-1111", "product_status": status}],
            }
        ),
        encoding="utf-8",
    )
    return path


def test_csaf_buckets_with_the_same_status_are_combined(tmp_path: Path) -> None:
    """Only the first affected bucket was read, so `first_affected` products were lost."""
    consumed = parse_vex(
        _csaf_file(
            tmp_path,
            {},
            {
                "known_affected": ["product-a"],
                "first_affected": ["product-b"],
                "known_not_affected": ["product-c"],
            },
        )
    )
    by_status = {stmt.status: stmt.products for stmt in consumed}
    assert by_status == {"affected": ("product-a", "product-b"), "not_affected": ("product-c",)}


def test_csaf_relationship_products_resolve_through_full_product_name(tmp_path: Path) -> None:
    consumed = parse_vex(
        _csaf_file(
            tmp_path,
            {
                "relationships": [
                    {
                        "category": "default_component_of",
                        "product_reference": "lib",
                        "relates_to_product_reference": "platform",
                        "full_product_name": {
                            "product_id": "lib-on-platform",
                            "name": "lib on platform",
                            "product_identification_helper": {"purl": "pkg:pypi/acme-api@1.4.0"},
                        },
                    }
                ]
            },
            {"known_not_affected": ["lib-on-platform"]},
        )
    )
    assert consumed[0].products == ("lib-on-platform", "pkg:pypi/acme-api@1.4.0")


def test_an_at_sign_in_a_non_purl_identifier_is_not_a_version(tmp_path: Path) -> None:
    """`service` must not cover a release product declared as `service@production`."""
    bundle = _bundle_with_cve("CVE-2024-1111")
    consumed = parse_vex(_openvex_file(tmp_path, ["service"]))
    merged = merge_consumed_vex(
        build_openvex(bundle), bundle, consumed, products=["service@production"]
    )
    assert _status_of(merged, "CVE-2024-1111") == "under_investigation"


def _cdx_file(tmp_path: Path, affects: list[object]) -> Path:
    path = tmp_path / "vendor.cdx.json"
    path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "vulnerabilities": [
                    {
                        "id": "CVE-2024-1111",
                        "affects": affects,
                        "analysis": {"state": "not_affected", "justification": "code_not_present"},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def test_cyclonedx_versions_restrict_a_versionless_ref(tmp_path: Path) -> None:
    """A verdict scoped to 1.3.0 covered every version when only the ref was read."""
    bundle = _bundle_with_cve("CVE-2024-1111")
    consumed = parse_vex(
        _cdx_file(
            tmp_path,
            [
                {
                    "ref": "pkg:pypi/acme-api",
                    "versions": [{"version": "1.3.0", "status": "unaffected"}],
                }
            ],
        )
    )
    assert consumed[0].products == ("pkg:pypi/acme-api@1.3.0",)
    merged = merge_consumed_vex(
        build_openvex(bundle), bundle, consumed, products=["pkg:pypi/acme-api@1.4.0"]
    )
    assert _status_of(merged, "CVE-2024-1111") == "under_investigation"


def test_cyclonedx_version_ranges_are_not_read_as_every_version(tmp_path: Path) -> None:
    consumed = parse_vex(
        _cdx_file(
            tmp_path, [{"ref": "pkg:pypi/acme-api", "versions": [{"range": "vers:pypi/<1.4"}]}]
        )
    )
    assert consumed[0].products == ()


def test_a_plain_bom_ref_with_versions_names_no_product(tmp_path: Path) -> None:
    consumed = parse_vex(
        _cdx_file(
            tmp_path,
            [{"ref": "component-a", "versions": [{"version": "1.3", "status": "unaffected"}]}],
        )
    )
    assert consumed[0].products == ()


def test_versioned_purls_match_whatever_the_qualifier_order(tmp_path: Path) -> None:
    bundle = _bundle_with_cve("CVE-2024-1111")
    consumed = parse_vex(_openvex_file(tmp_path, ["pkg:generic/api@1?a=x&b=y"]))
    merged = merge_consumed_vex(
        build_openvex(bundle), bundle, consumed, products=["pkg:generic/api@1?b=y&a=x"]
    )
    assert _status_of(merged, "CVE-2024-1111") == "not_affected"


def test_a_versioned_purl_ref_must_agree_with_its_versions(tmp_path: Path) -> None:
    """`ref@1.4.0` limited to `1.3.0` used to apply to 1.4.0 anyway."""
    disagreeing = parse_vex(
        _cdx_file(
            tmp_path,
            [
                {
                    "ref": "pkg:pypi/acme-api@1.4.0",
                    "versions": [{"version": "1.3.0", "status": "unaffected"}],
                }
            ],
        )
    )
    assert disagreeing[0].products == ()
    agreeing = parse_vex(
        _cdx_file(
            tmp_path,
            [
                {
                    "ref": "pkg:pypi/acme-api@1.4.0",
                    "versions": [{"version": "1.4.0", "status": "unaffected"}],
                }
            ],
        )
    )
    assert agreeing[0].products == ("pkg:pypi/acme-api@1.4.0",)


def test_local_product_ids_do_not_match_across_documents(tmp_path: Path) -> None:
    """Two CSAF files may reuse CSAFPID-0001 for unrelated products."""
    bundle = _bundle_with_cve("CVE-2024-1111")
    first = tmp_path / "a"
    second = tmp_path / "b"
    first.mkdir()
    second.mkdir()
    consumed = [
        *parse_vex(_csaf_file(first, {}, {"known_affected": ["CSAFPID-0001"]})),
        *parse_vex(_csaf_file(second, {}, {"known_not_affected": ["CSAFPID-0001"]})),
    ]
    skipped: list[VexStatement] = []
    merged = merge_consumed_vex(
        build_openvex(bundle), bundle, consumed, products=["CSAFPID-0001"], skipped=skipped
    )
    assert _status_of(merged, "CVE-2024-1111") == "under_investigation"
    assert len(skipped) == 2

    single = parse_vex(_csaf_file(first, {}, {"known_not_affected": ["CSAFPID-0001"]}))
    merged = merge_consumed_vex(build_openvex(bundle), bundle, single, products=["CSAFPID-0001"])
    assert _status_of(merged, "CVE-2024-1111") == "not_affected"


def test_purl_versions_are_compared_decoded(tmp_path: Path) -> None:
    agreeing = parse_vex(
        _cdx_file(
            tmp_path,
            [
                {
                    "ref": "pkg:deb/acme@1.0%2Bdeb1",
                    "versions": [{"version": "1.0+deb1", "status": "unaffected"}],
                }
            ],
        )
    )
    assert agreeing[0].products == ("pkg:deb/acme@1.0%2Bdeb1",)
    built = parse_vex(
        _cdx_file(
            tmp_path,
            [
                {
                    "ref": "pkg:deb/acme",
                    "versions": [{"version": "1.0+deb1", "status": "unaffected"}],
                }
            ],
        )
    )
    assert built[0].products == ("pkg:deb/acme@1.0%2Bdeb1",)
    bundle = _bundle_with_cve("CVE-2024-1111")
    merged = merge_consumed_vex(
        build_openvex(bundle), bundle, built, products=["pkg:deb/acme@1.0+deb1"]
    )
    assert _status_of(merged, "CVE-2024-1111") == "not_affected"


def test_a_bom_link_still_matches_across_documents(tmp_path: Path) -> None:
    bundle = _bundle_with_cve("CVE-2024-1111")
    link = "urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1#component-a"
    first = tmp_path / "a"
    second = tmp_path / "b"
    first.mkdir()
    second.mkdir()
    consumed = [
        *parse_vex(_cdx_file(first, [{"ref": link}])),
        *parse_vex(_openvex_file(second, ["pkg:npm/unrelated@1.0.0"], cve="CVE-2024-2222")),
    ]
    merged = merge_consumed_vex(build_openvex(bundle), bundle, consumed, products=[link])
    assert _status_of(merged, "CVE-2024-1111") == "not_affected"


def test_a_cyclonedx_version_marked_affected_is_not_called_not_affected(tmp_path: Path) -> None:
    """`versions[].status` defaults to affected; a not_affected analysis cannot cover it."""
    consumed = parse_vex(
        _cdx_file(
            tmp_path,
            [
                {
                    "ref": "pkg:pypi/acme-api",
                    "versions": [
                        {"version": "1.3.0", "status": "unaffected"},
                        {"version": "1.4.0", "status": "affected"},
                        {"version": "1.5.0"},
                    ],
                }
            ],
        )
    )
    assert consumed[0].products == ("pkg:pypi/acme-api@1.3.0",)


def test_cyclonedx_bom_refs_resolve_to_the_component_purl(tmp_path: Path) -> None:
    """An opaque `affects[].ref` named only `component-a`, so `--product pkg:...` never matched."""
    path = tmp_path / "vendor.cdx.json"
    path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [
                    {
                        "bom-ref": "component-a",
                        "name": "acme-api",
                        "purl": "pkg:pypi/acme-api",
                    }
                ],
                "vulnerabilities": [
                    {
                        "id": "CVE-2024-1111",
                        "affects": [
                            {"ref": "component-a"},
                            {
                                "ref": "component-a",
                                "versions": [{"version": "1.3.0", "status": "unaffected"}],
                            },
                        ],
                        "analysis": {"state": "not_affected"},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    consumed = parse_vex(path)
    assert consumed[0].products == (
        "component-a",
        "pkg:pypi/acme-api",
        "pkg:pypi/acme-api@1.3.0",
    )


def test_an_absolute_iri_still_matches_across_documents(tmp_path: Path) -> None:
    bundle = _bundle_with_cve("CVE-2024-1111")
    iri = "https://vendor.example/products/api/1"
    first = tmp_path / "a"
    second = tmp_path / "b"
    first.mkdir()
    second.mkdir()
    consumed = [
        *parse_vex(_openvex_file(first, [{"@id": iri}])),
        *parse_vex(_openvex_file(second, ["pkg:npm/unrelated@1.0.0"], cve="CVE-2024-2222")),
    ]
    merged = merge_consumed_vex(build_openvex(bundle), bundle, consumed, products=[iri])
    assert _status_of(merged, "CVE-2024-1111") == "not_affected"


def test_a_resolved_bom_ref_keeps_the_component_version(tmp_path: Path) -> None:
    """`version: 1.3.0` beside a versionless purl must not become a wildcard."""
    path = tmp_path / "vendor.cdx.json"
    path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [
                    {
                        "bom-ref": "component-a",
                        "name": "acme-api",
                        "version": "1.3.0",
                        "purl": "pkg:pypi/acme-api",
                    }
                ],
                "vulnerabilities": [
                    {
                        "id": "CVE-2024-1111",
                        "affects": [{"ref": "component-a"}],
                        "analysis": {"state": "not_affected"},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    consumed = parse_vex(path)
    assert consumed[0].products == ("component-a", "pkg:pypi/acme-api@1.3.0")
    bundle = _bundle_with_cve("CVE-2024-1111")
    merged = merge_consumed_vex(
        build_openvex(bundle), bundle, consumed, products=["pkg:pypi/acme-api@1.4.0"]
    )
    assert _status_of(merged, "CVE-2024-1111") == "under_investigation"
