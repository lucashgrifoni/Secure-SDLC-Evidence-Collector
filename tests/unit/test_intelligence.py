"""Unit tests for the EPSS + CISA KEV enrichment pipeline.

Synthetic feeds keep the tests offline and deterministic; no network IO
runs even when these tests are exercised in CI.
"""

from __future__ import annotations

import gzip
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from evidence_collector.domain.enums import (
    ConfidenceLevel,
    EvidenceStatus,
    EvidenceType,
    SubjectType,
)
from evidence_collector.domain.models import (
    EvidenceSource,
    NormalizedEvidence,
    ReleaseContext,
)
from evidence_collector.intelligence import (
    enrich_bundle,
    enrich_evidence,
    load_epss_feed,
    load_kev_feed,
)


@pytest.fixture
def synth_epss(tmp_path: Path) -> Path:
    body = (
        "#model_version:v2026.05.01,score_date:2026-05-17T00:00:00+0000\n"
        "cve,epss,percentile\n"
        "CVE-2023-1111,0.92345,0.99001\n"
        "CVE-2023-2222,0.55000,0.85000\n"
        "CVE-2024-9999,0.01000,0.20000\n"
    )
    path = tmp_path / "epss.csv"
    path.write_text(body, encoding="utf-8")
    return path


@pytest.fixture
def synth_epss_gz(tmp_path: Path) -> Path:
    body = (
        "#model_version:v2026.05.01,score_date:2026-05-17T00:00:00+0000\n"
        "cve,epss,percentile\n"
        "CVE-2023-1111,0.97000,0.99500\n"
    )
    path = tmp_path / "epss.csv.gz"
    with gzip.open(path, "wb") as fh:
        fh.write(body.encode("utf-8"))
    return path


@pytest.fixture
def synth_kev(tmp_path: Path) -> Path:
    body: dict[str, Any] = {
        "title": "synthetic",
        "catalogVersion": "2026.05.17",
        "dateReleased": "2026-05-17T00:00:00.000Z",
        "vulnerabilities": [
            {
                "cveID": "CVE-2023-1111",
                "vendorProject": "AcmeCorp",
                "product": "AcmeServer",
                "vulnerabilityName": "Acme RCE",
                "dateAdded": "2023-08-01",
                "knownRansomwareCampaignUse": "Known",
            },
            {
                "cveID": "CVE-2024-5555",
                "vendorProject": "Globex",
                "product": "GlobexDB",
                "vulnerabilityName": "Globex SQLi",
                "dateAdded": "2024-04-10",
                "knownRansomwareCampaignUse": "Unknown",
            },
        ],
    }
    path = tmp_path / "kev.json"
    path.write_text(json.dumps(body), encoding="utf-8")
    return path


def _build_evidence(cve_ids: list[str]) -> NormalizedEvidence:
    return NormalizedEvidence(
        evidence_id="sca-test-0001",
        evidence_type=EvidenceType.SCA_SCAN,
        source=EvidenceSource(name="trivy", kind="sarif", version="0.50.0"),
        producer="trivy",
        subject_type=SubjectType.COMMIT,
        subject_ref="abcdef1234567890",
        status=EvidenceStatus.GENERATED,
        confidence=ConfidenceLevel.HIGH,
        release_id="2026.05.17",
        commit_sha="abcdef1234567890",
        cve_ids=cve_ids,
    )


def test_load_epss_feed_reads_score_date(synth_epss: Path) -> None:
    feed = load_epss_feed(synth_epss)
    assert feed.feed_date == "2026-05-17"
    record = feed.get("CVE-2023-1111")
    assert record is not None
    assert record.epss_score == pytest.approx(0.92345)
    assert record.epss_percentile == pytest.approx(0.99001)


def test_load_epss_feed_reads_model_version(synth_epss: Path) -> None:
    assert load_epss_feed(synth_epss).model_version == "v2026.05.01"


def test_load_epss_feed_model_version_none_without_header(tmp_path: Path) -> None:
    path = tmp_path / "epss.csv"
    path.write_text("cve,epss,percentile\nCVE-2023-1111,0.5,0.5\n", encoding="utf-8")
    feed = load_epss_feed(path)
    assert feed.model_version is None
    assert feed.get("CVE-2023-1111") is not None


def test_enrich_evidence_records_epss_model_version(synth_epss: Path, synth_kev: Path) -> None:
    enriched = enrich_evidence(
        _build_evidence(["CVE-2023-1111"]),
        load_epss_feed(synth_epss),
        load_kev_feed(synth_kev),
    )
    intel = enriched.vulnerability_intelligence
    assert intel is not None
    assert intel.epss_model_version == "v2026.05.01"
    assert intel.epss_feed_date == "2026-05-17"


def test_load_epss_feed_handles_gzip(synth_epss_gz: Path) -> None:
    feed = load_epss_feed(synth_epss_gz)
    assert feed.feed_date == "2026-05-17"
    assert feed.get("CVE-2023-1111") is not None


def test_load_epss_feed_returns_empty_on_missing_file(tmp_path: Path) -> None:
    feed = load_epss_feed(tmp_path / "absent.csv")
    assert feed.feed_date is None
    assert feed.records == {}


def test_load_kev_feed_parses_ransomware_flag(synth_kev: Path) -> None:
    feed = load_kev_feed(synth_kev)
    assert feed.feed_date is not None
    rec = feed.get("CVE-2023-1111")
    assert rec is not None
    assert rec.known_ransomware_use is True
    rec2 = feed.get("CVE-2024-5555")
    assert rec2 is not None and rec2.known_ransomware_use is False


def test_load_kev_feed_empty_when_missing(tmp_path: Path) -> None:
    feed = load_kev_feed(tmp_path / "absent.json")
    assert feed.records == {}


def test_enrich_evidence_skips_when_no_cves(synth_epss: Path, synth_kev: Path) -> None:
    evidence = _build_evidence([])
    epss = load_epss_feed(synth_epss)
    kev = load_kev_feed(synth_kev)
    enriched = enrich_evidence(evidence, epss, kev)
    assert enriched is evidence  # untouched copy


def test_enrich_evidence_summarises_max_epss(synth_epss: Path, synth_kev: Path) -> None:
    evidence = _build_evidence(["CVE-2023-1111", "CVE-2023-2222", "CVE-2024-9999"])
    epss = load_epss_feed(synth_epss)
    kev = load_kev_feed(synth_kev)
    enriched = enrich_evidence(evidence, epss, kev, now=datetime(2026, 5, 17, 12, 0, tzinfo=UTC))

    intel = enriched.vulnerability_intelligence
    assert intel is not None
    assert intel.cve_count == 3
    assert intel.max_epss_score == pytest.approx(0.92345)
    assert intel.cves_in_kev_count == 1
    assert intel.cves_known_ransomware_count == 1
    assert len(intel.top_risk_cves) == 3
    assert intel.top_risk_cves[0].cve_id == "CVE-2023-1111"
    assert intel.top_risk_cves[0].in_kev is True
    assert intel.top_risk_cves[0].known_ransomware is True


def test_enrich_evidence_deduplicates_cve_ids(synth_epss: Path, synth_kev: Path) -> None:
    evidence = _build_evidence(["CVE-2023-1111", "cve-2023-1111", "CVE-2023-1111"])
    enriched = enrich_evidence(
        evidence,
        load_epss_feed(synth_epss),
        load_kev_feed(synth_kev),
    )
    intel = enriched.vulnerability_intelligence
    assert intel is not None
    assert intel.cve_count == 1


def test_enrich_bundle_reports_aggregates(
    synth_epss: Path, synth_kev: Path, sample_release: ReleaseContext
) -> None:
    from evidence_collector.domain.enums import ReleaseStatus
    from evidence_collector.domain.models import Application, EvidenceBundle, Summary

    distinct_evidence = [
        _build_evidence(["CVE-2023-1111"]),
        _build_evidence([]),
        _build_evidence(["CVE-2024-5555", "CVE-2024-9999"]),
    ]
    # NormalizedEvidence requires unique evidence_id per record; rebuild
    # with distinct ids so EvidenceBundle accepts the list.
    distinct_evidence[1] = distinct_evidence[1].model_copy(update={"evidence_id": "no-cve-evt"})
    distinct_evidence[2] = distinct_evidence[2].model_copy(update={"evidence_id": "sca-test-0002"})

    bundle = EvidenceBundle(
        bundle_id="bundle-test",
        application=Application(name="x", repository="x/y"),
        release=sample_release,
        evidence=distinct_evidence,
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
    epss = load_epss_feed(synth_epss)
    kev = load_kev_feed(synth_kev)
    enriched, report = enrich_bundle(bundle, epss, kev)
    assert report.evidence_with_cves == 2
    assert report.distinct_cves == 3
    assert report.cves_in_kev == 2
    assert report.epss_feed_date == "2026-05-17"
    # Original bundle untouched
    assert bundle.evidence[0].vulnerability_intelligence is None
    assert enriched.evidence[0].vulnerability_intelligence is not None
