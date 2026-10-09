"""``--risk-mode epss-weighted`` must be able to change the verdict end to end (D02).

``apply_risk_mode`` runs inside ``build_bundle`` on freshly collected evidence,
which never carries EPSS / KEV intelligence: only ``enrich`` attaches it, and
only to an existing bundle. So ``run --risk-mode epss-weighted`` always said
"no vulnerability intelligence ... Run 'enrich' first", and running ``enrich``
afterwards attached KEV / ransomware / EPSS data while leaving
``release_status`` and ``risk_assessment`` exactly as they were.

The documented flow is ``run --risk-mode epss-weighted`` then ``enrich``.
``enrich`` now re-derives the verdict under the risk mode recorded in the
bundle. A bundle built in the default mode keeps its verdict untouched.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from evidence_collector.cli.main import app
from evidence_collector.domain.enums import ReleaseStatus
from evidence_collector.domain.models import EvidenceBundle

# examples/sample_release/artifacts/trivy.sarif reports exactly this CVE.
SAMPLE_CVE = "CVE-2024-12345"


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def _run(runner: CliRunner, sample_release_root: Path, out: Path, *extra: str) -> EvidenceBundle:
    result = runner.invoke(
        app,
        [
            "run",
            "--application",
            "payments-api",
            "--repository",
            "acme/payments-api",
            "--release-id",
            "2026.04.10",
            "--commit-sha",
            "abcdef1234567890",
            "--artifacts-dir",
            str(sample_release_root / "artifacts"),
            "--attestations-dir",
            str(sample_release_root / "attestations"),
            "--output-dir",
            str(out),
            *extra,
        ],
    )
    assert result.exit_code == 0, result.output
    return EvidenceBundle.model_validate_json((out / "bundle.json").read_text(encoding="utf-8"))


def _kev_feed(tmp_path: Path, *, ransomware: bool) -> Path:
    path = tmp_path / "kev.json"
    path.write_text(
        json.dumps(
            {
                "title": "synthetic",
                "catalogVersion": "2026.08.01",
                "dateReleased": "2026-08-01T00:00:00.000Z",
                "vulnerabilities": [
                    {
                        "cveID": SAMPLE_CVE,
                        "vendorProject": "Python",
                        "product": "requests",
                        "vulnerabilityName": "synthetic",
                        "dateAdded": "2026-07-01",
                        "knownRansomwareCampaignUse": "Known" if ransomware else "Unknown",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def _epss_feed(tmp_path: Path, percentile: str) -> Path:
    path = tmp_path / "epss.csv"
    path.write_text(
        "#model_version:v2026.06.15,score_date:2026-08-01T00:00:00+0000\n"
        "cve,epss,percentile\n"
        f"{SAMPLE_CVE},0.97132,{percentile}\n",
        encoding="utf-8",
    )
    return path


def _enrich(runner: CliRunner, bundle: Path, target: Path, *feeds: str) -> EvidenceBundle:
    result = runner.invoke(app, ["enrich", str(bundle), "--output", str(target), *feeds])
    assert result.exit_code == 0, result.output
    return EvidenceBundle.model_validate_json(target.read_text(encoding="utf-8"))


@pytest.mark.integration
def test_enrich_applies_the_recorded_risk_mode_kev_ransomware_blocks(
    runner: CliRunner, sample_release_root: Path, tmp_path: Path
) -> None:
    built = _run(runner, sample_release_root, tmp_path / "out", "--risk-mode", "epss-weighted")
    assert built.summary.release_status is ReleaseStatus.READY
    assert built.summary.risk_assessment is not None
    assert "no vulnerability intelligence" in built.summary.risk_assessment.rationale

    enriched = _enrich(
        runner,
        tmp_path / "out" / "bundle.json",
        tmp_path / "enriched.json",
        "--kev-feed",
        str(_kev_feed(tmp_path, ransomware=True)),
        "--epss-feed",
        str(_epss_feed(tmp_path, "0.99900")),
    )
    assessment = enriched.summary.risk_assessment
    assert enriched.summary.release_status is ReleaseStatus.NOT_READY
    assert assessment is not None
    assert assessment.mode == "epss-weighted"
    assert assessment.base_release_status is ReleaseStatus.READY
    assert assessment.kev_ransomware_cve_count == 1
    assert assessment.kev_cve_count == 1
    assert "no vulnerability intelligence" not in assessment.rationale


@pytest.mark.integration
def test_enrich_kev_ransomware_without_epss_record_blocks(
    runner: CliRunner, sample_release_root: Path, tmp_path: Path
) -> None:
    """D02 + D07 together: KEV-only feed, the CVE has no EPSS record at all."""
    _run(runner, sample_release_root, tmp_path / "out", "--risk-mode", "epss-weighted")
    enriched = _enrich(
        runner,
        tmp_path / "out" / "bundle.json",
        tmp_path / "enriched.json",
        "--kev-feed",
        str(_kev_feed(tmp_path, ransomware=True)),
    )
    assert enriched.summary.release_status is ReleaseStatus.NOT_READY
    assert enriched.summary.risk_assessment is not None
    assert enriched.summary.risk_assessment.kev_ransomware_cve_count == 1


@pytest.mark.integration
def test_enrich_high_epss_downgrades_to_conditional_under_recorded_threshold(
    runner: CliRunner, sample_release_root: Path, tmp_path: Path
) -> None:
    _run(
        runner,
        sample_release_root,
        tmp_path / "out",
        "--risk-mode",
        "epss-weighted",
        "--epss-percentile-threshold",
        "0.95",
    )
    enriched = _enrich(
        runner,
        tmp_path / "out" / "bundle.json",
        tmp_path / "enriched.json",
        "--epss-feed",
        str(_epss_feed(tmp_path, "0.96000")),
    )
    assert enriched.summary.release_status is ReleaseStatus.CONDITIONAL
    assert enriched.summary.risk_assessment is not None
    assert enriched.summary.risk_assessment.epss_percentile_threshold == pytest.approx(0.95)
    assert enriched.summary.risk_assessment.high_epss_cve_count == 1


@pytest.mark.integration
def test_re_enrich_reflects_the_newer_feed_not_the_previous_verdict(
    runner: CliRunner, sample_release_root: Path, tmp_path: Path
) -> None:
    """The verdict is re-derived from ``base_release_status``, never compounded."""
    _run(runner, sample_release_root, tmp_path / "out", "--risk-mode", "epss-weighted")
    first = tmp_path / "first.json"
    _enrich(
        runner,
        tmp_path / "out" / "bundle.json",
        first,
        "--epss-feed",
        str(_epss_feed(tmp_path, "0.99000")),
    )
    second = _enrich(
        runner,
        first,
        tmp_path / "second.json",
        "--epss-feed",
        str(_epss_feed(tmp_path, "0.10000")),
    )
    assert second.summary.release_status is ReleaseStatus.READY
    assert second.summary.risk_assessment is not None
    assert second.summary.risk_assessment.base_release_status is ReleaseStatus.READY
    assert "No exploitable CVEs detected" in second.summary.risk_assessment.rationale


@pytest.mark.integration
def test_enrich_never_changes_the_verdict_of_a_default_mode_bundle(
    runner: CliRunner, sample_release_root: Path, tmp_path: Path
) -> None:
    built = _run(runner, sample_release_root, tmp_path / "out")
    enriched = _enrich(
        runner,
        tmp_path / "out" / "bundle.json",
        tmp_path / "enriched.json",
        "--kev-feed",
        str(_kev_feed(tmp_path, ransomware=True)),
    )
    assert enriched.evidence != built.evidence  # intelligence was attached
    assert enriched.summary == built.summary
    assert enriched.summary.risk_assessment is None
    assert enriched.summary.release_status is ReleaseStatus.READY


_EVALUATE = [
    "evaluate",
    "--application",
    "payments-api",
    "--repository",
    "acme/payments-api",
    "--release-id",
    "2026.04.10",
    "--commit-sha",
    "abcdef1234567890",
]


@pytest.mark.integration
def test_evaluate_accepts_risk_mode_on_enriched_evidence(
    runner: CliRunner, sample_release_root: Path, tmp_path: Path
) -> None:
    """``evaluate --risk-mode`` weighs intelligence already on the evidence list."""
    _run(runner, sample_release_root, tmp_path / "out")
    enriched = _enrich(
        runner,
        tmp_path / "out" / "bundle.json",
        tmp_path / "enriched.json",
        "--kev-feed",
        str(_kev_feed(tmp_path, ransomware=True)),
    )
    evidence_file = tmp_path / "evidence.json"
    evidence_file.write_text(
        json.dumps({"evidence": [e.model_dump(mode="json") for e in enriched.evidence]}),
        encoding="utf-8",
    )
    common = [*_EVALUATE, "--evidence", str(evidence_file)]
    off = runner.invoke(app, [*common, "--output-dir", str(tmp_path / "off")])
    assert off.exit_code == 0, off.output

    weighted = runner.invoke(
        app,
        [
            *common,
            "--output-dir",
            str(tmp_path / "weighted"),
            "--risk-mode",
            "epss-weighted",
            "--epss-percentile-threshold",
            "0.9",
        ],
    )
    assert weighted.exit_code == 2, weighted.output  # default --fail-on not_ready
    bundle = EvidenceBundle.model_validate_json(
        (tmp_path / "weighted" / "bundle.json").read_text(encoding="utf-8")
    )
    assert bundle.summary.release_status is ReleaseStatus.NOT_READY
    assert bundle.summary.risk_assessment is not None
    assert bundle.summary.risk_assessment.kev_ransomware_cve_count == 1
    assert bundle.summary.risk_assessment.epss_percentile_threshold == pytest.approx(0.9)


@pytest.mark.integration
def test_evaluate_rejects_an_unknown_risk_mode(runner: CliRunner, tmp_path: Path) -> None:
    evidence_file = tmp_path / "evidence.json"
    evidence_file.write_text("[]", encoding="utf-8")
    result = runner.invoke(
        app,
        [
            *_EVALUATE,
            "--evidence",
            str(evidence_file),
            "--output-dir",
            str(tmp_path / "o"),
            "--risk-mode",
            "bogus",
        ],
    )
    assert result.exit_code == 2, result.output
    assert not (tmp_path / "o" / "bundle.json").exists()


@pytest.mark.integration
def test_enrich_exits_three_on_an_unknown_recorded_risk_mode(
    runner: CliRunner, sample_release_root: Path, tmp_path: Path
) -> None:
    _run(runner, sample_release_root, tmp_path / "out", "--risk-mode", "epss-weighted")
    bundle_path = tmp_path / "out" / "bundle.json"
    raw = json.loads(bundle_path.read_text(encoding="utf-8"))
    raw["summary"]["risk_assessment"]["mode"] = "cvss-weighted"
    bundle_path.write_text(json.dumps(raw), encoding="utf-8")
    target = tmp_path / "enriched.json"
    result = runner.invoke(
        app,
        [
            "enrich",
            str(bundle_path),
            "--output",
            str(target),
            "--kev-feed",
            str(_kev_feed(tmp_path, ransomware=True)),
        ],
    )
    assert result.exit_code == 3, result.output
    assert not target.exists()


# ---------------------------------------------------------------------------
# enrich with no feed consults no source: it must not overwrite intelligence or
# re-derive the verdict (Codex P1 on #147). Re-enriching a not_ready bundle with
# plain `enrich bundle.json` replaced every CVE's intelligence with data from two
# empty feeds and promoted the release back to its presence-based status, with a
# rationale claiming no exploitable CVEs.
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_enrich_without_feeds_keeps_the_prior_risk_verdict_and_intelligence(
    runner: CliRunner, sample_release_root: Path, tmp_path: Path
) -> None:
    _run(runner, sample_release_root, tmp_path / "out", "--risk-mode", "epss-weighted")
    blocked = _enrich(
        runner,
        tmp_path / "out" / "bundle.json",
        tmp_path / "blocked.json",
        "--kev-feed",
        str(_kev_feed(tmp_path, ransomware=True)),
    )
    assert blocked.summary.release_status is ReleaseStatus.NOT_READY

    target = tmp_path / "again.json"
    result = runner.invoke(app, ["enrich", str(tmp_path / "blocked.json"), "--output", str(target)])
    assert result.exit_code == 0, result.output
    assert "no feed" in result.output.lower()
    again = EvidenceBundle.model_validate_json(target.read_text(encoding="utf-8"))
    assert again.summary == blocked.summary
    assert again.summary.release_status is ReleaseStatus.NOT_READY
    assert again.evidence == blocked.evidence


@pytest.mark.integration
def test_enrich_without_feeds_in_place_leaves_the_bundle_unchanged(
    runner: CliRunner, sample_release_root: Path, tmp_path: Path
) -> None:
    _run(runner, sample_release_root, tmp_path / "out", "--risk-mode", "epss-weighted")
    blocked = tmp_path / "blocked.json"
    _enrich(
        runner,
        tmp_path / "out" / "bundle.json",
        blocked,
        "--kev-feed",
        str(_kev_feed(tmp_path, ransomware=True)),
    )
    before = blocked.read_bytes()
    result = runner.invoke(app, ["enrich", str(blocked)])
    assert result.exit_code == 0, result.output
    assert blocked.read_bytes() == before


# ---------------------------------------------------------------------------
# The CRA projection's exploitation signal is computed by `run --profile
# cra-2026` before any intelligence exists ("unavailable"); enrich must refresh
# it (Codex P2 on #147).
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_enrich_refreshes_the_cra_global_exploitation_signal(
    runner: CliRunner, sample_release_root: Path, tmp_path: Path
) -> None:
    built = _run(runner, sample_release_root, tmp_path / "out", "--profile", "cra-2026")

    def signals(bundle: EvidenceBundle) -> dict[str, str]:
        return {
            e.evidence_id: e.metadata["cra"]["global_exploitation_signal"] for e in bundle.evidence
        }

    cve_ids = {e.evidence_id for e in built.evidence if SAMPLE_CVE in e.cve_ids}
    assert cve_ids
    assert set(signals(built).values()) == {"unavailable"}

    enriched = _enrich(
        runner,
        tmp_path / "out" / "bundle.json",
        tmp_path / "enriched.json",
        "--kev-feed",
        str(_kev_feed(tmp_path, ransomware=False)),
    )
    after = signals(enriched)
    assert {after[i] for i in cve_ids} == {"kev_listed"}
    # Records without CVEs received no intelligence and stay unavailable.
    assert {v for i, v in after.items() if i not in cve_ids} <= {"unavailable"}
    # Nothing else in the CRA projection moves.
    for before_e, after_e in zip(built.evidence, enriched.evidence, strict=True):
        b = dict(before_e.metadata["cra"])
        a = dict(after_e.metadata["cra"])
        b.pop("global_exploitation_signal")
        a.pop("global_exploitation_signal")
        assert a == b
