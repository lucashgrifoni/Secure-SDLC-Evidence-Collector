"""End-to-end orchestration for the Evidence Collector.

Responsibilities:
1. drive the collectors (local + optional GitHub) to assemble evidence,
2. invoke the control engine and scoring to build the evaluation,
3. assemble the final `EvidenceBundle`,
4. export it to JSON/Markdown/HTML.

This module is the single place where all layers are wired together; the
CLI and (future) API are thin facades over these functions.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from evidence_collector.application.profiles import ReleaseProfile, apply_profile
from evidence_collector.collectors.local import (
    LocalArtifactCollector,
    LocalCollectionReport,
)
from evidence_collector.controls import default_catalog, evaluate_controls, load_catalog
from evidence_collector.domain.enums import ReleaseStatus
from evidence_collector.domain.models import (
    Application,
    CollectionError,
    ControlDefinition,
    EvidenceBundle,
    EvidenceException,
    NormalizedEvidence,
    ReleaseContext,
)
from evidence_collector.exporters import export_html, export_json, export_markdown
from evidence_collector.scoring import (
    RiskMode,
    RiskThresholds,
    apply_risk_mode,
    build_summary,
)


@dataclass
class BundleBuildResult:
    bundle: EvidenceBundle
    json_path: Path | None = None
    markdown_path: Path | None = None
    html_path: Path | None = None
    collection_report: LocalCollectionReport | None = None
    controls_used: list[ControlDefinition] = field(default_factory=list)


def _default_bundle_id(application: Application, release: ReleaseContext) -> str:
    today = datetime.now(tz=UTC).strftime("%Y%m%d")
    slug = application.name.lower().replace(" ", "-")
    return f"bundle-{today}-{slug}-{release.release_id}-{uuid.uuid4().hex[:8]}"


def _release_anchor_drift(
    release: ReleaseContext, evidence: list[NormalizedEvidence]
) -> list[CollectionError]:
    """Report evidence anchored to a release other than the one being asserted.

    Every normalizer stamps ``release_id`` and ``commit_sha`` on each record —
    the domain calls them the anchor, and both fields are required. Nothing
    ever read them back. ``evaluate`` therefore accepted an evidence file
    collected for one commit and certified a completely different release with
    it: verdict `ready`, exit 0, no warning, and `statement` then signed that
    false binding into an in-toto predicate.

    ``run`` was never exposed — it builds the collector and the bundle from the
    same context object — but the two-step ``collect`` → ``evaluate`` split is
    a documented, first-class CLI flow, so the check has to live in the tool.

    Not a hard refusal: carrying part of an evidence set forward is a plausible
    operator intent. It is recorded where it survives (bundle, report, HTML)
    and the verdict is degraded, so the discrepancy cannot be missed.
    """
    expected = (release.release_id, release.commit_sha)
    counts: dict[tuple[str, str], int] = {}
    for record in evidence:
        anchor = (record.release_id, record.commit_sha)
        if anchor != expected:
            counts[anchor] = counts.get(anchor, 0) + 1
    return [
        CollectionError(
            path=f"evidence[{release_id}@{commit_sha}]",
            reason=(
                f"{count} evidence record(s) are anchored to release {release_id} / "
                f"commit {commit_sha}, but this bundle asserts {release.release_id} / "
                f"{release.commit_sha}. The verdict does not describe the release "
                "named in the header."
            ),
        )
        for (release_id, commit_sha), count in sorted(counts.items())
    ]


def build_bundle(
    application: Application,
    release: ReleaseContext,
    evidence: list[NormalizedEvidence],
    *,
    catalog_path: str | Path | None = None,
    exceptions: list[EvidenceException] | None = None,
    risk_mode: RiskMode = RiskMode.OFF,
    risk_thresholds: RiskThresholds | None = None,
    collection_errors: list[CollectionError] | None = None,
) -> tuple[EvidenceBundle, list[ControlDefinition]]:
    """Build an EvidenceBundle from an already-normalized evidence set."""
    controls = load_catalog(catalog_path) if catalog_path else list(default_catalog())
    exception_list = exceptions or []
    evaluations, gaps = evaluate_controls(
        controls,
        evidence,
        exceptions=exception_list,
        application=application,
        release=release,
    )
    summary = build_summary(controls, evaluations, gaps)
    summary = apply_risk_mode(summary, evidence, mode=risk_mode, thresholds=risk_thresholds)

    errors = list(collection_errors or [])
    drift = _release_anchor_drift(release, evidence)
    if drift:
        errors.extend(drift)
        # A `ready` verdict backed by another commit's evidence is the actual
        # harm, so the verdict is degraded as well as recorded. One-way only,
        # mirroring apply_risk_mode: never a promotion.
        if summary.release_status is ReleaseStatus.READY:
            summary = summary.model_copy(update={"release_status": ReleaseStatus.CONDITIONAL})

    bundle = EvidenceBundle(
        bundle_id=_default_bundle_id(application, release),
        application=application,
        release=release,
        evidence=evidence,
        control_evaluations=evaluations,
        gaps=gaps,
        exceptions=exception_list,
        collection_errors=errors,
        summary=summary,
    )
    return bundle, controls


def run_pipeline(
    application: Application,
    release: ReleaseContext,
    *,
    artifacts_dirs: list[Path] | None = None,
    attestations_dirs: list[Path] | None = None,
    exceptions_dirs: list[Path] | None = None,
    extra_evidence: list[NormalizedEvidence] | None = None,
    extra_exceptions: list[EvidenceException] | None = None,
    output_dir: Path,
    catalog_path: str | Path | None = None,
    artifact_root: Path | None = None,
    risk_mode: RiskMode = RiskMode.OFF,
    risk_thresholds: RiskThresholds | None = None,
    profile: ReleaseProfile = ReleaseProfile.NONE,
) -> BundleBuildResult:
    """Collect, evaluate, and export a bundle end-to-end."""
    collector = LocalArtifactCollector(
        release=release,
        artifacts_dirs=artifacts_dirs or [],
        attestations_dirs=attestations_dirs or [],
        exceptions_dirs=exceptions_dirs or [],
        artifact_root=artifact_root,
    )
    report = collector.collect()
    evidence_records = list(report.evidence)
    if extra_evidence:
        evidence_records.extend(extra_evidence)
    exception_records = list(report.exceptions)
    if extra_exceptions:
        exception_records.extend(extra_exceptions)

    bundle, controls = build_bundle(
        application,
        release,
        evidence_records,
        catalog_path=catalog_path,
        exceptions=exception_records,
        risk_mode=risk_mode,
        risk_thresholds=risk_thresholds,
        # A file the caller supplied and the collector could not read is a
        # different state from a file that was never supplied. The console
        # warning dies with the CI log; the bundle is what survives.
        collection_errors=[
            CollectionError(path=str(error.path), reason=error.reason) for error in report.errors
        ],
    )
    bundle = apply_profile(bundle, profile)

    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = export_json(bundle, output_dir / "bundle.json")
    markdown_path = export_markdown(bundle, output_dir / "report.md")
    html_path = export_html(bundle, output_dir / "summary.html")

    return BundleBuildResult(
        bundle=bundle,
        json_path=json_path,
        markdown_path=markdown_path,
        html_path=html_path,
        collection_report=report,
        controls_used=controls,
    )
