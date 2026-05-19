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
from evidence_collector.domain.models import (
    Application,
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


def build_bundle(
    application: Application,
    release: ReleaseContext,
    evidence: list[NormalizedEvidence],
    *,
    catalog_path: str | Path | None = None,
    exceptions: list[EvidenceException] | None = None,
    risk_mode: RiskMode = RiskMode.OFF,
    risk_thresholds: RiskThresholds | None = None,
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
    bundle = EvidenceBundle(
        bundle_id=_default_bundle_id(application, release),
        application=application,
        release=release,
        evidence=evidence,
        control_evaluations=evaluations,
        gaps=gaps,
        exceptions=exception_list,
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
