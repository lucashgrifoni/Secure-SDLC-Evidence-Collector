"""Normalizers: parsed artifact → NormalizedEvidence.

Each normalizer takes one parser output (or GitHub collector payload) plus a
`ReleaseContext` and produces a canonical `NormalizedEvidence`. Normalizers
know about release context, but remain free of IO concerns.

Heuristics for evidence classification:

- SARIF produced by Semgrep, SonarQube, Snyk Code, or CodeQL is classified
  as `sast_scan`. SARIF produced by Gitleaks, Trufflehog, or similar tools
  is classified as `secrets_scan`. SARIF produced by Trivy/Grype/Snyk
  (dependencies) is classified as `sca_scan`. When the tool is unknown, the
  caller can override via `evidence_type_override`.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from evidence_collector.domain.enums import (
    ConfidenceLevel,
    EvidenceStatus,
    EvidenceType,
    SubjectType,
)
from evidence_collector.domain.models import (
    EvidenceSource,
    NormalizedEvidence,
    RawEvidenceRef,
    ReleaseContext,
)
from evidence_collector.parsers._common import ParsedArtifact
from evidence_collector.parsers.attestation import ParsedAttestation
from evidence_collector.parsers.junit import ParsedJUnit
from evidence_collector.parsers.sarif import ParsedSarif
from evidence_collector.parsers.sbom import ParsedSbom
from evidence_collector.parsers.zap import ParsedZap

_SAST_TOOLS: frozenset[str] = frozenset(
    {
        "semgrep",
        "sonarqube",
        "sonar",
        "snyk-code",
        "codeql",
        "bandit",
        "brakeman",
        "checkov",
        "eslint",
    }
)
_SCA_TOOLS: frozenset[str] = frozenset(
    {
        "trivy",
        "grype",
        "snyk",
        "dependency-check",
        "owasp-dependency-check",
        "osv-scanner",
        "pip-audit",
        "pip_audit",
        "safety",
        "npm-audit",
        "yarn-audit",
        "retire.js",
        "retire",
    }
)
_SECRETS_TOOLS: frozenset[str] = frozenset(
    {
        "gitleaks",
        "trufflehog",
        "detect-secrets",
        "noseyparker",
    }
)


def _new_evidence_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def _raw_ref(artifact: ParsedArtifact, root: str | None = None) -> RawEvidenceRef:
    artifact_path = str(artifact.path)
    if root is not None:
        try:
            artifact_path = str(artifact.path.relative_to(root))
        except ValueError:
            artifact_path = str(artifact.path)
    return RawEvidenceRef(
        artifact_path=artifact_path,
        integrity_hash=artifact.integrity_hash,
        content_type=artifact.content_type,
        size_bytes=artifact.size_bytes,
    )


def _classify_sarif(tool_name: str, override: EvidenceType | None) -> EvidenceType:
    if override is not None:
        return override
    lowered = tool_name.lower()
    for token in _SAST_TOOLS:
        if token in lowered:
            return EvidenceType.SAST_SCAN
    for token in _SECRETS_TOOLS:
        if token in lowered:
            return EvidenceType.SECRETS_SCAN
    for token in _SCA_TOOLS:
        if token in lowered:
            return EvidenceType.SCA_SCAN
    return EvidenceType.SAST_SCAN


def _sarif_status(findings_count: dict[str, int]) -> EvidenceStatus:
    blocking = findings_count.get("critical", 0) + findings_count.get("high", 0)
    if blocking > 0:
        return EvidenceStatus.FAILED
    return EvidenceStatus.PASSED


def normalize_sarif(
    parsed: ParsedSarif,
    release: ReleaseContext,
    *,
    evidence_type_override: EvidenceType | None = None,
    artifact_root: str | None = None,
) -> NormalizedEvidence:
    evidence_type = _classify_sarif(parsed.tool_name, evidence_type_override)
    status = _sarif_status(parsed.findings_count)
    prefix = {
        EvidenceType.SAST_SCAN: "sast",
        EvidenceType.SCA_SCAN: "sca",
        EvidenceType.SECRETS_SCAN: "secrets",
    }.get(evidence_type, "scan")
    return NormalizedEvidence(
        evidence_id=_new_evidence_id(prefix),
        evidence_type=evidence_type,
        source=EvidenceSource(name=parsed.tool_name, kind="sarif", version=parsed.tool_version),
        producer=parsed.tool_name,
        subject_type=SubjectType.COMMIT,
        subject_ref=release.commit_sha,
        status=status,
        confidence=ConfidenceLevel.HIGH,
        release_id=release.release_id,
        commit_sha=release.commit_sha,
        generated_at=None,
        raw=_raw_ref(parsed.artifact, artifact_root),
        findings_count=dict(parsed.findings_count),
        summary=(
            f"{parsed.tool_name} reported {parsed.total_findings} findings "
            f"(high/critical={parsed.findings_count.get('critical', 0) + parsed.findings_count.get('high', 0)})"
        ),
    )


def normalize_sbom(
    parsed: ParsedSbom,
    release: ReleaseContext,
    *,
    artifact_root: str | None = None,
) -> NormalizedEvidence:
    subject_ref = parsed.subject_ref or release.artifact_digest or release.release_id
    return NormalizedEvidence(
        evidence_id=_new_evidence_id("sbom"),
        evidence_type=EvidenceType.SBOM,
        source=EvidenceSource(name=parsed.format, kind="sbom", version=parsed.spec_version),
        producer=parsed.format,
        subject_type=SubjectType.ARTIFACT,
        subject_ref=subject_ref,
        status=EvidenceStatus.GENERATED,
        confidence=ConfidenceLevel.HIGH,
        release_id=release.release_id,
        commit_sha=release.commit_sha,
        generated_at=None,
        raw=_raw_ref(parsed.artifact, artifact_root),
        findings_count={"components": parsed.component_count},
        summary=(
            f"{parsed.format.upper()} SBOM with {parsed.component_count} components "
            f"(spec {parsed.spec_version})"
        ),
        metadata={"serial_number": parsed.serial_number} if parsed.serial_number else {},
    )


def normalize_zap(
    parsed: ParsedZap,
    release: ReleaseContext,
    *,
    artifact_root: str | None = None,
) -> NormalizedEvidence:
    """Build a `dast_scan` evidence from an OWASP ZAP JSON report."""
    blocking = parsed.findings_count.get("critical", 0) + parsed.findings_count.get("high", 0)
    status = EvidenceStatus.FAILED if blocking > 0 else EvidenceStatus.PASSED
    primary_target = parsed.target_urls[0] if parsed.target_urls else release.release_id
    return NormalizedEvidence(
        evidence_id=_new_evidence_id("dast"),
        evidence_type=EvidenceType.DAST_SCAN,
        source=EvidenceSource(name=parsed.tool_name, kind="dast", version=parsed.tool_version),
        producer=parsed.tool_name,
        subject_type=SubjectType.APPLICATION,
        subject_ref=primary_target,
        status=status,
        confidence=ConfidenceLevel.HIGH,
        release_id=release.release_id,
        commit_sha=release.commit_sha,
        generated_at=None,
        raw=_raw_ref(parsed.artifact, artifact_root),
        findings_count=dict(parsed.findings_count),
        summary=(
            f"{parsed.tool_name} DAST reported {parsed.total_findings} findings "
            f"across {len(parsed.target_urls) or 1} target(s); "
            f"high/critical={blocking}"
        ),
        metadata={"targets": parsed.target_urls},
    )


def normalize_junit(
    parsed: ParsedJUnit,
    release: ReleaseContext,
    *,
    artifact_root: str | None = None,
) -> NormalizedEvidence:
    failed = parsed.failures + parsed.errors
    status = EvidenceStatus.PASSED if failed == 0 else EvidenceStatus.FAILED
    return NormalizedEvidence(
        evidence_id=_new_evidence_id("test"),
        evidence_type=EvidenceType.TEST_RESULT,
        source=EvidenceSource(name="junit", kind="junit-xml"),
        producer=parsed.suite_name or "junit",
        subject_type=SubjectType.COMMIT,
        subject_ref=release.commit_sha,
        status=status,
        confidence=ConfidenceLevel.HIGH,
        release_id=release.release_id,
        commit_sha=release.commit_sha,
        generated_at=None,
        raw=_raw_ref(parsed.artifact, artifact_root),
        findings_count={
            "total": parsed.total,
            "failures": parsed.failures,
            "errors": parsed.errors,
            "skipped": parsed.skipped,
        },
        summary=(
            f"{parsed.total} tests executed, {parsed.failures} failures, "
            f"{parsed.errors} errors, {parsed.skipped} skipped, "
            f"duration {parsed.time_seconds:.2f}s"
        ),
    )


def normalize_attestation(
    parsed: ParsedAttestation,
    release: ReleaseContext,
    *,
    artifact_root: str | None = None,
) -> NormalizedEvidence:
    return NormalizedEvidence(
        evidence_id=_new_evidence_id("att"),
        evidence_type=parsed.evidence_type,
        source=EvidenceSource(name="manual-attestation", kind="attestation"),
        producer=parsed.producer,
        subject_type=parsed.subject_type,
        subject_ref=parsed.subject_ref,
        status=parsed.status,
        confidence=parsed.confidence,
        release_id=release.release_id,
        commit_sha=release.commit_sha,
        generated_at=parsed.generated_at,
        raw=_raw_ref(parsed.artifact, artifact_root),
        summary=parsed.summary,
        metadata=dict(parsed.metadata),
        manual=True,
    )


def normalize_pr_metadata(
    payload: dict[str, Any],
    release: ReleaseContext,
) -> NormalizedEvidence:
    """Normalize a GitHub PR metadata payload collected by the GitHub adapter.

    Expected keys (see `collectors.github`): `number`, `reviewers_required`,
    `reviewers_approved`, `last_approval_after_last_commit`, `html_url`,
    `merged`, `base`, `head`, `title`, `author`.
    """
    approved = int(payload.get("reviewers_approved", 0))
    required = int(payload.get("reviewers_required", 1))
    after_last_commit = bool(payload.get("last_approval_after_last_commit", False))
    status: EvidenceStatus
    if approved >= required and after_last_commit:
        status = EvidenceStatus.PASSED
    elif approved > 0:
        status = EvidenceStatus.FAILED
    else:
        status = EvidenceStatus.MISSING
    subject_ref = f"PR-{payload.get('number', '?')}"
    collected_at = payload.get("collected_at")
    if isinstance(collected_at, str):
        try:
            collected_at_dt = datetime.fromisoformat(collected_at.replace("Z", "+00:00"))
        except ValueError:
            collected_at_dt = datetime.now(tz=UTC)
    elif isinstance(collected_at, datetime):
        collected_at_dt = collected_at
    else:
        collected_at_dt = datetime.now(tz=UTC)
    return NormalizedEvidence(
        evidence_id=_new_evidence_id("cr"),
        evidence_type=EvidenceType.CODE_REVIEW,
        source=EvidenceSource(name="github", kind="scm", uri=payload.get("html_url")),
        producer="github-pull-request",
        subject_type=SubjectType.PULL_REQUEST,
        subject_ref=subject_ref,
        status=status,
        confidence=ConfidenceLevel.HIGH,
        release_id=release.release_id,
        commit_sha=release.commit_sha,
        generated_at=None,
        collected_at=collected_at_dt,
        summary=(
            f"PR {subject_ref}: {approved}/{required} approvals, "
            f"last_approval_after_last_commit={after_last_commit}"
        ),
        metadata=payload,
    )


def normalize_workflow_run(
    payload: dict[str, Any],
    release: ReleaseContext,
) -> NormalizedEvidence:
    """Normalize a GitHub Actions workflow run payload."""
    conclusion = str(payload.get("conclusion", "")).lower()
    if conclusion == "success":
        status = EvidenceStatus.PASSED
    elif conclusion in {"failure", "timed_out", "cancelled", "startup_failure"}:
        status = EvidenceStatus.FAILED
    else:
        status = EvidenceStatus.COMPLETED
    return NormalizedEvidence(
        evidence_id=_new_evidence_id("wf"),
        evidence_type=EvidenceType.WORKFLOW_RUN,
        source=EvidenceSource(
            name="github-actions",
            kind="ci",
            uri=payload.get("html_url"),
            version=payload.get("workflow_name"),
        ),
        producer="github-actions",
        subject_type=SubjectType.WORKFLOW_RUN,
        subject_ref=str(payload.get("run_id", "unknown")),
        status=status,
        confidence=ConfidenceLevel.HIGH,
        release_id=release.release_id,
        commit_sha=release.commit_sha,
        generated_at=None,
        summary=(
            f"workflow {payload.get('workflow_name')} run "
            f"{payload.get('run_id')} ended with {conclusion or 'unknown'}"
        ),
        metadata=payload,
    )
