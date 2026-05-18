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

import hashlib
from datetime import UTC, datetime
from typing import Any

from evidence_collector.domain.enums import (
    ConfidenceLevel,
    EvidenceStatus,
    EvidenceType,
    SubjectType,
)
from evidence_collector.domain.models import (
    EvidenceClassification,
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


def _new_evidence_id(prefix: str, *parts: str) -> str:
    """Return a deterministic evidence id built from `prefix` + a digest of
    the tuple of string parts. Any caller that passes the same parts gets
    the same id, which makes the whole bundle reproducible across runs on
    identical inputs (see `docs/limitations.md §8`).
    """
    digest = hashlib.sha256("||".join(parts).encode("utf-8")).hexdigest()[:12]
    return f"{prefix}-{digest}"


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
    """Classify a SARIF run by driver name.

    See :func:`_classify_sarif_with_provenance` when the caller also
    needs the classification provenance (driver match vs fallback vs
    explicit override).
    """
    return _classify_sarif_with_provenance(tool_name, override)[0]


def _classify_sarif_with_provenance(
    tool_name: str, override: EvidenceType | None
) -> tuple[EvidenceType, EvidenceClassification]:
    """Classify a SARIF run and report the provenance of the decision.

    Returns ``(evidence_type, classification)`` so callers can populate
    the first-class ``classification`` field on the resulting
    ``NormalizedEvidence``. The classification taxonomy is:

    * ``manual_override`` — the caller passed ``evidence_type_override``
      explicitly, MEDIUM confidence (human intent, not a machine match).
    * ``driver_match`` — the driver name matched one of the curated
      tool token sets, HIGH confidence.
    * ``fallback_sast`` — no token matched and the heuristic defaulted
      to ``sast_scan``, LOW confidence. See ``docs/limitations.md §2``.
    """
    if override is not None:
        return override, EvidenceClassification(
            confidence=ConfidenceLevel.MEDIUM,
            reason="manual_override",
            driver_name=tool_name,
        )
    # Normalize punctuation / whitespace so "Snyk Code", "snyk-code",
    # "snykcode", and "snyk_code" all match the same token. Without
    # this, a SAST driver whose name happens to use a different
    # separator falls through to the SCA bucket (false-positive risk
    # tracked in docs/limitations.md §2).
    lowered = tool_name.lower()
    normalized = lowered.replace("-", " ").replace("_", " ").replace("/", " ")
    compact = normalized.replace(" ", "")

    def _matches(tokens: frozenset[str]) -> bool:
        for token in tokens:
            token_norm = token.replace("-", " ").replace("_", " ")
            token_compact = token_norm.replace(" ", "")
            if token_norm in normalized or token_compact in compact or token in lowered:
                return True
        return False

    # Order matters: check SAST first so composite tools (e.g., "Snyk Code"
    # where both "snyk" and "snyk-code" can match) are labelled as SAST,
    # which is more specific than SCA.
    if _matches(_SAST_TOOLS):
        return EvidenceType.SAST_SCAN, EvidenceClassification(
            confidence=ConfidenceLevel.HIGH,
            reason="driver_match",
            driver_name=tool_name,
        )
    if _matches(_SECRETS_TOOLS):
        return EvidenceType.SECRETS_SCAN, EvidenceClassification(
            confidence=ConfidenceLevel.HIGH,
            reason="driver_match",
            driver_name=tool_name,
        )
    if _matches(_SCA_TOOLS):
        return EvidenceType.SCA_SCAN, EvidenceClassification(
            confidence=ConfidenceLevel.HIGH,
            reason="driver_match",
            driver_name=tool_name,
        )
    return EvidenceType.SAST_SCAN, EvidenceClassification(
        confidence=ConfidenceLevel.LOW,
        reason="fallback_sast",
        driver_name=tool_name,
    )


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
    evidence_type, classification = _classify_sarif_with_provenance(
        parsed.tool_name, evidence_type_override
    )
    status = _sarif_status(parsed.findings_count)
    prefix = {
        EvidenceType.SAST_SCAN: "sast",
        EvidenceType.SCA_SCAN: "sca",
        EvidenceType.SECRETS_SCAN: "secrets",
    }.get(evidence_type, "scan")
    # When the classification fell through to the SAST default we cannot
    # claim HIGH overall confidence for the record either: the evidence
    # type itself is a heuristic guess. Reflect that on the existing
    # ``confidence`` field so consumers that ignore ``classification``
    # still see the weakened signal.
    overall_confidence = (
        ConfidenceLevel.LOW if classification.reason == "fallback_sast" else ConfidenceLevel.HIGH
    )
    return NormalizedEvidence(
        evidence_id=_new_evidence_id(
            prefix, parsed.tool_name, parsed.artifact.integrity_hash, release.commit_sha
        ),
        evidence_type=evidence_type,
        source=EvidenceSource(name=parsed.tool_name, kind="sarif", version=parsed.tool_version),
        producer=parsed.tool_name,
        subject_type=SubjectType.COMMIT,
        subject_ref=release.commit_sha,
        status=status,
        confidence=overall_confidence,
        classification=classification,
        release_id=release.release_id,
        commit_sha=release.commit_sha,
        generated_at=None,
        raw=_raw_ref(parsed.artifact, artifact_root),
        findings_count=dict(parsed.findings_count),
        cve_ids=list(parsed.cve_ids),
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
        evidence_id=_new_evidence_id(
            "sbom", parsed.artifact.integrity_hash, subject_ref, release.release_id
        ),
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
        cve_ids=list(parsed.cve_ids),
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
        evidence_id=_new_evidence_id(
            "dast", parsed.tool_name, parsed.artifact.integrity_hash, primary_target
        ),
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
        evidence_id=_new_evidence_id(
            "test",
            parsed.suite_name or "junit",
            parsed.artifact.integrity_hash,
            release.commit_sha,
        ),
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
        evidence_id=_new_evidence_id(
            "att",
            str(parsed.evidence_type),
            parsed.artifact.integrity_hash,
            parsed.subject_ref,
        ),
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
    pr_digest_key = f"{payload.get('number', '?')}|{payload.get('html_url', '')}"
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
        evidence_id=_new_evidence_id("cr", pr_digest_key, release.commit_sha),
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
        evidence_id=_new_evidence_id(
            "wf",
            str(payload.get("run_id", "unknown")),
            str(payload.get("workflow_name", "")),
            release.commit_sha,
        ),
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
