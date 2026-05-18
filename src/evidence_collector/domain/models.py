"""Domain models for the canonical evidence bundle.

These Pydantic v2 models define the stable contract for every evidence,
evaluation, and bundle produced by the tool. Keep this module free of IO,
adapter, and framework concerns.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from evidence_collector.domain.enums import (
    ConfidenceLevel,
    ControlCriticality,
    ControlEvaluationStatus,
    ControlFramework,
    EvidenceStatus,
    EvidenceType,
    ReleaseStatus,
    SubjectType,
)

BUNDLE_SCHEMA_VERSION = "1.0.0"


class _BaseModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=False,
        str_strip_whitespace=True,
        populate_by_name=True,
        use_enum_values=False,
        validate_assignment=True,
    )


def _utcnow() -> datetime:
    return datetime.now(tz=UTC)


class Application(_BaseModel):
    """Product or service under evaluation."""

    name: Annotated[str, Field(min_length=1, max_length=200)]
    repository: Annotated[str, Field(min_length=1, max_length=300)]
    environment: Annotated[str, Field(min_length=1, max_length=50)] = "production"
    owner_team: str | None = Field(default=None, max_length=200)


class ReleaseContext(_BaseModel):
    """Release candidate context that anchors every evidence collected."""

    release_id: Annotated[str, Field(min_length=1, max_length=100)]
    commit_sha: Annotated[str, Field(min_length=7, max_length=64)]
    branch: Annotated[str, Field(min_length=1, max_length=200)] = "main"
    pipeline_run_id: str | None = Field(default=None, max_length=200)
    build_id: str | None = Field(default=None, max_length=200)
    artifact_digest: str | None = Field(
        default=None,
        description="Content digest of the published artifact, e.g. sha256:...",
        max_length=200,
    )
    tag: str | None = Field(default=None, max_length=100)

    @field_validator("commit_sha")
    @classmethod
    def _validate_sha(cls, value: str) -> str:
        candidate = value.strip().lower()
        if not all(c in "0123456789abcdef" for c in candidate):
            raise ValueError("commit_sha must be a hexadecimal string")
        return candidate


class EvidenceSource(_BaseModel):
    """Origin system that produced an evidence artifact."""

    name: Annotated[str, Field(min_length=1, max_length=100)]
    kind: Annotated[str, Field(min_length=1, max_length=60)]
    version: str | None = Field(default=None, max_length=60)
    uri: str | None = Field(default=None, max_length=500)


class RawEvidenceRef(_BaseModel):
    """Reference to a raw (non-normalized) artifact stored alongside the bundle."""

    artifact_path: str | None = Field(default=None, max_length=500)
    artifact_uri: str | None = Field(default=None, max_length=500)
    integrity_hash: str | None = Field(
        default=None,
        description="Hex digest with algorithm prefix, e.g. sha256:abcd...",
        max_length=200,
    )
    content_type: str | None = Field(default=None, max_length=100)
    size_bytes: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def _must_have_locator(self) -> RawEvidenceRef:
        if not self.artifact_path and not self.artifact_uri:
            raise ValueError("RawEvidenceRef requires artifact_path or artifact_uri")
        return self


class EvidenceClassification(_BaseModel):
    """How the ``evidence_type`` of a record was decided.

    Promotes the implicit confidence signal previously visible only in
    ``evaluation.rationale`` text to a first-class bundle field so
    downstream consumers can weight or filter evidence by classification
    confidence without parsing free-form prose. The taxonomy is small on
    purpose: any new ``reason`` value MUST be documented in
    ``docs/limitations.md`` so reviewers know what to expect.
    """

    confidence: ConfidenceLevel
    reason: Annotated[str, Field(min_length=1, max_length=60)]
    driver_name: str | None = Field(default=None, max_length=120)


class NormalizedEvidence(_BaseModel):
    """Canonical evidence record after normalization.

    Every evaluation must reference normalized evidence via `evidence_id`.
    """

    evidence_id: Annotated[str, Field(min_length=1, max_length=200)]
    evidence_type: EvidenceType
    source: EvidenceSource
    producer: Annotated[str, Field(min_length=1, max_length=100)]
    subject_type: SubjectType
    subject_ref: Annotated[str, Field(min_length=1, max_length=500)]
    status: EvidenceStatus
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    classification: EvidenceClassification | None = Field(
        default=None,
        description=(
            "Optional classification provenance for the evidence_type. "
            "Populated by parsers that apply a heuristic (currently the "
            "SARIF normalizer); absent when the evidence type is "
            "self-evident from the format (SBOM, JUnit, ZAP)."
        ),
    )
    release_id: Annotated[str, Field(min_length=1, max_length=100)]
    commit_sha: Annotated[str, Field(min_length=7, max_length=64)]
    generated_at: datetime | None = None
    collected_at: datetime = Field(default_factory=_utcnow)
    raw: RawEvidenceRef | None = None
    findings_count: dict[str, int] = Field(
        default_factory=dict,
        description="Aggregated findings counters keyed by severity, e.g. {high: 0}.",
    )
    summary: str | None = Field(default=None, max_length=1000)
    metadata: dict[str, Any] = Field(default_factory=dict)
    manual: bool = Field(
        default=False,
        description="True when the evidence was provided via manual attestation.",
    )

    @field_validator("commit_sha")
    @classmethod
    def _validate_sha(cls, value: str) -> str:
        candidate = value.strip().lower()
        if not all(c in "0123456789abcdef" for c in candidate):
            raise ValueError("commit_sha must be a hexadecimal string")
        return candidate

    @model_validator(mode="after")
    def _manual_lowers_confidence(self) -> NormalizedEvidence:
        if self.manual and self.confidence == ConfidenceLevel.HIGH:
            self.confidence = ConfidenceLevel.MEDIUM
        return self


class ControlDefinition(_BaseModel):
    """Definition of a Secure SDLC control that the engine evaluates."""

    control_id: Annotated[str, Field(min_length=1, max_length=100)]
    framework: ControlFramework
    name: Annotated[str, Field(min_length=1, max_length=200)]
    description: Annotated[str, Field(min_length=1, max_length=2000)]
    criticality: ControlCriticality
    required_evidence_types: list[EvidenceType] = Field(default_factory=list)
    recommended_evidence_types: list[EvidenceType] = Field(default_factory=list)
    rationale_template: str | None = Field(default=None, max_length=2000)

    @model_validator(mode="after")
    def _must_have_required_or_recommended(self) -> ControlDefinition:
        if not self.required_evidence_types and not self.recommended_evidence_types:
            raise ValueError(
                "ControlDefinition must declare at least one required or recommended evidence type"
            )
        return self


class ControlEvaluation(_BaseModel):
    """Outcome of evaluating a control against the collected evidence set."""

    control_id: Annotated[str, Field(min_length=1, max_length=100)]
    framework: ControlFramework
    control_name: Annotated[str, Field(min_length=1, max_length=200)]
    evaluation_status: ControlEvaluationStatus
    criticality: ControlCriticality
    evidence_refs: list[str] = Field(default_factory=list)
    missing_required_evidence_types: list[EvidenceType] = Field(default_factory=list)
    missing_recommended_evidence_types: list[EvidenceType] = Field(default_factory=list)
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    rationale: Annotated[str, Field(min_length=1, max_length=2000)]
    evaluated_at: datetime = Field(default_factory=_utcnow)
    exception_refs: list[str] = Field(default_factory=list)


class Gap(_BaseModel):
    """A concrete missing or weak evidence that impacts release readiness."""

    control_id: str
    evidence_type: EvidenceType | None = None
    criticality: ControlCriticality
    description: Annotated[str, Field(min_length=1, max_length=1000)]
    remediation: str | None = Field(default=None, max_length=1000)


class Summary(_BaseModel):
    """Aggregated verdict and scores for the bundle."""

    evidence_coverage_score: Annotated[int, Field(ge=0, le=100)]
    confidence_score: Annotated[int, Field(ge=0, le=100)]
    release_status: ReleaseStatus
    missing_critical_evidence: list[str] = Field(default_factory=list)
    total_controls: int = Field(ge=0)
    controls_met: int = Field(ge=0)
    controls_partial: int = Field(ge=0)
    controls_missing: int = Field(ge=0)
    controls_waived: int = Field(ge=0)
    controls_not_applicable: int = Field(ge=0)

    @model_validator(mode="after")
    def _counters_consistent(self) -> Summary:
        total = (
            self.controls_met
            + self.controls_partial
            + self.controls_missing
            + self.controls_waived
            + self.controls_not_applicable
        )
        if total != self.total_controls:
            raise ValueError(
                f"Sum of control counters ({total}) does not match total_controls "
                f"({self.total_controls})"
            )
        return self


class ExceptionScope(_BaseModel):
    """Scope to which an exception applies."""

    application: str | None = Field(default=None, max_length=200)
    release_id: str | None = Field(default=None, max_length=100)


class EvidenceException(_BaseModel):
    """Formal, time-bound waiver that allows a control to pass without
    its required evidence being present.

    Exceptions must have an approver, a written justification, and an
    expiration date. The engine refuses expired or unscoped exceptions.
    """

    exception_id: Annotated[str, Field(min_length=1, max_length=100)]
    control_id: Annotated[str, Field(min_length=1, max_length=100)]
    approver: Annotated[str, Field(min_length=1, max_length=200)]
    approved_at: datetime
    expires_at: datetime
    justification: Annotated[str, Field(min_length=10, max_length=2000)]
    reference: str | None = Field(
        default=None,
        description="Ticket or document where the waiver was recorded.",
        max_length=300,
    )
    scope: ExceptionScope = Field(default_factory=ExceptionScope)

    @model_validator(mode="after")
    def _expiration_after_approval(self) -> EvidenceException:
        if self.expires_at <= self.approved_at:
            raise ValueError(
                f"Exception {self.exception_id}: expires_at must be strictly after approved_at"
            )
        return self

    def is_valid_for(self, application: str, release_id: str, now: datetime) -> bool:
        if now >= self.expires_at:
            return False
        if self.scope.application and self.scope.application != application:
            return False
        return not (self.scope.release_id and self.scope.release_id != release_id)


class EvidenceBundle(_BaseModel):
    """Top-level, serializable container produced by the collector."""

    bundle_version: str = BUNDLE_SCHEMA_VERSION
    bundle_id: Annotated[str, Field(min_length=1, max_length=200)]
    generated_at: datetime = Field(default_factory=_utcnow)
    application: Application
    release: ReleaseContext
    evidence: list[NormalizedEvidence] = Field(default_factory=list)
    control_evaluations: list[ControlEvaluation] = Field(default_factory=list)
    gaps: list[Gap] = Field(default_factory=list)
    exceptions: list[EvidenceException] = Field(default_factory=list)
    summary: Summary

    @model_validator(mode="after")
    def _evaluations_reference_existing_evidence(self) -> EvidenceBundle:
        known_ids = {e.evidence_id for e in self.evidence}
        known_exception_ids = {e.exception_id for e in self.exceptions}
        for evaluation in self.control_evaluations:
            unknown_evidence = [ref for ref in evaluation.evidence_refs if ref not in known_ids]
            if unknown_evidence:
                raise ValueError(
                    f"Control {evaluation.control_id} references unknown evidence: "
                    f"{unknown_evidence}"
                )
            unknown_exceptions = [
                ref for ref in evaluation.exception_refs if ref not in known_exception_ids
            ]
            if unknown_exceptions:
                raise ValueError(
                    f"Control {evaluation.control_id} references unknown exceptions: "
                    f"{unknown_exceptions}"
                )
        return self
