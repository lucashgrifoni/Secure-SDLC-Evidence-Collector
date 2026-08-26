"""Domain models for the canonical evidence bundle.

These Pydantic v2 models define the stable contract for every evidence,
evaluation, and bundle produced by the tool. Keep this module free of IO,
adapter, and framework concerns.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SerializerFunctionWrapHandler,
    ValidationInfo,
    field_validator,
    model_serializer,
    model_validator,
)

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

# Versions the *bundle contract*, not the tool. It moves when the shape of a
# bundle changes in a way a consumer must know about, which is why the
# published schema sets `additionalProperties: false` at every level: a
# consumer pinning a version is told when a bundle no longer matches it.
#
# 2.0.0 adds `collection_errors`. That field is additive, but a strict
# validator pinned to 1.0.0 rejects any bundle carrying it, so by this
# contract's own rules it is a breaking change and the version has to say so.
# It stayed at 1.0.0 while the shape changed underneath it, which is the one
# thing a version field must never do — a consumer got a validation failure
# with no way to learn that a newer schema existed.
#
# Bundles without collection problems do not carry the field at all (see
# `_omit_empty_collection_errors`), so they still validate against 1.0.0.
#
# 2.1.0 adds `catalog`. Minor, not major, because the direction that breaks is
# the other one: a 2.1.0 consumer reads a 2.0.0 bundle fine — the field is
# optional and simply absent — while a validator pinned to 2.0.0 rejects a
# 2.1.0 bundle, which is exactly what the version field is for telling it.
# Unlike `collection_errors` this one is never omitted, because "which catalog
# produced this verdict" has no empty case worth hiding.
BUNDLE_SCHEMA_VERSION = "2.1.0"


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


def _reject_duplicates(ids: list[str], *, label: str, refs: str) -> None:
    """Raise if any id appears twice, naming the offenders and what breaks."""
    seen: set[str] = set()
    duplicates: list[str] = []
    for value in ids:
        if value in seen and value not in duplicates:
            duplicates.append(value)
        seen.add(value)
    if duplicates:
        raise ValueError(
            f"Duplicate {label}: {duplicates}. Each id must identify exactly "
            f"one record, otherwise {refs} are ambiguous."
        )


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


class TopRiskCve(_BaseModel):
    """A single CVE selected for top-risk listing in vulnerability intelligence.

    Kept small on purpose: only the fields a maintainer needs to decide
    whether to patch *this week* vs *batch later*. Full CVE detail lives
    in the raw scanner artefacts referenced by ``raw.artifact_path``.
    """

    cve_id: Annotated[str, Field(min_length=1, max_length=30)]
    epss_score: Annotated[float, Field(ge=0.0, le=1.0)]
    epss_percentile: Annotated[float, Field(ge=0.0, le=1.0)]
    in_kev: bool = False
    known_ransomware: bool = False


class VulnerabilityIntelligence(_BaseModel):
    """EPSS + CISA KEV enrichment aggregated for a single evidence record.

    Computed by the optional ``sdlc-evidence enrich`` command, run against an
    existing ``bundle.json``. When the enrichment step is skipped the field
    stays ``None`` and the bundle behaves exactly like it did
    pre-enrichment, so consumers that never opt in are unaffected.

    Source feeds:

    * EPSS — https://epss.cyentia.com/ (FIRST.org, public CSV, refreshed
      daily). ``epss_score`` is the probability of exploitation in the
      next 30 days; ``epss_percentile`` is the position within the day's
      distribution.
    * CISA KEV — https://www.cisa.gov/known-exploited-vulnerabilities-catalog
      (JSON catalog of vulnerabilities confirmed exploited in the wild).
    """

    cve_count: int = Field(default=0, ge=0)
    max_epss_score: float | None = Field(default=None, ge=0.0, le=1.0)
    max_epss_percentile: float | None = Field(default=None, ge=0.0, le=1.0)
    cves_in_kev_count: int = Field(default=0, ge=0)
    cves_known_ransomware_count: int = Field(default=0, ge=0)
    top_risk_cves: list[TopRiskCve] = Field(
        default_factory=list,
        description="Up to N CVEs sorted by EPSS percentile (highest first).",
    )
    epss_feed_date: str | None = Field(
        default=None,
        max_length=20,
        description="YYYY-MM-DD date stamped on the EPSS feed used for enrichment.",
    )
    epss_model_version: str | None = Field(
        default=None,
        max_length=40,
        description=(
            "EPSS model version stamped on the feed header (e.g. 'v2026.01.04'). "
            "EPSS scores are not comparable across model versions, so recording "
            "it keeps day-to-day score deltas honest. None when enrichment is "
            "skipped or the feed header omits it."
        ),
    )
    kev_feed_date: str | None = Field(
        default=None,
        max_length=20,
        description="YYYY-MM-DD date stamped on the CISA KEV catalog used for enrichment.",
    )
    enriched_at: datetime | None = Field(
        default=None,
        description="Timestamp at which enrichment ran; volatile, stripped before structural hash.",
    )


class Reachability(_BaseModel):
    """Optional reachability annotation for an SCA / dependency finding (§3.2).

    Records whether the vulnerable code path is reachable from the
    application entry points. Source = whichever tool produced the
    signal (CodeQL reachability, Endor Labs, Semgrep Pro, or a manual
    review). The collector **does not** re-derive reachability; it
    only stores the upstream verdict so consumers can filter findings
    by reachable / not_reachable / unknown.
    """

    status: Annotated[str, Field(min_length=1, max_length=20)]
    source: Annotated[str, Field(min_length=1, max_length=60)]
    method: Annotated[str, Field(min_length=1, max_length=30)] = "manual_review"
    evidence_ref: str | None = Field(default=None, max_length=500)

    @field_validator("status")
    @classmethod
    def _validate_status(cls, value: str) -> str:
        normalised = value.strip().lower()
        if normalised not in {"reachable", "not_reachable", "unknown"}:
            raise ValueError(
                "Reachability.status must be one of: reachable, not_reachable, unknown"
            )
        return normalised

    @field_validator("method")
    @classmethod
    def _validate_method(cls, value: str) -> str:
        normalised = value.strip().lower()
        if normalised not in {"data_flow", "function_call", "manual_review"}:
            raise ValueError(
                "Reachability.method must be one of: data_flow, function_call, manual_review"
            )
        return normalised


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
    cve_ids: list[str] = Field(
        default_factory=list,
        description=(
            "Distinct CVE identifiers extracted from the underlying scanner "
            "output. Populated by parsers that can correlate findings to CVEs "
            "(SARIF results with security/cve tags, CycloneDX vulnerabilities "
            "block). Used by the optional EPSS/KEV enrichment step. Empty when "
            "the parser cannot derive CVEs or when the evidence type does not "
            "correspond to vulnerability data (test_result, code_review, etc)."
        ),
    )
    vulnerability_intelligence: VulnerabilityIntelligence | None = Field(
        default=None,
        description=(
            "Optional EPSS/KEV enrichment summary for the CVEs in ``cve_ids``. "
            "Stays ``None`` unless the user opted into enrichment by running "
            "``sdlc-evidence enrich`` against the bundle. The bundle remains "
            "schema-compatible with pre-enrichment consumers when this field "
            "is absent."
        ),
    )
    reachability: Reachability | None = Field(
        default=None,
        description=(
            "Optional reachability annotation (§3.2). Populated externally "
            "(CodeQL reachability, Endor Labs, Semgrep Pro, manual review). "
            "The collector preserves the upstream verdict; it does not "
            "compute reachability itself."
        ),
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


class RiskAssessment(_BaseModel):
    """Risk-weighted verdict rationale (T6.6, opt-in).

    Populated when the run was invoked with ``--risk-mode epss-weighted``.
    ``None`` when the default presence-based verdict is in effect, which
    preserves byte-stability for pre-T6.6 bundles.
    """

    mode: Annotated[str, Field(min_length=1, max_length=40)]
    epss_percentile_threshold: Annotated[float, Field(ge=0.0, le=1.0)]
    kev_blocks: bool = True
    exploitable_cve_count: int = Field(ge=0)
    kev_cve_count: int = Field(ge=0)
    kev_ransomware_cve_count: int = Field(ge=0)
    high_epss_cve_count: int = Field(ge=0)
    base_release_status: ReleaseStatus
    rationale: Annotated[str, Field(max_length=400)] = ""


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
    # T6.6 — opt-in risk-weighted verdict rationale. ``None`` keeps the
    # bundle structurally identical to pre-T6.6 outputs once the
    # structural-hash normaliser strips the null field.
    risk_assessment: RiskAssessment | None = None

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

    @field_validator("approved_at", "expires_at")
    @classmethod
    def _require_timezone(cls, value: datetime, info: ValidationInfo) -> datetime:
        """Reject a waiver timestamp with no timezone.

        `datetime.fromisoformat` happily accepts `2026-12-31` and
        `2026-12-31T00:00:00`, producing a naive value. Every consumer
        compares it against `datetime.now(tz=UTC)`, so the whole run died on
        `TypeError: can't compare offset-naive and offset-aware datetimes` —
        a bare traceback, exit 3, and no bundle, report or summary written at
        all. One waiver missing a `Z` took the entire release report with it.

        Validating here rather than in the parser also covers bundle
        round-trips and waivers built programmatically. The message names the
        field and shows the fix, because "add a timezone" is not obvious from
        a date that looks perfectly well-formed.
        """
        if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
            raise ValueError(
                f"{info.field_name} must carry a timezone (e.g. "
                f"'2026-12-31T00:00:00Z' or '2026-12-31T00:00:00+00:00'); got a "
                "value with none. Waiver windows are compared against UTC, and a "
                "naive timestamp has no defined instant."
            )
        return value

    @model_validator(mode="after")
    def _expiration_after_approval(self) -> EvidenceException:
        if self.expires_at <= self.approved_at:
            raise ValueError(
                f"Exception {self.exception_id}: expires_at must be strictly after approved_at"
            )
        return self

    def is_valid_for(self, application: str, release_id: str, now: datetime) -> bool:
        """Whether this waiver is in force for the given release, right now.

        Both ends of the window are enforced. Only the upper bound was, so a
        waiver dated to be approved next quarter already waived a critical
        control today: the control flipped missing -> waived and the release
        flipped not_ready -> ready, exit 2 -> 0. An approval that has not
        happened yet cannot excuse anything.
        """
        if not (self.approved_at <= now < self.expires_at):
            return False
        if self.scope.application and self.scope.application != application:
            return False
        return not (self.scope.release_id and self.scope.release_id != release_id)


class CollectionError(_BaseModel):
    """An input that was supplied but could not be ingested.

    "No evidence was supplied" and "evidence was supplied and is broken" are
    materially different states, and only the first was ever recorded. The
    collector warned on the console and the warning died there: the bundle,
    the report and the HTML summary all showed the affected control as
    plainly *missing evidence*, telling the engineer to re-run a scan that
    had in fact already run and whose output was sitting on disk, truncated.

    CI logs rotate; the bundle is the durable, signable artifact that
    ``verify``, ``compare``, ``statement``, ``vex`` and ``oscal`` all
    consume. The distinction has to live here to survive.
    """

    path: Annotated[str, Field(min_length=1, max_length=500)]
    reason: Annotated[str, Field(min_length=1, max_length=1000)]


class CatalogRef(_BaseModel):
    """Which control catalog produced a bundle's evaluations.

    Every verdict in a bundle is relative to a catalog, and `--catalog` lets an
    operator supply their own. Nothing recorded which one had been used, so two
    bundles built from identical evidence — one `not_ready` and exit 2 against
    the shipped catalog, one `conditional` and exit 0 against a catalog whose
    required evidence had been moved to recommended — were indistinguishable to
    whoever received them. `verify --expected` proves a bundle has not changed
    since it was generated; this is what says against which standard.

    `origin` matters on its own because the names collide: `catalog.yaml` is
    both the packaged default and the likeliest name for an operator's own
    file, so the name alone cannot answer "was this the shipped catalog?".

    `name` is a bare filename, never a path. Which directory an operator keeps
    their catalog in is the kind of detail `--artifact-root` exists to keep out
    of a published bundle, and it is not needed to identify the catalog — the
    digest does that.
    """

    origin: Literal["builtin", "custom"] = Field(
        description=(
            "`builtin` for a catalog shipped inside the package, `custom` for "
            "one loaded from a path the operator supplied."
        )
    )
    name: Annotated[str, Field(min_length=1, max_length=200)] = Field(
        description="Filename of the catalog, without any directory component."
    )
    sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")] = Field(
        description=(
            "SHA-256 of the catalog file's bytes as read. The repository stores "
            "and checks out YAML with LF endings, so this matches `sha256sum` "
            "on a normal checkout and is stable across operating systems."
        )
    )
    control_count: Annotated[int, Field(ge=1)] = Field(
        description="How many controls the catalog defines."
    )


class EvidenceBundle(_BaseModel):
    """Top-level, serializable container produced by the collector."""

    bundle_version: str = BUNDLE_SCHEMA_VERSION
    bundle_id: Annotated[str, Field(min_length=1, max_length=200)]
    generated_at: datetime = Field(default_factory=_utcnow)
    application: Application
    release: ReleaseContext
    catalog: CatalogRef | None = Field(
        default=None,
        description=(
            "The control catalog these evaluations were produced against. "
            "Optional so that a bundle written before 2.1.0 still validates; "
            "every bundle this version writes carries it."
        ),
    )
    evidence: list[NormalizedEvidence] = Field(default_factory=list)
    control_evaluations: list[ControlEvaluation] = Field(default_factory=list)
    gaps: list[Gap] = Field(default_factory=list)
    exceptions: list[EvidenceException] = Field(default_factory=list)
    collection_errors: list[CollectionError] = Field(
        default_factory=list,
        description=(
            "Inputs that were supplied but could not be ingested (unreadable, "
            "malformed, oversized). Omitted entirely for a clean run, so a "
            "bundle with no collection problems still validates against a "
            "pinned pre-3.x schema. It is not byte-identical to a pre-3.x "
            "bundle: bundle_version moved to 2.0.0 in the same release, and "
            "that field is inside the structural hash."
        ),
    )
    summary: Summary

    # No return annotation, deliberately. Pydantic builds the serialization
    # schema from a wrap serializer's annotated return type, so declaring
    # `-> dict[str, Any]` replaced the entire contract:
    # `model_json_schema(mode="serialization")` collapsed from 11 properties,
    # 24 $defs and `additionalProperties: false` to a bare
    # `{"additionalProperties": true, "type": "object"}`. Serialization mode is
    # the semantically correct mode for a schema describing *produced* bundles
    # and the one FastAPI uses for `response_model`, so a downstream service
    # exposing `response_model=EvidenceBundle` published an untyped object in
    # its OpenAPI — from a package that ships `py.typed`. Nothing in the suite
    # covered that mode, so it stayed green.
    # `-> Any` collapses it too, so the annotation has to be absent rather than
    # widened, and mypy is silenced at exactly this line.
    @model_serializer(mode="wrap")
    def _omit_empty_collection_errors(self, handler: SerializerFunctionWrapHandler):  # type: ignore[no-untyped-def]
        """Leave `collection_errors` out entirely when nothing failed.

        The published schema is `additionalProperties: false` at every level,
        so a consumer validating against the 1.0.0 contract they pinned
        rejects any bundle carrying a field that contract does not know. With
        the key always present, *every* bundle broke those consumers —
        including the overwhelming majority where nothing went wrong and there
        was nothing to report.

        Omitting the empty case keeps a clean run byte-identical to what it
        produced before the field existed, which is what the field's own
        description already promised, and narrows the breaking change to the
        bundles that genuinely carry new information.
        """
        data: dict[str, Any] = handler(self)
        if not data.get("collection_errors"):
            data.pop("collection_errors", None)
        return data

    @model_validator(mode="after")
    def _ids_are_unique(self) -> EvidenceBundle:
        """An id must identify exactly one record, for evidence and waivers alike.

        The validator below already checks that every `evidence_refs` and
        `exception_refs` entry points at a known id. That is only half the
        guarantee: if two records share an id, the reference resolves to two
        things, and a consumer doing the obvious
        `{e.evidence_id: e for e in bundle.evidence}` keeps whichever came last
        without noticing. For a tool whose product is the audit trail, an
        ambiguous reference is not a bundle worth signing.
        """
        _reject_duplicates(
            [item.evidence_id for item in self.evidence],
            label="evidence ids",
            refs="control evidence_refs",
        )
        # A waiver is what lets a control pass *without* evidence, so an
        # ambiguous `exception_id` matters more here than anywhere else. The
        # uniqueness guarantee was added for evidence and skipped for
        # exceptions, while `_evaluations_reference_existing_evidence` below
        # already checks `exception_refs` against known ids — the same half a
        # guarantee that check had before.
        _reject_duplicates(
            [item.exception_id for item in self.exceptions],
            label="exception ids",
            refs="control exception_refs",
        )
        return self

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
