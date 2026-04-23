"""Domain enums for the Evidence Collector.

All enums use string values so JSON/YAML serialization produces stable,
auditable representations rather than opaque integers.
"""

from __future__ import annotations

from enum import StrEnum


class EvidenceType(StrEnum):
    """Canonical evidence types supported by the MVP.

    Extending this enum requires updating control definitions that reference
    the new type. Unknown evidence should be rejected at the parser boundary.
    """

    SAST_SCAN = "sast_scan"
    SCA_SCAN = "sca_scan"
    SECRETS_SCAN = "secrets_scan"
    DAST_SCAN = "dast_scan"
    SBOM = "sbom"
    TEST_RESULT = "test_result"
    CODE_REVIEW = "code_review"
    PR_METADATA = "pr_metadata"
    WORKFLOW_RUN = "workflow_run"
    THREAT_MODEL = "threat_model"
    RELEASE_APPROVAL = "release_approval"
    ROLLBACK_PLAN = "rollback_plan"
    ARTIFACT_SIGNATURE = "artifact_signature"
    ARTIFACT_ATTESTATION = "artifact_attestation"
    GENERIC_ATTESTATION = "generic_attestation"


class EvidenceStatus(StrEnum):
    """Operational status of an evidence artifact.

    `passed`/`failed` apply to evaluative evidence (scans, tests). `generated`
    applies to artifacts that exist without a pass/fail verdict (SBOM). `missing`
    is used by the evaluation engine when an expected evidence is not found.
    `invalid` marks artifacts that were present but failed parsing/validation.
    """

    PASSED = "passed"
    FAILED = "failed"
    COMPLETED = "completed"
    GENERATED = "generated"
    MISSING = "missing"
    INVALID = "invalid"
    UNKNOWN = "unknown"


class ConfidenceLevel(StrEnum):
    """Confidence of an evidence or an evaluation.

    Manual attestations default to `medium` at best; automated signals from
    trusted sources can reach `high`. `low` signals data that is inconsistent
    or derived from weakly authenticated sources.
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class SubjectType(StrEnum):
    """Subject an evidence is attached to."""

    REPOSITORY = "repository"
    COMMIT = "commit"
    PULL_REQUEST = "pull_request"
    WORKFLOW_RUN = "workflow_run"
    BUILD = "build"
    ARTIFACT = "artifact"
    RELEASE = "release"
    APPLICATION = "application"


class ControlFramework(StrEnum):
    """Compliance / governance frameworks referenced by controls."""

    NIST_SSDF = "NIST_SSDF"
    OWASP_SAMM = "OWASP_SAMM"
    ORG_INTERNAL = "ORG_INTERNAL"


class ControlCriticality(StrEnum):
    """Criticality of a control, driving release gate impact.

    - `critical`: missing evidence forces `release_status = not_ready`.
    - `high`: missing evidence forces `release_status = conditional` (at best).
    - `medium`: missing evidence downgrades to `conditional` when paired with
      any other gap; otherwise tolerated.
    - `low`: advisory; never blocks the release by itself.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ControlEvaluationStatus(StrEnum):
    """Outcome of evaluating a control against collected evidence."""

    MET = "met"
    PARTIAL = "partial"
    MISSING = "missing"
    WAIVED = "waived"
    NOT_APPLICABLE = "not_applicable"


class ReleaseStatus(StrEnum):
    """Overall release readiness verdict computed from control evaluations."""

    READY = "ready"
    CONDITIONAL = "conditional"
    NOT_READY = "not_ready"
