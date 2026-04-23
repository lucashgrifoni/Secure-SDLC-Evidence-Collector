"""Domain layer: pure entities, enums, and invariants of the evidence model.

This layer has no dependency on frameworks, IO, or adapters. It defines the
canonical contracts that every other layer must honor.
"""

from __future__ import annotations

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
from evidence_collector.domain.models import (
    Application,
    ControlDefinition,
    ControlEvaluation,
    EvidenceBundle,
    EvidenceException,
    EvidenceSource,
    ExceptionScope,
    Gap,
    NormalizedEvidence,
    RawEvidenceRef,
    ReleaseContext,
    Summary,
)

__all__ = [
    "Application",
    "ConfidenceLevel",
    "ControlCriticality",
    "ControlDefinition",
    "ControlEvaluation",
    "ControlEvaluationStatus",
    "ControlFramework",
    "EvidenceBundle",
    "EvidenceException",
    "EvidenceSource",
    "EvidenceStatus",
    "EvidenceType",
    "ExceptionScope",
    "Gap",
    "NormalizedEvidence",
    "RawEvidenceRef",
    "ReleaseContext",
    "ReleaseStatus",
    "SubjectType",
    "Summary",
]
