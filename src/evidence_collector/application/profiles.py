"""Opt-in evidence annotations, with no submissions or certification claims.

CRA clocks require release-bound operator context. KEV/EPSS signals do not
establish product exploitation or the manufacturer's awareness. FedRAMP
identifies the reviewed CR26 revision without prescribing retention policy.
"""

from __future__ import annotations

import calendar
import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, Self

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator

from evidence_collector.domain.models import EvidenceBundle, NormalizedEvidence
from evidence_collector.parsers._common import ensure_file, load_json


class ReleaseProfile(StrEnum):
    NONE = "none"
    CRA_2026 = "cra-2026"
    FEDRAMP_20X = "fedramp-20x"


CRA_DISCLOSURE_WINDOW = timedelta(hours=24)
CRA_FULL_NOTIFICATION_WINDOW = timedelta(hours=72)
CRA_FINAL_REPORT_WINDOW = timedelta(days=14)
CRA_REPORTING_OBLIGATION_START = "2026-09-11"
# Art. 71(2): Article 14 applies from 11 September 2026. ENISA FAQ Q13: awareness
# before that date carries no retrospective reporting obligation. Taken as UTC.
_CRA_OBLIGATION_START_AT = datetime(2026, 9, 11, tzinfo=UTC)
_NOT_APPLICABLE = {"status": "not_applicable", "reason": "awareness_precedes_obligation_start"}
FEDRAMP_RULESET_VERSION = "2026.10.05.01"
FEDRAMP_RULESET_COMMIT = "1c33385a06acf4faf50da2b9b4dc31cd826e5b91"
SRP_GLOSSARY_URL = "https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp/cra-srp-glossary2"
_SRP_FIELD_IDS = frozenset(
    [str(i) for i in range(1, 19)]
    + [f"v{i}" for i in range(19, 31)]
    + ["v26a"]
    + [f"i{i}" for i in range(31, 40)]
    # 40 (AR Note) is optional reporter text. 41 (CSIRT Note) is written by the
    # designated CSIRT, not the reporter, so it stays unknown here.
    + ["40"]
)


class CraReportingContext(BaseModel):
    """Operator input bound to one release; narrative adequacy is not checked."""

    model_config = ConfigDict(extra="forbid")
    release_id: str = Field(min_length=1, max_length=255)
    commit_sha: str = Field(min_length=1, max_length=255)
    notification_type: Literal["vulnerability", "incident"]
    awareness_at: AwareDatetime | None = None
    corrective_measure_available_at: AwareDatetime | None = None
    notification_72h_submitted_at: AwareDatetime | None = None
    euvd_ids: list[str] = Field(default_factory=list, max_length=100)
    srp_fields: dict[str, str] = Field(default_factory=dict, max_length=40)

    @field_validator("notification_type", mode="before")
    @classmethod
    def _lowercase_type(cls, value: object) -> object:
        return value.lower() if isinstance(value, str) else value

    @model_validator(mode="after")
    def validate_scope(self) -> Self:
        timestamps = (
            self.awareness_at,
            self.corrective_measure_available_at,
            self.notification_72h_submitted_at,
        )
        if any(timestamp and not 2 <= timestamp.year <= 9998 for timestamp in timestamps):
            raise ValueError("CRA timestamps must allow deadline arithmetic (years 2 through 9998)")
        if any(not re.fullmatch(r"EUVD-\d{4}-\d{4,}", value) for value in self.euvd_ids):
            raise ValueError("EUVD identifiers must use EUVD-YYYY-NNNN (variable-length sequence)")
        if self.notification_type == "incident" and (
            self.euvd_ids or self.corrective_measure_available_at
        ):
            raise ValueError(
                "EUVD and corrective-measure timestamps belong to vulnerability notifications"
            )
        if self.notification_type == "vulnerability" and self.notification_72h_submitted_at:
            raise ValueError("The submitted-notification clock belongs to incident final reports")
        if (
            self.awareness_at
            and self.notification_72h_submitted_at
            and self.notification_72h_submitted_at < self.awareness_at
        ):
            raise ValueError("notification_72h_submitted_at cannot be earlier than awareness_at")
        for key, value in self.srp_fields.items():
            if key == "41":
                raise ValueError(
                    "SRP field '41' (CSIRT Note) is written by the designated CSIRT, "
                    "not the reporter; remove it from srp_fields"
                )
            if key not in _SRP_FIELD_IDS:
                raise ValueError(
                    f"Unknown SRP field identifier {key!r}; expected one of 1-18, "
                    "v19-v30, v26a, i31-i39 or 40"
                )
            if len(value) > 4000:
                raise ValueError(f"SRP field {key!r} is {len(value)} characters; the limit is 4000")
        if self.notification_type == "incident" and any(
            key.startswith("v") for key in self.srp_fields
        ):
            raise ValueError("Vulnerability fields cannot be used in an incident notification")
        if self.notification_type == "vulnerability" and any(
            key.startswith("i") for key in self.srp_fields
        ):
            raise ValueError("Incident fields cannot be used in a vulnerability notification")
        return self


def load_cra_context(path: str) -> CraReportingContext:
    return CraReportingContext.model_validate(load_json(ensure_file(Path(path))))


def _global_exploitation_signal(evidence: NormalizedEvidence) -> str:
    intel = evidence.vulnerability_intelligence
    if intel is None:
        return "unavailable"
    if any(top.in_kev for top in intel.top_risk_cves):
        return "kev_listed"
    if any(top.epss_percentile >= 0.9 for top in intel.top_risk_cves):
        return "high_epss_percentile"
    return "no_kev_or_high_epss_in_top_risk_cves"


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat()


def _one_month_after(value: datetime) -> datetime:
    value = value.astimezone(UTC)
    year = value.year + (value.month == 12)
    month = value.month % 12 + 1
    return value.replace(
        year=year, month=month, day=min(value.day, calendar.monthrange(year, month)[1])
    )


def _cra_metadata(context: CraReportingContext | None) -> dict[str, Any]:
    kind = context.notification_type if context else None
    awareness = context.awareness_at if context else None
    deadlines: dict[str, Any] = {
        "early_warning": _iso(awareness + CRA_DISCLOSURE_WINDOW)
        if awareness
        else {"relative_to": "awareness_at", "window_hours": 24},
        "full_notification": _iso(awareness + CRA_FULL_NOTIFICATION_WINDOW)
        if awareness
        else {"relative_to": "awareness_at", "window_hours": 72},
    }
    if kind == "incident":
        final: dict[str, Any] = {
            "relative_to": "notification_72h_submitted_at",
            "window_calendar_months": 1,
        }
        if context and context.notification_72h_submitted_at:
            final["due_at"] = _iso(_one_month_after(context.notification_72h_submitted_at))
    elif kind == "vulnerability":
        final = {"relative_to": "corrective_or_mitigating_measure_available", "window_days": 14}
        if context and context.corrective_measure_available_at:
            final["due_at"] = _iso(
                context.corrective_measure_available_at + CRA_FINAL_REPORT_WINDOW
            )
    else:
        final = {
            "vulnerability": {
                "relative_to": "corrective_or_mitigating_measure_available",
                "window_days": 14,
            },
            "incident": {
                "relative_to": "notification_72h_submitted_at",
                "window_calendar_months": 1,
            },
        }
    deadlines["final_report"] = final
    if awareness and awareness < _CRA_OBLIGATION_START_AT:
        deadlines = {stage: dict(_NOT_APPLICABLE) for stage in deadlines}
    metadata: dict[str, Any] = {
        "notification_type": kind,
        "awareness_at": _iso(awareness) if awareness else None,
        "awareness_source": "operator_context" if awareness else "not_supplied",
        "annotation_scope": "release_context_not_per_finding",
        "legal_applicability": "not_assessed",
        "exploitation_status": "not_assessed",
        "reporting_deadlines": deadlines,
        "disclosure_deadline": deadlines["early_warning"],
        "reporting_obligation_start": CRA_REPORTING_OBLIGATION_START,
        "regulation": "EU CRA 2024/2847",
        "article": {"vulnerability": "14(2)", "incident": "14(4)"}.get(kind or "", "14(2),14(4)"),
        "srp_glossary_version": "1.4",
        "srp_glossary_date": "2026-10-01",
        "srp_glossary_url": SRP_GLOSSARY_URL,
        "submission_status": "not_submitted",
    }
    if context:
        fingerprint = json.dumps(
            context.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        ).encode()
        metadata["canonical_context_sha256"] = hashlib.sha256(fingerprint).hexdigest()
        metadata["euvd_ids"] = sorted(set(context.euvd_ids))
        provided = {key for key, value in context.srp_fields.items() if value.strip()} | {"1"}
        if awareness:
            provided.add("v26" if kind == "vulnerability" else "i37")
        if context.corrective_measure_available_at:
            provided.add("v22")
        common = {str(i) for i in range(1, 8)}
        early = common | ({"v26"} if kind == "vulnerability" else {"i31", "i37"})
        full = early | ({"v21", "v26a"} if kind == "vulnerability" else {"i32", "i38", "i39"})
        final_fields = (
            (full - ({"i38"} if kind == "incident" else set()))
            | {"16", "17"}
            | (
                {"v22", "v23", "v24", "v25"}
                if kind == "vulnerability"
                else {"i33", "i34", "i35", "i36"}
            )
        )
        metadata["srp_completeness"] = {
            stage: {"missing_field_ids": sorted(required - provided), "presence_only": True}
            for stage, required in [
                ("early_warning", early),
                ("72h_notification", full),
                ("final_report", final_fields),
            ]
        }
        metadata["srp_conditional_manual_fields"] = ["v27"] if kind == "vulnerability" else []
        metadata["srp_declared_field_ids"] = sorted(provided)
    return metadata


def apply_profile(
    bundle: EvidenceBundle,
    profile: ReleaseProfile,
    *,
    now: datetime | None = None,
    cra_context: CraReportingContext | None = None,
    fedramp_class: Literal["A", "B", "C", "D"] | None = None,
) -> EvidenceBundle:
    """Annotate a copy; deprecated now never substitutes for awareness."""
    if cra_context is not None:
        if profile != ReleaseProfile.CRA_2026:
            raise ValueError("CRA context requires the cra-2026 profile")
        if (
            cra_context.release_id != bundle.release.release_id
            or cra_context.commit_sha.lower() != bundle.release.commit_sha.lower()
        ):
            raise ValueError("CRA context must match the bundle release_id and commit_sha")
    if fedramp_class and profile != ReleaseProfile.FEDRAMP_20X:
        raise ValueError("FedRAMP class requires the fedramp-20x profile")
    if fedramp_class is not None and fedramp_class not in {"A", "B", "C", "D"}:
        raise ValueError("FedRAMP class must be A, B, C or D")
    if profile == ReleaseProfile.NONE:
        return bundle
    new_evidence = []
    for evidence in bundle.evidence:
        metadata = dict(evidence.metadata)
        if profile == ReleaseProfile.CRA_2026:
            metadata["cra"] = _cra_metadata(cra_context)
            metadata["cra"]["global_exploitation_signal"] = _global_exploitation_signal(evidence)
        elif profile == ReleaseProfile.FEDRAMP_20X:
            metadata["fedramp"] = {
                "profile": "20x",
                "ruleset": "CR26",
                "ruleset_version": FEDRAMP_RULESET_VERSION,
                "ruleset_commit": FEDRAMP_RULESET_COMMIT,
                "class": fedramp_class,
                "certification_status": "not_assessed",
                "retention_policy": "operator_defined",
            }
        new_evidence.append(evidence.model_copy(update={"metadata": metadata}))
    return bundle.model_copy(update={"evidence": new_evidence})
