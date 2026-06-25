"""Regulatory profiles for the release pipeline (T6.8).

Profiles are post-processing filters applied to a bundle right
before serialisation. They do **not** change the underlying
evidence; they project a slice of the bundle into the shape a
specific regulator expects.

Two profiles ship in v2.0:

* ``cra-2026`` — EU Cyber Resilience Act (Regulation (EU) 2024/2847;
  vulnerability/incident reporting obligations start 2026-09-11).
  Annotates each evidence with ``metadata.cra.exploitation_status``
  and the CRA Article 14 reporting timeline under
  ``metadata.cra.reporting_deadlines`` — ``early_warning`` (24h),
  ``full_notification`` (72h), and ``final_report`` (14 days), all
  anchored on the report time — plus ``disclosure_deadline`` (kept as
  the 24h early-warning alias). The ENISA payload format is not yet
  final; the field names follow the spec direction and will be
  adjusted when ENISA publishes.

* ``fedramp-20x`` — pairs with ``catalog-fedramp-20x-ksi.yaml``.
  No bundle annotation is required (the verdict comes from the
  catalog), but the profile sets ``metadata.fedramp.retention`` on
  each evidence so the OSCAL Assessment Results exporter can stamp
  10-year retention without bespoke logic at export time.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

from evidence_collector.domain.models import EvidenceBundle, NormalizedEvidence


class ReleaseProfile(StrEnum):
    NONE = "none"
    CRA_2026 = "cra-2026"
    FEDRAMP_20X = "fedramp-20x"


CRA_DISCLOSURE_WINDOW = timedelta(hours=24)
CRA_FULL_NOTIFICATION_WINDOW = timedelta(hours=72)
CRA_FINAL_REPORT_WINDOW = timedelta(days=14)
CRA_REPORTING_OBLIGATION_START = "2026-09-11"
FEDRAMP_20X_RETENTION_YEARS = 10


def _cra_exploitation_status(evidence: NormalizedEvidence) -> str:
    """Derive a CRA-shaped ``exploitation_status`` for one enriched evidence.

    The EU CRA distinguishes vulnerabilities by exploitation state:
    ``actively_exploited`` (CISA KEV equivalent), ``known_exploitable``
    (public PoC or high EPSS), and ``under_investigation`` (no
    confirmed signal yet). We map our enrichment data onto those
    three values; consumers that want the raw signal can still read
    ``vulnerability_intelligence`` directly.
    """
    intel = evidence.vulnerability_intelligence
    if intel is None:
        return "under_investigation"
    for top in intel.top_risk_cves:
        if top.in_kev and top.known_ransomware:
            return "actively_exploited"
    for top in intel.top_risk_cves:
        if top.in_kev:
            return "actively_exploited"
    for top in intel.top_risk_cves:
        if top.epss_percentile >= 0.9:
            return "known_exploitable"
    return "under_investigation"


def _annotate_cra(bundle: EvidenceBundle, *, now: datetime | None = None) -> EvidenceBundle:
    anchor = now or datetime.now(tz=UTC)
    early_warning_iso = (anchor + CRA_DISCLOSURE_WINDOW).isoformat()
    full_notification_iso = (anchor + CRA_FULL_NOTIFICATION_WINDOW).isoformat()
    final_report_iso = (anchor + CRA_FINAL_REPORT_WINDOW).isoformat()
    new_evidence: list[NormalizedEvidence] = []
    for evidence in bundle.evidence:
        metadata: dict[str, Any] = dict(evidence.metadata)
        metadata["cra"] = {
            "exploitation_status": _cra_exploitation_status(evidence),
            # Kept for backward compatibility: the 24h early-warning deadline.
            "disclosure_deadline": early_warning_iso,
            # CRA Article 14 reporting timeline for actively-exploited
            # vulnerabilities, all anchored on the report time.
            "reporting_deadlines": {
                "early_warning": early_warning_iso,
                "full_notification": full_notification_iso,
                "final_report": final_report_iso,
            },
            "reporting_obligation_start": CRA_REPORTING_OBLIGATION_START,
            "regulation": "EU CRA 2024/2847",
        }
        new_evidence.append(evidence.model_copy(update={"metadata": metadata}))
    return bundle.model_copy(update={"evidence": new_evidence})


def _annotate_fedramp(bundle: EvidenceBundle) -> EvidenceBundle:
    new_evidence: list[NormalizedEvidence] = []
    for evidence in bundle.evidence:
        metadata: dict[str, Any] = dict(evidence.metadata)
        metadata["fedramp"] = {
            "retention_years": FEDRAMP_20X_RETENTION_YEARS,
            "profile": "20x",
        }
        new_evidence.append(evidence.model_copy(update={"metadata": metadata}))
    return bundle.model_copy(update={"evidence": new_evidence})


def apply_profile(
    bundle: EvidenceBundle,
    profile: ReleaseProfile,
    *,
    now: datetime | None = None,
) -> EvidenceBundle:
    """Return a new bundle with the profile-specific annotations applied."""
    if profile == ReleaseProfile.NONE:
        return bundle
    if profile == ReleaseProfile.CRA_2026:
        return _annotate_cra(bundle, now=now)
    if profile == ReleaseProfile.FEDRAMP_20X:
        return _annotate_fedramp(bundle)
    return bundle
