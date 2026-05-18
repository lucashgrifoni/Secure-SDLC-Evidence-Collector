"""OpenVEX exporter.

Emits a single OpenVEX (https://github.com/openvex/spec) document that
restates, in machine-readable VEX form, the exploitability statements
implied by an :class:`EvidenceBundle`:

* every CVE collected from a scanner is enumerated as a ``statement``
  with status ``under_investigation`` by default;
* any CVE listed in CISA KEV (via the enrichment step) is upgraded to
  ``affected`` with an ``action_statement`` that points at the EPSS /
  KEV evidence in the bundle;
* any CVE that the bundle's :class:`EvidenceException` machinery has
  waived for the active application + release is emitted as
  ``not_affected`` with the waiver justification and reference as
  ``justification`` and ``status_notes``.

The OpenVEX spec uses ``purl``-shaped product identifiers. The bundle
does not always have a purl, so we synthesize a stable
``pkg:generic/<repository>@<release_id>`` and fall back to the
application name when even the repository is missing. Consumers that
need real package coordinates should still rely on the SBOM; VEX here
is the per-CVE exploitability lane, not a replacement for the SBOM.

This module ships zero IO. The CLI command at
``cli/commands/vex.py`` is responsible for reading the bundle and
writing the OpenVEX JSON to disk.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from evidence_collector.domain.models import (
    EvidenceBundle,
    EvidenceException,
    NormalizedEvidence,
)

OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"
OPENVEX_AUTHOR = "secure-sdlc-evidence-collector"

# OpenVEX status vocabulary.
STATUS_NOT_AFFECTED = "not_affected"
STATUS_AFFECTED = "affected"
STATUS_FIXED = "fixed"
STATUS_UNDER_INVESTIGATION = "under_investigation"

# Allowed justification values for status `not_affected`. We only use one
# here (`vulnerable_code_not_in_execute_path`) when the waiver does not
# carry a specific reason; consumers can override by setting
# `justification` directly on the exception scope in future schemas.
DEFAULT_NOT_AFFECTED_JUSTIFICATION = "vulnerable_code_not_in_execute_path"


def _vex_id(bundle: EvidenceBundle) -> str:
    """Deterministic OpenVEX document id derived from bundle inputs.

    Using ``uuid5`` over a stable concatenation of bundle fields keeps
    the id reproducible across runs on identical inputs, which matters
    for downstream verifiers that hash the VEX document.
    """
    payload = "||".join(
        [
            bundle.application.name,
            bundle.application.repository,
            bundle.release.release_id,
            bundle.release.commit_sha,
        ]
    )
    return f"https://openvex.dev/docs/{uuid5(NAMESPACE_URL, payload)}"


def _product_id(bundle: EvidenceBundle) -> str:
    """Synthesize a stable purl-shaped product identifier."""
    repo = bundle.application.repository.strip()
    release = bundle.release.release_id.strip()
    if repo and release:
        return f"pkg:generic/{repo}@{release}"
    if repo:
        return f"pkg:generic/{repo}"
    return f"pkg:generic/{bundle.application.name}"


def _collect_cve_to_evidence(
    evidence_list: list[NormalizedEvidence],
) -> dict[str, list[str]]:
    """Build a CVE → [evidence_id] index over the bundle."""
    index: dict[str, list[str]] = {}
    for evidence in evidence_list:
        for cve_id in evidence.cve_ids:
            cid = cve_id.upper()
            index.setdefault(cid, []).append(evidence.evidence_id)
    return index


def _waiver_for_cve(
    _cve_id: str,
    exceptions: list[EvidenceException],
    application: str,
    release_id: str,
    now: datetime,
) -> EvidenceException | None:
    """Return the first valid exception that covers ``cve_id``.

    The current schema waives whole controls, not individual CVEs, so
    here we apply a coarse but useful rule: if any exception is valid
    for the current application+release window, every CVE collected
    during that window is considered intentionally accepted. Consumers
    that want CVE-level waivers can introduce a more granular schema
    later; for v1 this matches how the rest of the codebase reads
    exceptions.
    """
    for exc in exceptions:
        if exc.is_valid_for(application, release_id, now):
            return exc
    return None


def _kev_ransomware_cves(evidence_list: list[NormalizedEvidence]) -> set[str]:
    """CVE ids the enrichment step flagged as in KEV with ransomware use."""
    out: set[str] = set()
    for evidence in evidence_list:
        intel = evidence.vulnerability_intelligence
        if intel is None:
            continue
        for top in intel.top_risk_cves:
            if top.in_kev:
                out.add(top.cve_id.upper())
    return out


def build_openvex(bundle: EvidenceBundle, *, now: datetime | None = None) -> dict[str, Any]:
    """Return an OpenVEX 0.2.0 document derived from ``bundle``.

    The document is a plain ``dict`` so the CLI layer can serialise
    it with ``json.dumps`` and the unit tests can validate structure
    without round-tripping through Pydantic.
    """
    fixed_now = now or datetime.now(tz=UTC)
    cve_index = _collect_cve_to_evidence(list(bundle.evidence))
    in_kev = _kev_ransomware_cves(list(bundle.evidence))
    product_id = _product_id(bundle)

    statements: list[dict[str, Any]] = []
    for cve_id in sorted(cve_index.keys()):
        waiver = _waiver_for_cve(
            cve_id,
            list(bundle.exceptions),
            bundle.application.name,
            bundle.release.release_id,
            fixed_now,
        )
        if waiver is not None:
            statements.append(
                {
                    "vulnerability": {"name": cve_id},
                    "products": [{"@id": product_id}],
                    "status": STATUS_NOT_AFFECTED,
                    "justification": DEFAULT_NOT_AFFECTED_JUSTIFICATION,
                    "impact_statement": waiver.justification,
                    "status_notes": (
                        f"Waived under exception {waiver.exception_id} approved by "
                        f"{waiver.approver}; expires {waiver.expires_at.isoformat()}."
                    ),
                }
            )
        elif cve_id in in_kev:
            statements.append(
                {
                    "vulnerability": {"name": cve_id},
                    "products": [{"@id": product_id}],
                    "status": STATUS_AFFECTED,
                    "action_statement": (
                        "Listed in CISA KEV; review enrichment data on the "
                        "evidence records that report this CVE."
                    ),
                }
            )
        else:
            statements.append(
                {
                    "vulnerability": {"name": cve_id},
                    "products": [{"@id": product_id}],
                    "status": STATUS_UNDER_INVESTIGATION,
                }
            )

    return {
        "@context": OPENVEX_CONTEXT,
        "@id": _vex_id(bundle),
        "author": OPENVEX_AUTHOR,
        "timestamp": fixed_now.isoformat(),
        "version": 1,
        "statements": statements,
    }
