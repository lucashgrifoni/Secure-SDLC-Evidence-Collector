"""OpenVEX exporter.

Emits a single OpenVEX (https://github.com/openvex/spec) document that
restates, in machine-readable VEX form, the exploitability statements
implied by an :class:`EvidenceBundle`:

* every CVE collected from a scanner is enumerated as a ``statement``
  with status ``under_investigation`` by default;
* any CVE listed in CISA KEV (via the enrichment step) is upgraded to
  ``affected`` with an ``action_statement`` that points at the EPSS /
  KEV evidence in the bundle;
* a CVE is emitted as ``not_affected`` only when a waiver actually
  applies to it: the exception is in force for the bundle's application,
  release and clock, the engine recorded it on a control it names as
  ``waived`` (``exception_refs``), and the CVE is reported by evidence of a
  type that control was missing (``missing_required_evidence_types``), i.e.
  the evidence the waiver compensates for. Any other exception, including
  an in-force one on an unrelated or met control, leaves the CVE exactly
  as it would be without waivers.

The document is reproducible: the clock defaults to the bundle's
``generated_at`` (for both ``timestamp`` and waiver validity), and ``@id``
is derived from the bundle identity plus a digest of the statements, so
two runs on one bundle are byte-identical and different content never
shares an id.

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

import hashlib
import json
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from evidence_collector.domain.enums import ControlEvaluationStatus
from evidence_collector.domain.models import (
    EvidenceBundle,
    EvidenceException,
    NormalizedEvidence,
)
from evidence_collector.parsers.vex import VexStatement


class MergeConflictPolicy(StrEnum):
    """How to handle conflicts between VEX sources for the same CVE (T6.7)."""

    FIRST_WINS = "first-wins"
    LAST_WINS = "last-wins"
    FAIL = "fail"


class VexMergeConflictError(ValueError):
    """Raised under ``MergeConflictPolicy.FAIL`` when two VEX sources disagree."""


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

# Map CycloneDX inline-analysis ``state`` to an OpenVEX status. The
# CycloneDX vocabulary is broader than OpenVEX (e.g. ``resolved`` vs
# ``resolved_with_pedigree``); we collapse equivalent values to the
# nearest OpenVEX bucket and let the bundle carry the original
# CycloneDX detail in ``status_notes``.
_CYCLONEDX_STATE_TO_OPENVEX: dict[str, str] = {
    "exploitable": STATUS_AFFECTED,
    "in_triage": STATUS_UNDER_INVESTIGATION,
    "false_positive": STATUS_NOT_AFFECTED,
    "not_affected": STATUS_NOT_AFFECTED,
    "resolved": STATUS_FIXED,
    "resolved_with_pedigree": STATUS_FIXED,
}

# Map CycloneDX ``analysis.justification`` to an OpenVEX justification.
# OpenVEX only defines five values, all for ``not_affected``; the
# CycloneDX vocabulary is wider, so several CycloneDX values fall into
# the same OpenVEX bucket. When CycloneDX justification has no OpenVEX
# equivalent we fall back to the default and keep the CycloneDX text in
# ``status_notes`` for transparency.
_CYCLONEDX_JUSTIFICATION_TO_OPENVEX: dict[str, str] = {
    "code_not_present": "vulnerable_code_not_present",
    "code_not_reachable": "vulnerable_code_not_in_execute_path",
    "requires_configuration": "vulnerable_code_cannot_be_controlled_by_adversary",
    "requires_dependency": "vulnerable_code_cannot_be_controlled_by_adversary",
    "requires_environment": "vulnerable_code_cannot_be_controlled_by_adversary",
    "protected_by_compiler": "inline_mitigations_already_exist",
    "protected_at_runtime": "inline_mitigations_already_exist",
    "protected_at_perimeter": "inline_mitigations_already_exist",
    "protected_by_mitigating_control": "inline_mitigations_already_exist",
}


def _vex_id(bundle: EvidenceBundle, statements: list[dict[str, Any]], timestamp: str) -> str:
    """Deterministic OpenVEX document id derived from bundle inputs and content.

    Using ``uuid5`` over a stable concatenation of bundle fields keeps
    the id reproducible across runs on identical inputs, which matters
    for downstream verifiers that hash the VEX document. The statements'
    digest and the document ``timestamp`` are part of the payload so two
    documents with different content for the same release never share an
    id (the ``version`` stays 1).
    """
    statements_digest = hashlib.sha256(
        json.dumps(statements, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    payload = "||".join(
        [
            bundle.application.name,
            bundle.application.repository,
            bundle.release.release_id,
            bundle.release.commit_sha,
            statements_digest,
            timestamp,
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


def _waivers_by_cve(bundle: EvidenceBundle, now: datetime) -> dict[str, EvidenceException]:
    """Map each CVE to the exception that actually waives it, if any.

    Exceptions waive controls, not CVEs, so a CVE is waived only through a
    control the waiver was applied to. An exception counts for a CVE when
    all of these hold:

    * it is in force for the bundle's application and release at ``now``;
    * a control evaluation it names (``control_id``) is ``waived`` and lists
      it in ``exception_refs`` (the engine also lists in-force waivers on
      met controls, and those waived nothing);
    * the CVE is reported by evidence whose type is among that control's
      ``missing_required_evidence_types``, the evidence the waiver stands in
      for. A control waived for a missing SBOM says nothing about CVEs from
      a passing SCA scan, and a rollback waiver says nothing about any CVE.

    The first match in bundle order (evaluations, then ``exception_refs``,
    then evidence) wins, which keeps the result deterministic.
    """
    application = bundle.application.name
    release_id = bundle.release.release_id
    in_force = {
        exc.exception_id: exc
        for exc in bundle.exceptions
        if exc.is_valid_for(application, release_id, now)
    }
    out: dict[str, EvidenceException] = {}
    for evaluation in bundle.control_evaluations:
        if evaluation.evaluation_status != ControlEvaluationStatus.WAIVED:
            continue
        waived_types = set(evaluation.missing_required_evidence_types)
        for ref in evaluation.exception_refs:
            exc = in_force.get(ref)
            if exc is None or exc.control_id != evaluation.control_id:
                continue
            for evidence in bundle.evidence:
                if evidence.evidence_type not in waived_types:
                    continue
                for cve_id in evidence.cve_ids:
                    out.setdefault(cve_id.upper(), exc)
    return out


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


def _collect_sbom_inline_analyses(
    evidence_list: list[NormalizedEvidence],
) -> dict[str, dict[str, Any]]:
    """Index CycloneDX inline ``vulnerabilities[*].analysis`` blocks by CVE id.

    The SBOM normalizer carries these as a list of dicts under
    ``metadata.sbom_vex_analyses``. When more than one SBOM evidence
    record covers the same CVE, the first one wins for stability
    (alphabetical evidence order from the bundle).
    """
    out: dict[str, dict[str, Any]] = {}
    for evidence in evidence_list:
        analyses = evidence.metadata.get("sbom_vex_analyses")
        if not isinstance(analyses, list):
            continue
        for entry in analyses:
            if not isinstance(entry, dict):
                continue
            cve_id_raw = entry.get("cve_id")
            if not isinstance(cve_id_raw, str):
                continue
            cve_id = cve_id_raw.upper()
            if cve_id in out:
                continue
            out[cve_id] = entry
    return out


def _statement_from_inline_analysis(
    cve_id: str, product_id: str, analysis: dict[str, Any]
) -> dict[str, Any] | None:
    """Translate a CycloneDX inline analysis into an OpenVEX statement.

    Returns ``None`` when the analysis carries no usable state, which
    lets the caller fall back to the default exploitability logic.
    """
    state_raw = analysis.get("state")
    if not isinstance(state_raw, str):
        return None
    openvex_status = _CYCLONEDX_STATE_TO_OPENVEX.get(state_raw)
    if openvex_status is None:
        return None

    statement: dict[str, Any] = {
        "vulnerability": {"name": cve_id},
        "products": [{"@id": product_id}],
        "status": openvex_status,
    }

    detail_raw = analysis.get("detail")
    notes_parts: list[str] = [f"Inline CycloneDX analysis: state={state_raw}"]
    if isinstance(detail_raw, str) and detail_raw.strip():
        notes_parts.append(detail_raw.strip())
    responses_raw = analysis.get("responses")
    if isinstance(responses_raw, list) and responses_raw:
        notes_parts.append("responses=" + ",".join(str(r) for r in responses_raw))

    if openvex_status == STATUS_NOT_AFFECTED:
        justification_raw = analysis.get("justification")
        openvex_justification = (
            _CYCLONEDX_JUSTIFICATION_TO_OPENVEX.get(justification_raw)
            if isinstance(justification_raw, str)
            else None
        )
        statement["justification"] = openvex_justification or DEFAULT_NOT_AFFECTED_JUSTIFICATION
        if isinstance(justification_raw, str) and openvex_justification is None:
            notes_parts.append(f"cyclonedx_justification={justification_raw}")
    elif openvex_status == STATUS_AFFECTED:
        statement["action_statement"] = (
            "CycloneDX inline analysis marked vulnerability exploitable; "
            "review the SBOM analysis detail."
        )

    statement["status_notes"] = "; ".join(notes_parts)
    return statement


def build_openvex(bundle: EvidenceBundle, *, now: datetime | None = None) -> dict[str, Any]:
    """Return an OpenVEX 0.2.0 document derived from ``bundle``.

    The document is a plain ``dict`` so the CLI layer can serialise
    it with ``json.dumps`` and the unit tests can validate structure
    without round-tripping through Pydantic.

    ``now`` defaults to ``bundle.generated_at`` and drives both the
    document ``timestamp`` and waiver validity, so the output depends on
    the bundle alone.
    """
    fixed_now = now or bundle.generated_at
    if fixed_now.tzinfo is None:
        # Waiver windows are timezone-aware; a naive bundle clock means UTC.
        fixed_now = fixed_now.replace(tzinfo=UTC)
    evidence_list = list(bundle.evidence)
    cve_index = _collect_cve_to_evidence(evidence_list)
    in_kev = _kev_ransomware_cves(evidence_list)
    inline_analyses = _collect_sbom_inline_analyses(evidence_list)
    product_id = _product_id(bundle)
    waivers = _waivers_by_cve(bundle, fixed_now)

    statements: list[dict[str, Any]] = []
    for cve_id in sorted(cve_index.keys()):
        waiver = waivers.get(cve_id)
        if waiver is not None:
            # An applied waiver wins over every other signal, KEV included — the operator
            # accepted the risk in writing.
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
            continue

        # CycloneDX inline analysis is a declared exploitability decision
        # by whoever produced the SBOM; honour it over the default
        # ``under_investigation`` and over the KEV heuristic, so the
        # SBOM author's call survives the round-trip into OpenVEX.
        analysis = inline_analyses.get(cve_id)
        if analysis is not None:
            statement = _statement_from_inline_analysis(cve_id, product_id, analysis)
            if statement is not None:
                statements.append(statement)
                continue

        if cve_id in in_kev:
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
        "@id": _vex_id(bundle, statements, fixed_now.isoformat()),
        "author": OPENVEX_AUTHOR,
        "timestamp": fixed_now.isoformat(),
        "version": 1,
        "statements": statements,
    }


def _statement_from_consumed(cve_id: str, product_id: str, stmt: VexStatement) -> dict[str, Any]:
    """Translate a consumed VEX statement into an OpenVEX statement dict."""
    out: dict[str, Any] = {
        "vulnerability": {"name": cve_id},
        "products": [{"@id": product_id}],
        "status": stmt.status,
    }
    if stmt.status == STATUS_NOT_AFFECTED:
        out["justification"] = stmt.justification or DEFAULT_NOT_AFFECTED_JUSTIFICATION
    notes: list[str] = []
    if stmt.source_shape:
        notes.append(f"source={stmt.source_shape}")
    if stmt.source_path:
        notes.append(f"path={stmt.source_path}")
    if stmt.detail:
        notes.append(stmt.detail)
    if notes:
        out["status_notes"] = "; ".join(notes)
    return out


def merge_consumed_vex(
    bundle_document: dict[str, Any],
    bundle: EvidenceBundle,
    consumed: list[VexStatement],
    *,
    policy: MergeConflictPolicy = MergeConflictPolicy.LAST_WINS,
) -> dict[str, Any]:
    """Merge ``consumed`` VEX statements into a bundle-derived OpenVEX document.

    Conflict policy semantics:

    * ``last-wins`` (default) — a consumed statement overrides any
      bundle-derived statement for the same CVE. Useful when an
      authoritative vendor VEX should win over the collector's
      heuristic verdict.
    * ``first-wins`` — bundle-derived statements are preserved; a
      consumed statement is only added when the bundle has no
      statement for that CVE.
    * ``fail`` — raise :class:`VexMergeConflictError` if the bundle and a
      consumed source disagree on a CVE's ``status``. Use in
      pipelines where an unexpected disagreement is itself a finding.
    """
    product_id = _product_id(bundle)
    by_cve: dict[str, dict[str, Any]] = {
        s["vulnerability"]["name"]: s
        for s in bundle_document.get("statements", [])
        if isinstance(s, dict) and isinstance(s.get("vulnerability"), dict)
    }
    for stmt in consumed:
        cve_id = stmt.cve_id.upper()
        new_statement = _statement_from_consumed(cve_id, product_id, stmt)
        existing = by_cve.get(cve_id)
        if existing is None:
            by_cve[cve_id] = new_statement
            continue
        existing_status = existing.get("status")
        if existing_status == stmt.status:
            # Agreement: keep the consumed statement so source attribution
            # makes it into the merged output.
            by_cve[cve_id] = new_statement
            continue
        if policy == MergeConflictPolicy.FAIL:
            raise VexMergeConflictError(
                f"VEX conflict for {cve_id}: bundle says {existing_status}, "
                f"consumed source says {stmt.status} "
                f"({stmt.source_shape or 'unknown'} / {stmt.source_path or 'inline'})."
            )
        if policy == MergeConflictPolicy.LAST_WINS:
            by_cve[cve_id] = new_statement
        # FIRST_WINS: keep ``existing`` untouched.

    bundle_document["statements"] = [by_cve[k] for k in sorted(by_cve.keys())]
    # The content changed, so the content-derived id must follow it.
    bundle_document["@id"] = _vex_id(
        bundle, bundle_document["statements"], bundle_document["timestamp"]
    )
    return bundle_document
