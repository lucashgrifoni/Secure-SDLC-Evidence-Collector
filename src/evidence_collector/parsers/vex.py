"""Multi-format VEX parser (OpenVEX + CycloneDX VEX + CSAF). T6.7.

Reads a single VEX document on disk and returns a list of canonical
``VexStatement`` records that the OpenVEX exporter can merge with the
bundle-derived statements. Three shapes are detected by sniffing
discriminating top-level keys:

* **OpenVEX** — ``@context`` starts with ``https://openvex.dev/`` and
  ``statements`` is an array.
* **CycloneDX VEX** — a CycloneDX BOM (``bomFormat == "CycloneDX"``)
  whose ``vulnerabilities[*].analysis.state`` blocks restate
  exploitability decisions.
* **CSAF** — ``$schema`` references CSAF or a top-level ``document``
  with ``category == "csaf_vex"``. Statements come from
  ``vulnerabilities[*].product_status`` (``known_affected`` /
  ``known_not_affected`` / ``fixed`` / ``under_investigation``).

SPDX VEX is deferred (low industry adoption; tracked under v2.1
backlog).

Normalization rules (canonical OpenVEX vocabulary):

* CycloneDX ``state`` → OpenVEX status via the same map used by the
  inline-analysis path in ``exporters.vex``.
* CSAF ``known_affected`` → ``affected``, ``known_not_affected`` →
  ``not_affected``, ``fixed`` → ``fixed``, ``under_investigation`` →
  ``under_investigation``.

The parser is pure: zero IO outside of ``ensure_file`` / ``load_json``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from evidence_collector.parsers._common import (
    ParseError,
    describe,
    ensure_file,
    load_json,
)

VexShape = Literal["openvex", "cyclonedx-vex", "csaf-vex"]

OPENVEX_STATUSES = {"not_affected", "affected", "fixed", "under_investigation"}

_CVE_PATTERN = re.compile(r"\bCVE-(?:19|20)\d{2}-\d{4,7}\b", re.IGNORECASE)


# CycloneDX ``analysis.state`` → OpenVEX status.
_CDX_STATE_TO_OPENVEX: dict[str, str] = {
    "exploitable": "affected",
    "in_triage": "under_investigation",
    "false_positive": "not_affected",
    "not_affected": "not_affected",
    "resolved": "fixed",
    "resolved_with_pedigree": "fixed",
}

# CSAF ``product_status`` keys → OpenVEX status.
_CSAF_PRODUCT_STATUS_TO_OPENVEX: dict[str, str] = {
    "known_affected": "affected",
    "first_affected": "affected",
    "last_affected": "affected",
    "recommended": "affected",
    "known_not_affected": "not_affected",
    "first_fixed": "fixed",
    "fixed": "fixed",
    "under_investigation": "under_investigation",
}


@dataclass
class VexStatement:
    """Canonical, source-agnostic VEX statement."""

    cve_id: str
    status: str
    justification: str | None = None
    detail: str | None = None
    source_shape: VexShape | None = None
    source_path: str | None = None


def _detect_shape(data: dict[str, Any]) -> VexShape:
    context = data.get("@context")
    if isinstance(context, str) and "openvex.dev" in context:
        return "openvex"
    if data.get("bomFormat") == "CycloneDX":
        return "cyclonedx-vex"
    document = data.get("document")
    if (
        isinstance(document, dict)
        and isinstance(document.get("category"), str)
        and "csaf" in document["category"].lower()
    ):
        return "csaf-vex"
    schema = data.get("$schema")
    if isinstance(schema, str) and "csaf" in schema.lower():
        return "csaf-vex"
    raise ParseError(
        "VEX file did not match OpenVEX, CycloneDX VEX, or CSAF; "
        "set a discriminating top-level key."
    )


def _normalise_cve(value: Any) -> str | None:
    """Extract a CVE id from a raw string or vulnerability dict.

    OpenVEX puts the CVE in ``vulnerability.name``; CycloneDX puts it
    in ``vulnerabilities[*].id``; CSAF puts it in ``vulnerabilities[*].cve``.
    All three are accepted here.
    """
    if isinstance(value, dict):
        for key in ("name", "id", "cve"):
            inner = value.get(key)
            if isinstance(inner, str):
                match = _CVE_PATTERN.search(inner)
                if match is not None:
                    return match.group(0).upper()
        return None
    if isinstance(value, str):
        match = _CVE_PATTERN.search(value)
        if match is not None:
            return match.group(0).upper()
    return None


def _parse_openvex(data: dict[str, Any]) -> list[VexStatement]:
    statements_raw = data.get("statements")
    if not isinstance(statements_raw, list):
        return []
    out: list[VexStatement] = []
    for entry in statements_raw:
        if not isinstance(entry, dict):
            continue
        cve_id = _normalise_cve(entry.get("vulnerability"))
        if cve_id is None:
            continue
        status = entry.get("status")
        if status not in OPENVEX_STATUSES:
            continue
        justification_raw = entry.get("justification")
        out.append(
            VexStatement(
                cve_id=cve_id,
                status=str(status),
                justification=(
                    str(justification_raw) if isinstance(justification_raw, str) else None
                ),
                detail=(
                    str(entry.get("status_notes"))
                    if isinstance(entry.get("status_notes"), str)
                    else None
                ),
            )
        )
    return out


def _parse_cyclonedx_vex(data: dict[str, Any]) -> list[VexStatement]:
    vulns = data.get("vulnerabilities")
    if not isinstance(vulns, list):
        return []
    out: list[VexStatement] = []
    for vuln in vulns:
        if not isinstance(vuln, dict):
            continue
        cve_id = _normalise_cve(vuln)
        if cve_id is None:
            continue
        analysis = vuln.get("analysis")
        if not isinstance(analysis, dict):
            continue
        state_raw = analysis.get("state")
        if not isinstance(state_raw, str):
            continue
        status = _CDX_STATE_TO_OPENVEX.get(state_raw)
        if status is None:
            continue
        justification_raw = analysis.get("justification")
        detail_raw = analysis.get("detail")
        out.append(
            VexStatement(
                cve_id=cve_id,
                status=status,
                justification=(
                    str(justification_raw)
                    if isinstance(justification_raw, str)
                    else None
                ),
                detail=str(detail_raw) if isinstance(detail_raw, str) else None,
            )
        )
    return out


def _parse_csaf(data: dict[str, Any]) -> list[VexStatement]:
    vulns = data.get("vulnerabilities")
    if not isinstance(vulns, list):
        return []
    out: list[VexStatement] = []
    for vuln in vulns:
        if not isinstance(vuln, dict):
            continue
        cve_id = _normalise_cve(vuln.get("cve")) or _normalise_cve(vuln)
        if cve_id is None:
            continue
        product_status = vuln.get("product_status")
        if not isinstance(product_status, dict):
            continue
        # Pick the most specific bucket: known_affected wins over recommended
        # because we want the "affected" signal explicit when both apply.
        status: str | None = None
        for csaf_key, openvex_status in _CSAF_PRODUCT_STATUS_TO_OPENVEX.items():
            if csaf_key in product_status:
                status = openvex_status
                if openvex_status == "affected":
                    break
        if status is None:
            continue
        # Threats / impact text travels into ``detail`` so reviewers
        # keep the CSAF rationale visible after merge.
        threats = vuln.get("threats")
        detail = None
        if isinstance(threats, list) and threats:
            first = threats[0]
            if isinstance(first, dict):
                t = first.get("details")
                if isinstance(t, str):
                    detail = t
        out.append(
            VexStatement(
                cve_id=cve_id,
                status=status,
                justification=None,
                detail=detail,
            )
        )
    return out


def parse_vex(path: str | Path) -> list[VexStatement]:
    """Parse a VEX document into the canonical list of statements.

    The detected shape and the source path are stamped on every
    statement so the merger can attribute the verdict back to its
    origin when emitting a merged OpenVEX document.
    """
    resolved = ensure_file(path)
    data = load_json(resolved)
    shape = _detect_shape(data)
    if shape == "openvex":
        statements = _parse_openvex(data)
    elif shape == "cyclonedx-vex":
        statements = _parse_cyclonedx_vex(data)
    else:
        statements = _parse_csaf(data)
    # Touch describe() so a future caller that wants integrity hashes
    # for VEX inputs has the helper wired even though we do not store
    # the result here (CLI logs the path; consumers do not need the
    # hash today).
    describe(resolved, content_type="application/json")
    for stmt in statements:
        stmt.source_shape = shape
        stmt.source_path = str(resolved)
    return statements
