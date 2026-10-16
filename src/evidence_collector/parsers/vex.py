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

SPDX VEX is deferred (low industry adoption) and not scheduled.

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
from urllib.parse import quote, unquote

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
    # Product identifiers the source statement names (purl, CPE, CycloneDX
    # ref or CSAF product id). The merger applies a statement only to the
    # release it names; an empty tuple means the source named no product.
    products: tuple[str, ...] = ()


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


def _strings(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    return [v.strip() for v in values if isinstance(v, str) and v.strip()]


def _openvex_products(entry: dict[str, Any]) -> tuple[str, ...]:
    products: list[str] = []
    raw = entry.get("products")
    for product in raw if isinstance(raw, list) else []:
        if isinstance(product, str) and product.strip():
            products.append(product.strip())
        elif isinstance(product, dict):
            ident = product.get("@id")
            if isinstance(ident, str) and ident.strip():
                products.append(ident.strip())
            identifiers = product.get("identifiers")
            if isinstance(identifiers, dict):
                products.extend(
                    v.strip() for v in identifiers.values() if isinstance(v, str) and v.strip()
                )
    return tuple(dict.fromkeys(products))


def _csaf_identities(data: dict[str, Any]) -> dict[str, list[str]]:
    """Map each CSAF product id to its purl / CPE from the product tree."""
    identities: dict[str, list[str]] = {}

    def visit(node: Any) -> None:
        if isinstance(node, list):
            for item in node:
                visit(item)
            return
        if not isinstance(node, dict):
            return
        # Branch leaves carry `product`; relationships carry the derived
        # product as a singular `full_product_name`.
        candidates = [
            value
            for value in (node.get("product"), node.get("full_product_name"))
            if isinstance(value, dict)
        ]
        names = node.get("full_product_names")
        if isinstance(names, list):
            candidates.extend(n for n in names if isinstance(n, dict))
        for candidate in candidates:
            pid = candidate.get("product_id")
            helper = candidate.get("product_identification_helper")
            if isinstance(pid, str) and isinstance(helper, dict):
                identities.setdefault(pid, []).extend(
                    v.strip()
                    for key in ("purl", "cpe")
                    for v in [helper.get(key)]
                    if isinstance(v, str) and v.strip()
                )
        visit(node.get("branches"))
        visit(node.get("relationships"))

    visit(data.get("product_tree"))
    return identities


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
        # A list or dict status is unhashable and raised TypeError on the set
        # lookup; it is an unknown status like any other and is skipped.
        if not isinstance(status, str) or status not in OPENVEX_STATUSES:
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
                products=_openvex_products(entry),
            )
        )
    return out


# Which `versions[].status` values agree with each OpenVEX status. CycloneDX
# defaults a missing status to `affected`; `unknown` agrees with nothing but an
# open investigation.
_CDX_VERSION_STATUS_FOR: dict[str, frozenset[str]] = {
    "affected": frozenset({"affected"}),
    "not_affected": frozenset({"unaffected"}),
    "fixed": frozenset({"unaffected"}),
    "under_investigation": frozenset({"affected", "unaffected", "unknown"}),
}


def _cyclonedx_identities(data: dict[str, Any]) -> dict[str, list[str]]:
    """Map each component or service ``bom-ref`` to its purl / CPE.

    A versionless purl takes the component's own ``version``: resolved bare,
    it would stand for every version of the package.
    """
    identities: dict[str, list[str]] = {}

    def visit(node: Any) -> None:
        if isinstance(node, list):
            for item in node:
                visit(item)
            return
        if not isinstance(node, dict):
            return
        ref = node.get("bom-ref")
        if isinstance(ref, str) and ref.strip():
            names: list[str] = []
            purl = node.get("purl")
            if isinstance(purl, str) and purl.strip():
                purl = purl.strip()
                version = node.get("version")
                versionless = "@" not in purl.split("?", 1)[0].split("#", 1)[0]
                if versionless and isinstance(version, str) and version.strip():
                    purl = _constrain_purl(purl, {version.strip()})[0]
                names.append(purl)
            cpe = node.get("cpe")
            if isinstance(cpe, str) and cpe.strip():
                names.append(cpe.strip())
            identities.setdefault(ref.strip(), []).extend(names)
        visit(node.get("components"))
        visit(node.get("services"))

    metadata = data.get("metadata")
    if isinstance(metadata, dict):
        visit(metadata.get("component"))
    visit(data.get("components"))
    visit(data.get("services"))
    return identities


def _constrain_purl(purl: str, explicit: set[str]) -> list[str]:
    """The versions of ``purl`` that a ``versions`` array leaves in scope."""
    core = purl.split("?", 1)[0].split("#", 1)[0]
    if "@" in core:
        # A versioned purl keeps its meaning only when the constraint lists
        # that same version; otherwise the two disagree and nothing is named.
        return [purl] if unquote(core.rsplit("@", 1)[1]) in explicit else []
    base, sep, rest = purl.partition("?")
    if not sep:
        base, sep, rest = purl.partition("#")
    suffix = f"{sep}{rest}" if sep else ""
    # Encoded as a canonical purl version: `1.0+deb1` becomes `1.0%2Bdeb1`.
    return [f"{base}@{quote(version, safe='.-_~')}{suffix}" for version in sorted(explicit)]


def _cyclonedx_affected_refs(
    entry: dict[str, Any], status: str, identities: dict[str, list[str]]
) -> list[str]:
    """The product identifiers one CycloneDX ``affects`` entry names.

    A bom-ref is resolved to the purl / CPE of the component it points at,
    as CSAF product ids are. A versionless purl restricted by a ``versions``
    array stands only for those versions: each explicit ``version`` whose own
    status agrees with the analysis becomes ``purl@version``. A ``range`` is
    not evaluated, so it contributes nothing; read as the bare ref it would
    have covered every version of the package. With ``versions``, only purls
    are named: a bare bom-ref or a CPE would drop the constraint. A purl that
    already carries a version stays only when ``versions`` lists it.
    """
    ref = entry.get("ref")
    if not isinstance(ref, str) or not ref.strip():
        return []
    ref = ref.strip()
    names = [ref, *identities.get(ref, [])]
    versions = entry.get("versions")
    if not isinstance(versions, list) or not versions:
        return names
    # A version whose own status contradicts the analysis (`affected` under a
    # `not_affected` analysis) is left out rather than given the wrong verdict.
    agreeing = _CDX_VERSION_STATUS_FOR.get(status, frozenset())
    explicit = {
        item["version"].strip()
        for item in versions
        if isinstance(item, dict)
        and isinstance(item.get("version"), str)
        and item["version"].strip()
        and str(item.get("status") or "affected") in agreeing
    }
    return [
        constrained
        for name in names
        if name.startswith("pkg:")
        for constrained in _constrain_purl(name, explicit)
    ]


def _parse_cyclonedx_vex(data: dict[str, Any]) -> list[VexStatement]:
    vulns = data.get("vulnerabilities")
    if not isinstance(vulns, list):
        return []
    out: list[VexStatement] = []
    identities = _cyclonedx_identities(data)
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
        affects = vuln.get("affects")
        refs = [
            ref
            for a in (affects if isinstance(affects, list) else [])
            if isinstance(a, dict)
            for ref in _cyclonedx_affected_refs(a, status, identities)
        ]
        out.append(
            VexStatement(
                cve_id=cve_id,
                status=status,
                justification=(
                    str(justification_raw) if isinstance(justification_raw, str) else None
                ),
                detail=str(detail_raw) if isinstance(detail_raw, str) else None,
                products=tuple(dict.fromkeys(refs)),
            )
        )
    return out


def _parse_csaf(data: dict[str, Any]) -> list[VexStatement]:
    vulns = data.get("vulnerabilities")
    if not isinstance(vulns, list):
        return []
    out: list[VexStatement] = []
    identities = _csaf_identities(data)
    for vuln in vulns:
        if not isinstance(vuln, dict):
            continue
        cve_id = _normalise_cve(vuln.get("cve")) or _normalise_cve(vuln)
        if cve_id is None:
            continue
        product_status = vuln.get("product_status")
        if not isinstance(product_status, dict):
            continue
        # One statement per OpenVEX status, each naming the products of every
        # CSAF bucket that maps to it: `known_affected: [a]` beside
        # `first_affected: [b]` marks both a and b affected.
        ids_by_status: dict[str, list[str]] = {}
        for csaf_key, openvex_status in _CSAF_PRODUCT_STATUS_TO_OPENVEX.items():
            if csaf_key in product_status:
                ids_by_status.setdefault(openvex_status, []).extend(
                    _strings(product_status.get(csaf_key))
                )
        if not ids_by_status:
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
        for status, product_ids in ids_by_status.items():
            products = list(product_ids)
            for pid in product_ids:
                products.extend(identities.get(pid, []))
            out.append(
                VexStatement(
                    cve_id=cve_id,
                    status=status,
                    justification=None,
                    detail=detail,
                    products=tuple(dict.fromkeys(products)),
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
