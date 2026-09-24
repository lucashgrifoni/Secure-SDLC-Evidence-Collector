"""Parsers for raw evidence formats (SARIF, CycloneDX, SPDX, JUnit, attestations)."""

from __future__ import annotations

from evidence_collector.parsers.attestation import parse_attestation
from evidence_collector.parsers.croissant import parse_croissant
from evidence_collector.parsers.exception import parse_exception
from evidence_collector.parsers.garak import parse_garak
from evidence_collector.parsers.intoto_provenance import parse_provenance, parse_provenances
from evidence_collector.parsers.intoto_statement import (
    parse_intoto_statement,
    parse_intoto_statements,
)
from evidence_collector.parsers.intoto_vsa import parse_vsa
from evidence_collector.parsers.junit import parse_junit
from evidence_collector.parsers.lm_eval import parse_lm_eval
from evidence_collector.parsers.model_card import parse_model_card
from evidence_collector.parsers.osv import parse_osv
from evidence_collector.parsers.registry_attestation import parse_registry_attestation
from evidence_collector.parsers.release_attestation import (
    parse_release_attestation,
    parse_release_attestations,
)
from evidence_collector.parsers.sarif import parse_sarif, parse_sarifs
from evidence_collector.parsers.sbom import parse_sbom
from evidence_collector.parsers.trivy_json import parse_trivy_json
from evidence_collector.parsers.zap import parse_zap

__all__ = [
    "parse_attestation",
    "parse_croissant",
    "parse_exception",
    "parse_garak",
    "parse_intoto_statement",
    "parse_intoto_statements",
    "parse_junit",
    "parse_lm_eval",
    "parse_model_card",
    "parse_osv",
    "parse_provenance",
    "parse_provenances",
    "parse_registry_attestation",
    "parse_release_attestation",
    "parse_release_attestations",
    "parse_sarif",
    "parse_sarifs",
    "parse_sbom",
    "parse_trivy_json",
    "parse_vsa",
    "parse_zap",
]
