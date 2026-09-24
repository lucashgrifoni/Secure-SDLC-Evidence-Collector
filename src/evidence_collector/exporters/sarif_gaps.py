"""SARIF 2.1.0 exporter for unmet controls.

Turns every control the bundle evaluated as ``missing`` or ``partial``
into one SARIF result, so a code scanning dashboard lists release
evidence gaps next to the findings of the scanners that produced the
evidence. ``met``, ``waived`` and ``not_applicable`` controls are left
out: a waiver already carries its own owner and expiry in the bundle.

A control gap has no line of source code, so every result points at the
bundle file itself. ``partialFingerprints`` is keyed on the control id,
which lets a dashboard track the same gap across releases instead of
opening a new alert per run.

The document holds no timestamps and every list is sorted, so the same
bundle always yields the same bytes. This module ships zero IO; the CLI
command at ``cli/commands/sarif.py`` reads the bundle and writes the file.
"""

from __future__ import annotations

from typing import Any

from evidence_collector import __version__
from evidence_collector.domain.enums import ControlCriticality, ControlEvaluationStatus
from evidence_collector.domain.models import ControlEvaluation, EvidenceBundle

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "secure-sdlc-evidence-collector"
TOOL_URI = "https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector"

_UNMET = {ControlEvaluationStatus.MISSING, ControlEvaluationStatus.PARTIAL}

_LEVEL = {
    ControlCriticality.CRITICAL: "error",
    ControlCriticality.HIGH: "error",
    ControlCriticality.MEDIUM: "warning",
    ControlCriticality.LOW: "note",
}

# GitHub code scanning reads `security-severity` (0.0-10.0) to rank a rule as
# critical (>= 9.0), high (>= 7.0), medium (>= 4.0) or low.
_SECURITY_SEVERITY = {
    ControlCriticality.CRITICAL: "9.0",
    ControlCriticality.HIGH: "7.0",
    ControlCriticality.MEDIUM: "5.0",
    ControlCriticality.LOW: "3.0",
}


def build_gap_sarif(bundle: EvidenceBundle, *, artifact_uri: str = "bundle.json") -> dict[str, Any]:
    """Return a SARIF 2.1.0 log with one result per unmet control in ``bundle``."""
    unmet = sorted(
        (e for e in bundle.control_evaluations if e.evaluation_status in _UNMET),
        key=lambda e: e.control_id,
    )
    remediation = _remediation_by_control(bundle)
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": __version__,
                        "informationUri": TOOL_URI,
                        "rules": [_rule(e, remediation.get(e.control_id)) for e in unmet],
                    }
                },
                "results": [_result(e, artifact_uri) for e in unmet],
            }
        ],
    }


def _remediation_by_control(bundle: EvidenceBundle) -> dict[str, str]:
    """First remediation hint the bundle's gaps give for each control."""
    hints: dict[str, str] = {}
    for gap in bundle.gaps:
        if gap.remediation and gap.control_id not in hints:
            hints[gap.control_id] = gap.remediation
    return hints


def _rule(evaluation: ControlEvaluation, remediation: str | None) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "id": evaluation.control_id,
        "shortDescription": {"text": evaluation.control_name},
        "defaultConfiguration": {"level": _LEVEL[evaluation.criticality]},
        "properties": {
            "tags": ["security", "release-evidence", evaluation.framework.value],
            "security-severity": _SECURITY_SEVERITY[evaluation.criticality],
            "criticality": evaluation.criticality.value,
        },
    }
    if remediation:
        rule["help"] = {"text": remediation}
    return rule


def _result(evaluation: ControlEvaluation, artifact_uri: str) -> dict[str, Any]:
    missing = ", ".join(sorted(t.value for t in evaluation.missing_required_evidence_types))
    text = (
        f"{evaluation.control_id} ({evaluation.control_name}) is "
        f"{evaluation.evaluation_status.value}."
    )
    if missing:
        text += f" Missing required evidence: {missing}."
    return {
        "ruleId": evaluation.control_id,
        "level": _LEVEL[evaluation.criticality],
        "message": {"text": text},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": artifact_uri},
                    "region": {"startLine": 1},
                }
            }
        ],
        "partialFingerprints": {"controlId/v1": evaluation.control_id},
    }
