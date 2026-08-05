"""garak prompt-injection report parser.

garak (https://github.com/leondz/garak) is the canonical OSS harness
for probing LLMs for prompt-injection / jailbreak / refusal bypass
weaknesses. It emits a JSON-Lines report where each line is one of
several entry kinds (``init``, ``start_run``, ``probespec``,
``attempt``, ``digest``, ``end_run``). The relevant signal for
evidence collection is:

* ``init`` — model under test, garak version
* ``probespec`` — which probes were planned
* ``digest`` — per-probe hit summary (probe name, attempts, hits)
* ``attempt`` — per-attempt verdicts (used only as a fallback when no
  digest line is present, e.g. partial runs)

We surface a compact ``ParsedGarak`` with per-probe hit counts and a
severity rollup that downstream controls can evaluate. The parser
stays severity-aware but does not invent severities for unrecognised
probes: anything without an explicit hit signal collapses to
``info``.

Spec references
* garak report format: https://reference.garak.ai/en/latest/reporting.html
* OWASP LLM Top 10 (LLM01 prompt injection):
  https://owasp.org/www-project-top-10-for-large-language-model-applications/
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from evidence_collector.parsers._common import (
    ParsedArtifact,
    ParseError,
    describe,
    ensure_file,
)


@dataclass
class GarakProbeResult:
    """One probe's outcome inside a garak run."""

    probe: str
    attempts: int = 0
    hits: int = 0


@dataclass
class ParsedGarak:
    artifact: ParsedArtifact
    tool_name: str = "garak"
    tool_version: str | None = None
    model_id: str | None = None
    model_provider: str | None = None
    findings_count: dict[str, int] = field(default_factory=dict)
    total_attempts: int = 0
    total_hits: int = 0
    probes: list[GarakProbeResult] = field(default_factory=list)
    raw: list[dict[str, Any]] = field(default_factory=list)


def _empty_findings() -> dict[str, int]:
    # garak does not emit a per-attempt CVSS-style severity, so we
    # bucket findings by whether the probe scored any hits at all.
    # ``high`` = at least one successful prompt injection; ``medium`` =
    # probe ran but borderline (hits < attempts) — collapsed into
    # ``high`` here because any hit is a real failure; ``info`` = probe
    # ran with zero hits (passive signal).
    return {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    """Read a garak JSON-Lines report into a list of dicts.

    A truly empty file raises ``ParseError``; lines that are not JSON
    objects (blanks, comments, garbled records) are skipped silently
    so a partially-corrupted log still surfaces the valid records.
    """
    records: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(entry, dict):
                    records.append(entry)
    except OSError as exc:
        raise ParseError(f"Could not read garak report {path}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise ParseError(f"Invalid text encoding in garak report {path}: {exc}") from exc
    if not records:
        raise ParseError(f"garak report {path} has no JSON records")
    return records


def _extract_init(records: list[dict[str, Any]]) -> tuple[str | None, str | None, str | None]:
    """Return (garak_version, model_id, model_provider) from an ``init`` record."""
    for entry in records:
        if entry.get("entry_type") == "init":
            version = entry.get("garak_version")
            model_id = entry.get("model_name") or entry.get("model")
            model_provider = entry.get("model_type")
            return (
                str(version) if version else None,
                str(model_id) if model_id else None,
                str(model_provider) if model_provider else None,
            )
    return (None, None, None)


def _aggregate_probes(records: list[dict[str, Any]]) -> list[GarakProbeResult]:
    """Aggregate ``digest`` and ``attempt`` records into per-probe results.

    Digest lines are authoritative when present (full runs). Attempt
    lines are used as a fallback so partial runs still surface signal.
    """
    by_probe: dict[str, GarakProbeResult] = {}

    # Preferred: digest lines.
    for entry in records:
        if entry.get("entry_type") != "digest":
            continue
        probe = entry.get("probe")
        if not isinstance(probe, str):
            continue
        attempts_raw = entry.get("attempts", 0)
        hits_raw = entry.get("hits", 0)
        attempts = int(attempts_raw) if isinstance(attempts_raw, int | float) else 0
        hits = int(hits_raw) if isinstance(hits_raw, int | float) else 0
        by_probe[probe] = GarakProbeResult(probe=probe, attempts=attempts, hits=hits)

    if by_probe:
        return sorted(by_probe.values(), key=lambda p: p.probe)

    # Fallback: per-attempt rollup.
    for entry in records:
        if entry.get("entry_type") != "attempt":
            continue
        probe = entry.get("probe_classname") or entry.get("probe")
        if not isinstance(probe, str):
            continue
        result = by_probe.setdefault(probe, GarakProbeResult(probe=probe))
        result.attempts += 1
        # garak marks a hit when ``passed`` is False (the probe
        # succeeded in eliciting the unsafe behaviour).
        if entry.get("passed") is False:
            result.hits += 1

    return sorted(by_probe.values(), key=lambda p: p.probe)


def parse_garak(path: str | Path) -> ParsedGarak:
    resolved = ensure_file(path)
    records = _load_jsonl(resolved)

    tool_version, model_id, model_provider = _extract_init(records)
    probes = _aggregate_probes(records)

    findings = _empty_findings()
    total_attempts = 0
    total_hits = 0
    for probe in probes:
        total_attempts += probe.attempts
        total_hits += probe.hits
        if probe.hits > 0:
            findings["high"] += 1
        else:
            findings["info"] += 1

    artifact = describe(resolved, content_type="application/json")
    return ParsedGarak(
        artifact=artifact,
        tool_name="garak",
        tool_version=tool_version,
        model_id=model_id,
        model_provider=model_provider,
        findings_count=findings,
        total_attempts=total_attempts,
        total_hits=total_hits,
        probes=probes,
        raw=records,
    )
