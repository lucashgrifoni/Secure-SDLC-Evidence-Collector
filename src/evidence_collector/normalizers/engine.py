"""Normalizers: parsed artifact → NormalizedEvidence.

Each normalizer takes one parser output (or GitHub collector payload) plus a
`ReleaseContext` and produces a canonical `NormalizedEvidence`. Normalizers
know about release context, but remain free of IO concerns.

Heuristics for evidence classification:

- SARIF produced by Semgrep, SonarQube, Snyk Code, or CodeQL is classified
  as `sast_scan`. SARIF produced by Gitleaks, Trufflehog, or similar tools
  is classified as `secrets_scan`. SARIF produced by Trivy/Grype/Snyk
  (dependencies) is classified as `sca_scan`. When the tool is unknown, the
  caller can override via `evidence_type_override`.
"""

from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from evidence_collector.domain.enums import (
    ConfidenceLevel,
    EvidenceStatus,
    EvidenceType,
    SubjectType,
)
from evidence_collector.domain.models import (
    EvidenceClassification,
    EvidenceSource,
    NormalizedEvidence,
    RawEvidenceRef,
    ReleaseContext,
)
from evidence_collector.parsers._common import ParsedArtifact
from evidence_collector.parsers.attestation import ParsedAttestation
from evidence_collector.parsers.croissant import ParsedCroissant
from evidence_collector.parsers.garak import ParsedGarak
from evidence_collector.parsers.intoto_provenance import ParsedProvenance
from evidence_collector.parsers.intoto_statement import (
    SVR_PREDICATE_TYPE,
    TEST_RESULT_PREDICATE_TYPE,
    VULNS_PREDICATE_TYPE,
    ParsedIntotoStatement,
)
from evidence_collector.parsers.intoto_vsa import ParsedVsa
from evidence_collector.parsers.junit import ParsedJUnit
from evidence_collector.parsers.lm_eval import ParsedLmEval
from evidence_collector.parsers.model_card import ParsedModelCard
from evidence_collector.parsers.osv import ParsedOsv
from evidence_collector.parsers.registry_attestation import ParsedRegistryAttestation
from evidence_collector.parsers.release_attestation import ParsedReleaseAttestation
from evidence_collector.parsers.sarif import ParsedSarif
from evidence_collector.parsers.sbom import ParsedSbom
from evidence_collector.parsers.trivy_json import ParsedTrivyJson
from evidence_collector.parsers.zap import ParsedZap
from evidence_collector.paths import relative_to_root

_SAST_TOOLS: frozenset[str] = frozenset(
    {
        "semgrep",
        "sonarqube",
        "sonar",
        "snyk-code",
        "codeql",
        "bandit",
        "brakeman",
        "checkov",
        "eslint",
    }
)
_SCA_TOOLS: frozenset[str] = frozenset(
    {
        "trivy",
        "grype",
        "snyk",
        "dependency-check",
        "owasp-dependency-check",
        "osv-scanner",
        "pip-audit",
        "pip_audit",
        "safety",
        "npm-audit",
        "yarn-audit",
        "retire.js",
        "retire",
    }
)
_SECRETS_TOOLS: frozenset[str] = frozenset(
    {
        "gitleaks",
        "trufflehog",
        "detect-secrets",
        "noseyparker",
    }
)


def _new_evidence_id(prefix: str, *parts: str) -> str:
    """Return a deterministic evidence id built from `prefix` + a digest of
    the tuple of string parts. Any caller that passes the same parts gets
    the same id, which makes the whole bundle reproducible across runs on
    identical inputs (see `docs/limitations.md §8`).
    """
    digest = hashlib.sha256("||".join(parts).encode("utf-8")).hexdigest()[:12]
    return f"{prefix}-{digest}"


def _strip_root(value: str, root: str | None) -> str:
    """Rewrite a scanner-reported location against the artifact root.

    Scanners report where *they* looked, which on a filesystem scan is a local
    *absolute* path. Only absolute values are considered, and that restriction
    is the whole correctness argument.

    Passing relative values through `relative_to_root` resolved them against
    the process working directory. Whenever that directory was inside the
    artifact root — running from `<repo>/services/api` with
    `--artifact-root <repo>` — a container-image reference matched and was
    rewritten: `acme/api:1.0` became `services\\api\\acme\\api:1.0`, and a
    Trivy target of `Java` became `services\\api\\Java`. That inserts the
    collector's own directory layout into fields that never held a path, and
    makes bundle content depend on where the command happened to be run from,
    which nothing else in this codebase does.

    Values that are not absolute paths under the root — image references,
    remote targets, package coordinates — come back **verbatim**, not
    round-tripped through `Path`: on Windows that alone would rewrite the
    separator in `acme/api:1.0`.

    Scanners also *decorate* the path rather than reporting it bare. Trivy
    composes an OS-package target as `<path> (<family> <version>)`; a CycloneDX
    subject arrives as `<name>@<version>`, and the name is the scanned
    directory. Requiring the whole string to be a path meant one trailing
    decoration made the strip fail and the value shipped verbatim — a bundle
    carrying `artifact_name: "."` beside a `targets[0]` with the full local
    path, both derived from the same string. So a leading path *prefix* is
    recognised too, and only the prefix is rewritten.

    That is deliberately not a list of decoration patterns. The prefix must
    still be an absolute path under the root, which is what keeps
    `acme/api:1.0 (debian 12)` and `pkg:pypi/app@1.0` untouched, and it does
    not need to be extended each time a scanner invents a new suffix.

    The prefix must also end where the root's last segment ends. `/tmp/repo`
    is a string prefix of `/tmp/repo-old/image`, a sibling directory, and
    stripping it produced `.-old/image`. A character that could continue a
    directory name disqualifies the match; a separator, a space or `@` does
    not.
    """
    if not root or not value:
        return value
    stripped = _strip_absolute(value, root)
    if stripped is not None:
        return stripped
    for base in _root_spellings(root):
        if os.path.normcase(value).startswith(os.path.normcase(base)):
            head, tail = value[: len(base)], value[len(base) :]
            if tail and _continues_a_name(tail[0]):
                continue
            inner = _strip_absolute(head, root)
            if inner is not None:
                return inner + tail
    return value


def _continues_a_name(char: str) -> bool:
    """Whether `char`, right after the root, would extend its last segment."""
    return char.isalnum() or char in "-_.+~"


def _root_spellings(root: str) -> list[str]:
    """The forms the artifact root can appear in inside a scanner's own string."""
    base = Path(root).expanduser()
    spellings = [str(base)]
    try:
        resolved = str(base.resolve())
    except OSError:  # pragma: no cover - depends on filesystem state
        return spellings
    if resolved not in spellings:
        spellings.append(resolved)
    # Longest first, so a root that is a prefix of its own resolved form does
    # not strip the shorter one and leave the rest of the path behind.
    return sorted(spellings, key=len, reverse=True)


def _strip_absolute(value: str, root: str) -> str | None:
    """Return `value` relative to `root`, or None if it is not a path under it."""
    candidate = Path(value)
    if not candidate.is_absolute():
        return None
    relative = relative_to_root(candidate, root)
    if relative == candidate:
        return None
    return str(relative)


def _raw_ref(artifact: ParsedArtifact, root: str | None = None) -> RawEvidenceRef:
    return RawEvidenceRef(
        artifact_path=str(relative_to_root(artifact.path, root)),
        integrity_hash=artifact.integrity_hash,
        content_type=artifact.content_type,
        size_bytes=artifact.size_bytes,
    )


def _classify_sarif(tool_name: str, override: EvidenceType | None) -> EvidenceType:
    """Classify a SARIF run by driver name.

    See :func:`_classify_sarif_with_provenance` when the caller also
    needs the classification provenance (driver match vs fallback vs
    explicit override).
    """
    return _classify_sarif_with_provenance(tool_name, override)[0]


def _classify_sarif_with_provenance(
    tool_name: str, override: EvidenceType | None
) -> tuple[EvidenceType, EvidenceClassification]:
    """Classify a SARIF run and report the provenance of the decision.

    Returns ``(evidence_type, classification)`` so callers can populate
    the first-class ``classification`` field on the resulting
    ``NormalizedEvidence``. The classification taxonomy is:

    * ``manual_override`` — the caller passed ``evidence_type_override``
      explicitly, MEDIUM confidence (human intent, not a machine match).
    * ``driver_match`` — the driver name matched one of the curated
      tool token sets, HIGH confidence.
    * ``fallback_sast`` — no token matched and the heuristic defaulted
      to ``sast_scan``, LOW confidence. See ``docs/limitations.md §2``.
    """
    if override is not None:
        return override, EvidenceClassification(
            confidence=ConfidenceLevel.MEDIUM,
            reason="manual_override",
            driver_name=tool_name,
        )
    # Normalize punctuation / whitespace so "Snyk Code", "snyk-code",
    # "snykcode", and "snyk_code" all match the same token. Without
    # this, a SAST driver whose name happens to use a different
    # separator falls through to the SCA bucket (false-positive risk
    # tracked in docs/limitations.md §2).
    lowered = tool_name.lower()
    normalized = lowered.replace("-", " ").replace("_", " ").replace("/", " ")
    compact = normalized.replace(" ", "")

    def _matches(tokens: frozenset[str]) -> bool:
        for token in tokens:
            token_norm = token.replace("-", " ").replace("_", " ")
            token_compact = token_norm.replace(" ", "")
            if token_norm in normalized or token_compact in compact or token in lowered:
                return True
        return False

    # Order matters: check SAST first so composite tools (e.g., "Snyk Code"
    # where both "snyk" and "snyk-code" can match) are labelled as SAST,
    # which is more specific than SCA.
    if _matches(_SAST_TOOLS):
        return EvidenceType.SAST_SCAN, EvidenceClassification(
            confidence=ConfidenceLevel.HIGH,
            reason="driver_match",
            driver_name=tool_name,
        )
    if _matches(_SECRETS_TOOLS):
        return EvidenceType.SECRETS_SCAN, EvidenceClassification(
            confidence=ConfidenceLevel.HIGH,
            reason="driver_match",
            driver_name=tool_name,
        )
    if _matches(_SCA_TOOLS):
        return EvidenceType.SCA_SCAN, EvidenceClassification(
            confidence=ConfidenceLevel.HIGH,
            reason="driver_match",
            driver_name=tool_name,
        )
    return EvidenceType.SAST_SCAN, EvidenceClassification(
        confidence=ConfidenceLevel.LOW,
        reason="fallback_sast",
        driver_name=tool_name,
    )


def _sarif_status(findings_count: dict[str, int]) -> EvidenceStatus:
    blocking = findings_count.get("critical", 0) + findings_count.get("high", 0)
    if blocking > 0:
        return EvidenceStatus.FAILED
    return EvidenceStatus.PASSED


def normalize_sarif(
    parsed: ParsedSarif,
    release: ReleaseContext,
    *,
    evidence_type_override: EvidenceType | None = None,
    artifact_root: str | None = None,
) -> NormalizedEvidence:
    evidence_type, classification = _classify_sarif_with_provenance(
        parsed.tool_name, evidence_type_override
    )
    status = _sarif_status(parsed.findings_count)
    prefix = {
        EvidenceType.SAST_SCAN: "sast",
        EvidenceType.SCA_SCAN: "sca",
        EvidenceType.SECRETS_SCAN: "secrets",
    }.get(evidence_type, "scan")
    # When the classification fell through to the SAST default we cannot
    # claim HIGH overall confidence for the record either: the evidence
    # type itself is a heuristic guess. Reflect that on the existing
    # ``confidence`` field so consumers that ignore ``classification``
    # still see the weakened signal.
    overall_confidence = (
        ConfidenceLevel.LOW if classification.reason == "fallback_sast" else ConfidenceLevel.HIGH
    )
    return NormalizedEvidence(
        evidence_id=_new_evidence_id(
            prefix,
            parsed.tool_name,
            parsed.artifact.integrity_hash,
            release.commit_sha,
            # Only from the second run onward, so a single-run SARIF — every
            # fixture and the overwhelming majority of real files — keeps the
            # id it had before merged files were split per run, and the
            # determinism snapshots do not move.
            *([str(parsed.run_index)] if parsed.run_index else []),
        ),
        evidence_type=evidence_type,
        source=EvidenceSource(name=parsed.tool_name, kind="sarif", version=parsed.tool_version),
        producer=parsed.tool_name,
        subject_type=SubjectType.COMMIT,
        subject_ref=release.commit_sha,
        status=status,
        confidence=overall_confidence,
        classification=classification,
        release_id=release.release_id,
        commit_sha=release.commit_sha,
        generated_at=None,
        raw=_raw_ref(parsed.artifact, artifact_root),
        findings_count=dict(parsed.findings_count),
        cve_ids=list(parsed.cve_ids),
        summary=(
            f"{parsed.tool_name} reported {parsed.total_findings} findings "
            f"(high/critical={parsed.findings_count.get('critical', 0) + parsed.findings_count.get('high', 0)})"
        ),
    )


def normalize_sbom(
    parsed: ParsedSbom,
    release: ReleaseContext,
    *,
    artifact_root: str | None = None,
) -> NormalizedEvidence:
    # `subject_ref` is the BOM's own `metadata.component`, and when the SBOM was
    # generated by scanning a directory that name IS the absolute path. It
    # reached bundle.json, report.md and summary.html untouched while
    # `raw.artifact_path` beside it was stripped correctly — the same flag, the
    # same run, one field honouring it and one not.
    subject_ref = _strip_root(
        parsed.subject_ref or release.artifact_digest or release.release_id, artifact_root
    )
    metadata: dict[str, Any] = {}
    if parsed.serial_number:
        metadata["serial_number"] = parsed.serial_number
    if parsed.lifecycle_phases:
        metadata["lifecycle_phases"] = list(parsed.lifecycle_phases)
    if parsed.vulnerability_analyses:
        # Carry the CycloneDX inline analyses through as plain dicts so the
        # bundle stays JSON-serialisable and the VEX exporter can consume
        # them without re-parsing the SBOM. Ordered by CVE id for byte
        # stability across runs on the same input.
        metadata["sbom_vex_analyses"] = [
            {
                "cve_id": a.cve_id,
                "state": a.state,
                "justification": a.justification,
                "responses": list(a.responses),
                "detail": a.detail,
            }
            for a in sorted(parsed.vulnerability_analyses, key=lambda x: x.cve_id)
        ]
    if parsed.cisa_minimum_elements:
        # Presence check against CISA's 2025 Minimum Elements for an SBOM.
        # Turns "an SBOM exists" into "the SBOM is shaped like a conformant
        # one"; the booleans are content-derived so the bundle stays
        # byte-stable across runs on the same input.
        metadata["cisa_2025_minimum_elements"] = dict(parsed.cisa_minimum_elements)
        metadata["cisa_2025_conformant"] = all(parsed.cisa_minimum_elements.values())
    # CycloneDX 1.6/1.7 evidence-bearing objects, surfaced only when present so
    # a classic dependency SBOM stays byte-identical to pre-1.7 bundles.
    if parsed.ml_model_count or parsed.dataset_count:
        metadata["ml_bom"] = {
            "model_count": parsed.ml_model_count,
            "dataset_count": parsed.dataset_count,
        }
    if parsed.crypto_asset_count:
        metadata["cbom"] = {"cryptographic_asset_count": parsed.crypto_asset_count}
    if parsed.attestation_count:
        metadata["cyclonedx_attestation_count"] = parsed.attestation_count
    # SPDX 3.0 AI / Dataset / Security profile element counts, conditional so
    # an SBOM without those profiles is unaffected.
    if (
        parsed.spdx_ai_package_count
        or parsed.spdx_dataset_count
        or parsed.spdx_security_assessment_count
    ):
        metadata["spdx_profiles"] = {
            "ai_package_count": parsed.spdx_ai_package_count,
            "dataset_count": parsed.spdx_dataset_count,
            "security_assessment_count": parsed.spdx_security_assessment_count,
        }
    return NormalizedEvidence(
        evidence_id=_new_evidence_id(
            "sbom", parsed.artifact.integrity_hash, subject_ref, release.release_id
        ),
        evidence_type=EvidenceType.SBOM,
        source=EvidenceSource(name=parsed.format, kind="sbom", version=parsed.spec_version),
        producer=parsed.format,
        subject_type=SubjectType.ARTIFACT,
        subject_ref=subject_ref,
        status=EvidenceStatus.GENERATED,
        confidence=ConfidenceLevel.HIGH,
        release_id=release.release_id,
        commit_sha=release.commit_sha,
        generated_at=None,
        raw=_raw_ref(parsed.artifact, artifact_root),
        findings_count={"components": parsed.component_count},
        cve_ids=list(parsed.cve_ids),
        summary=(
            f"{parsed.format.upper()} SBOM with {parsed.component_count} components "
            f"(spec {parsed.spec_version})"
        ),
        metadata=metadata,
    )


def normalize_osv(
    parsed: ParsedOsv,
    release: ReleaseContext,
    *,
    artifact_root: str | None = None,
) -> NormalizedEvidence:
    """Build an ``sca_scan`` evidence from an OSV / OSV-Scanner report.

    OSV is the canonical OSS dependency-vulnerability format. We map it
    to the existing ``sca_scan`` evidence type so it flows through the
    same EPSS/KEV enrichment lane as Trivy/Grype/Snyk findings. The
    ecosystem list is preserved in ``metadata.ecosystems`` so consumers
    can group dependency findings per package manager without re-reading
    the raw report.
    """
    blocking = parsed.findings_count.get("critical", 0) + parsed.findings_count.get("high", 0)
    status = EvidenceStatus.FAILED if blocking > 0 else EvidenceStatus.PASSED
    metadata: dict[str, Any] = {}
    if parsed.ecosystems:
        metadata["ecosystems"] = list(parsed.ecosystems)
    if parsed.package_count:
        metadata["affected_package_count"] = parsed.package_count
    return NormalizedEvidence(
        evidence_id=_new_evidence_id(
            "osv", parsed.tool_name, parsed.artifact.integrity_hash, release.release_id
        ),
        evidence_type=EvidenceType.SCA_SCAN,
        source=EvidenceSource(name=parsed.tool_name, kind="sca", version=parsed.tool_version),
        producer=parsed.tool_name,
        subject_type=SubjectType.ARTIFACT,
        subject_ref=release.artifact_digest or release.release_id,
        status=status,
        confidence=ConfidenceLevel.HIGH,
        classification=EvidenceClassification(
            confidence=ConfidenceLevel.HIGH,
            reason="driver_match",
            driver_name=parsed.tool_name,
        ),
        release_id=release.release_id,
        commit_sha=release.commit_sha,
        generated_at=None,
        raw=_raw_ref(parsed.artifact, artifact_root),
        findings_count=dict(parsed.findings_count),
        cve_ids=list(parsed.cve_ids),
        summary=(
            f"{parsed.tool_name} reported {parsed.total_findings} OSV "
            f"vulnerabilities across {len(parsed.ecosystems)} ecosystem(s)"
        ),
        metadata=metadata,
    )


def normalize_provenance(
    parsed: ParsedProvenance,
    release: ReleaseContext,
    *,
    artifact_root: str | None = None,
) -> NormalizedEvidence:
    """Build an ``artifact_attestation`` evidence from SLSA build provenance.

    Records *how* an artifact was built (builder identity, build type, and the
    in-toto/DSSE/Sigstore envelope it travelled in) without verifying the
    signature. Provenance is descriptive, not pass/fail, so the status is
    GENERATED (the same convention as SBOM evidence).
    """
    subject_ref = (parsed.subject_name or parsed.source_repository or parsed.builder_id)[:500]
    producer = parsed.builder_id[:100]
    metadata: dict[str, Any] = {
        "predicate_type": parsed.predicate_type,
        "builder_id": parsed.builder_id,
        "build_type": parsed.build_type,
        "envelope": parsed.envelope,
    }
    if parsed.invocation_id:
        metadata["invocation_id"] = parsed.invocation_id
    if parsed.source_repository:
        metadata["source_repository"] = parsed.source_repository
    return NormalizedEvidence(
        evidence_id=_new_evidence_id(
            "prov", parsed.artifact.integrity_hash, subject_ref, release.release_id
        ),
        evidence_type=EvidenceType.ARTIFACT_ATTESTATION,
        source=EvidenceSource(name=producer, kind="slsa-provenance"),
        producer=producer,
        subject_type=SubjectType.ARTIFACT,
        subject_ref=subject_ref,
        status=EvidenceStatus.GENERATED,
        confidence=ConfidenceLevel.HIGH,
        release_id=release.release_id,
        commit_sha=release.commit_sha,
        generated_at=None,
        raw=_raw_ref(parsed.artifact, artifact_root),
        findings_count={},
        summary=(
            f"SLSA provenance ({parsed.predicate_type.rsplit('/', 1)[-1]}) "
            f"built by {producer} via {parsed.build_type}"
        ),
        metadata=metadata,
    )


def normalize_vsa(
    parsed: ParsedVsa,
    release: ReleaseContext,
    *,
    artifact_root: str | None = None,
) -> NormalizedEvidence:
    """Build an ``artifact_attestation`` evidence from a SLSA VSA.

    A Verification Summary Attestation records that a verifier evaluated an
    artifact against a policy and the SLSA levels it met. We map the stated
    ``verificationResult`` to the evidence status (PASSED/FAILED) and carry
    the verifier, levels, and policy reference in ``metadata`` so reviewers
    can see *who* verified *what* without re-reading the raw attestation.
    The collector records the stated result; it does not verify the VSA's
    signature (see ``docs/limitations.md``).
    """
    if parsed.verification_result == "PASSED":
        status = EvidenceStatus.PASSED
    elif parsed.verification_result == "FAILED":
        status = EvidenceStatus.FAILED
    else:
        status = EvidenceStatus.UNKNOWN
    # verifier_id and resource_uri are guaranteed present by parse_vsa, which
    # rejects VSAs missing required fields before they ever reach normalize.
    subject_ref = (parsed.subject_name or parsed.resource_uri)[:500]
    producer = parsed.verifier_id[:100]
    metadata: dict[str, Any] = {
        "verification_result": parsed.verification_result,
        "verifier_id": parsed.verifier_id,
        "verified_levels": list(parsed.verified_levels),
        "resource_uri": parsed.resource_uri,
    }
    # Optional since SLSA v1.2 — only recorded when the verifier stated it.
    if parsed.time_verified:
        metadata["time_verified"] = parsed.time_verified
    if parsed.slsa_version:
        metadata["slsa_version"] = parsed.slsa_version
    if parsed.policy_uri:
        metadata["policy_uri"] = parsed.policy_uri
    if parsed.input_attestation_count:
        metadata["input_attestation_count"] = parsed.input_attestation_count
    # SLSA v1.2 Source Track: surface source semantics so a source VSA is
    # distinguishable from a build VSA without re-reading the raw statement.
    if parsed.source_levels:
        metadata["source_levels"] = list(parsed.source_levels)
    if parsed.source_refs:
        metadata["source_refs"] = list(parsed.source_refs)
    return NormalizedEvidence(
        evidence_id=_new_evidence_id(
            "vsa", parsed.artifact.integrity_hash, subject_ref, release.release_id
        ),
        evidence_type=EvidenceType.ARTIFACT_ATTESTATION,
        source=EvidenceSource(name=producer, kind="slsa-vsa", version=parsed.slsa_version),
        producer=producer,
        subject_type=SubjectType.ARTIFACT,
        subject_ref=subject_ref,
        status=status,
        confidence=ConfidenceLevel.HIGH,
        release_id=release.release_id,
        commit_sha=release.commit_sha,
        generated_at=None,
        raw=_raw_ref(parsed.artifact, artifact_root),
        findings_count={},
        summary=(
            f"SLSA VSA from {producer}: {parsed.verification_result}; "
            f"levels={', '.join(parsed.verified_levels)}"
        ),
        metadata=metadata,
    )


def normalize_release_attestation(
    parsed: ParsedReleaseAttestation,
    release: ReleaseContext,
    *,
    artifact_root: str | None = None,
) -> NormalizedEvidence:
    """Build an ``artifact_attestation`` evidence from an in-toto release
    attestation.

    Records *what was released*: the package URL, the stable package
    identifier when stated, and every asset the attestation binds to a digest.
    A release attestation asserts existence and binding rather than a verdict,
    so the status is GENERATED (the same convention as SBOM and provenance).

    ``producer`` is the attestation *format*, not an organization: the release
    predicate states no issuer, and the only place an identity appears is the
    Sigstore verification material — reading that as authoritative would be
    signature verification, which is out of scope (see ``docs/limitations.md``).
    Recording the format keeps the evidence honest about what was actually read.
    """
    subject_ref = (parsed.subject_name or parsed.purl)[:500]
    producer = "in-toto-release-attestation"
    metadata: dict[str, Any] = {
        "predicate_type": parsed.predicate_type,
        "purl": parsed.purl,
        "envelope": parsed.envelope,
        "asset_count": len(parsed.assets),
        "assets": [{"name": asset.name, "digests": dict(asset.digests)} for asset in parsed.assets],
    }
    # Optional in both predicate versions — only recorded when stated.
    if parsed.package_id:
        metadata["package_id"] = parsed.package_id
    return NormalizedEvidence(
        evidence_id=_new_evidence_id(
            "rel", parsed.artifact.integrity_hash, subject_ref, release.release_id
        ),
        evidence_type=EvidenceType.ARTIFACT_ATTESTATION,
        source=EvidenceSource(name=producer, kind="release-attestation"),
        producer=producer,
        subject_type=SubjectType.RELEASE,
        subject_ref=subject_ref,
        status=EvidenceStatus.GENERATED,
        confidence=ConfidenceLevel.HIGH,
        release_id=release.release_id,
        commit_sha=release.commit_sha,
        generated_at=None,
        raw=_raw_ref(parsed.artifact, artifact_root),
        findings_count={},
        summary=(
            f"Release attestation ({parsed.predicate_type.rsplit('/', 1)[-1]}) "
            f"for {parsed.purl} binding {len(parsed.assets)} asset(s)"
        ),
        metadata=metadata,
    )


_TRIVY_KIND_SHAPE: dict[str, tuple[EvidenceType, str]] = {
    "sca": (EvidenceType.SCA_SCAN, "sca"),
    "secrets": (EvidenceType.SECRETS_SCAN, "secrets"),
    "iac": (EvidenceType.IAC_SCAN, "iac"),
}


def normalize_trivy_json(
    parsed: ParsedTrivyJson,
    release: ReleaseContext,
    *,
    artifact_root: str | None = None,
) -> list[NormalizedEvidence]:
    """Build one evidence **per finding class** in a native Trivy report.

    This is the only normalizer that returns a list. A single Trivy run
    over a repository routinely produces dependency vulnerabilities,
    secret hits and IaC misconfigurations at once; the SARIF route
    collapses all of them into one evidence type, which makes a Terraform
    misconfiguration indistinguishable from a code vulnerability. Keeping
    them separate is the whole point of reading the native format.

    Each evidence gets its own deterministic id — derived from the report
    hash *and* the class — so re-running the same report is stable and the
    three do not collide.

    Status follows the convention the OSV normalizer set: FAILED when the
    class carries a critical or high finding, PASSED otherwise. An empty
    class produces no evidence at all rather than a vacuous PASSED, since
    "Trivy found no secrets" and "Trivy was not asked about secrets" are
    different claims and the report cannot tell them apart.
    """
    subject_ref = (
        parsed.repo_digest or parsed.image_id or release.artifact_digest or release.release_id
    )[:500]
    evidences: list[NormalizedEvidence] = []
    for group in parsed.groups:
        if group.total == 0:
            continue
        evidence_type, source_kind = _TRIVY_KIND_SHAPE[group.kind]
        blocking = group.findings_count.get("critical", 0) + group.findings_count.get("high", 0)
        metadata: dict[str, Any] = {
            "trivy_schema_version": parsed.schema_version,
            "result_class": group.kind,
        }
        # Trivy's `ArtifactName` and per-result `Target` are filesystem paths
        # when it scanned a directory, and they carried the full local path
        # into the bundle even when `--artifact-root` had correctly stripped
        # `raw.artifact_path` beside them. The flag promises the *bundle*
        # records repo-relative paths, so these are held to it too. A value
        # that is not a path under the root — an image reference like
        # `acme/api:1.0`, a remote target — is left exactly as Trivy wrote it.
        if parsed.artifact_name:
            metadata["artifact_name"] = _strip_root(parsed.artifact_name, artifact_root)
        if parsed.artifact_type:
            metadata["artifact_type"] = parsed.artifact_type
        if group.targets:
            metadata["targets"] = [_strip_root(target, artifact_root) for target in group.targets]
        evidences.append(
            NormalizedEvidence(
                evidence_id=_new_evidence_id(
                    "trivy", parsed.artifact.integrity_hash, group.kind, release.release_id
                ),
                evidence_type=evidence_type,
                source=EvidenceSource(name="trivy", kind=source_kind),
                producer="trivy",
                subject_type=SubjectType.ARTIFACT,
                subject_ref=subject_ref,
                status=EvidenceStatus.FAILED if blocking > 0 else EvidenceStatus.PASSED,
                confidence=ConfidenceLevel.HIGH,
                classification=EvidenceClassification(
                    confidence=ConfidenceLevel.HIGH,
                    reason="driver_match",
                    driver_name="trivy",
                ),
                release_id=release.release_id,
                commit_sha=release.commit_sha,
                generated_at=None,
                raw=_raw_ref(parsed.artifact, artifact_root),
                findings_count=dict(group.findings_count),
                # Only the dependency lane carries CVE ids; secret rule ids
                # and misconfiguration check ids are not CVEs and must not
                # be fed to EPSS/KEV enrichment as if they were.
                cve_ids=list(group.ids) if group.kind == "sca" else [],
                summary=(
                    f"trivy reported {group.total} {group.kind} finding(s) "
                    f"across {len(group.targets)} target(s)"
                ),
                metadata=metadata,
            )
        )
    return evidences


def normalize_registry_attestation(
    parsed: ParsedRegistryAttestation,
    release: ReleaseContext,
    *,
    artifact_root: str | None = None,
) -> NormalizedEvidence:
    """Build an ``artifact_attestation`` evidence from a registry attestation.

    Records the *envelope of publication*: which registry served the
    attestation, which kind of trusted publisher it names, and the
    predicate types the bundle carries. A package can hold flawless build
    provenance and still have been uploaded by the wrong identity — the
    registry's own record is the only thing that speaks to that.

    ``producer`` is the registry, because the registry is what asserts
    this. ``publisher_kind`` is carried verbatim in metadata as the open
    string PEP 740 defines it to be. Only the *names* of the publisher
    claims are recorded: their values are publisher-specific and can
    carry repository and workflow detail that does not belong in a bundle
    by default.

    Status is GENERATED — publication is a fact being recorded, not a
    verdict — and the signature is decoded, never verified.
    """
    predicate_types = sorted({statement.predicate_type for statement in parsed.statements})
    subject_name = next(
        (s.subject_name for s in parsed.statements if s.subject_name),
        None,
    )
    subject_ref = (subject_name or release.artifact_digest or release.release_id)[:500]
    metadata: dict[str, Any] = {
        "registry": parsed.registry,
        "predicate_types": predicate_types,
        "attestation_count": len(parsed.statements),
    }
    if parsed.publisher_kind:
        metadata["publisher_kind"] = parsed.publisher_kind
    if parsed.publisher_claim_keys:
        metadata["publisher_claim_keys"] = list(parsed.publisher_claim_keys)
    publisher = f" published by {parsed.publisher_kind}" if parsed.publisher_kind else ""
    return NormalizedEvidence(
        evidence_id=_new_evidence_id(
            "reg", parsed.artifact.integrity_hash, parsed.registry, release.release_id
        ),
        evidence_type=EvidenceType.ARTIFACT_ATTESTATION,
        source=EvidenceSource(name=parsed.registry, kind="registry-attestation"),
        producer=parsed.registry,
        subject_type=SubjectType.RELEASE,
        subject_ref=subject_ref,
        status=EvidenceStatus.GENERATED,
        confidence=ConfidenceLevel.HIGH,
        release_id=release.release_id,
        commit_sha=release.commit_sha,
        generated_at=None,
        raw=_raw_ref(parsed.artifact, artifact_root),
        findings_count={},
        summary=(
            f"{parsed.registry} registry attestation{publisher}: "
            f"{len(parsed.statements)} attestation(s) carrying "
            f"{len(predicate_types)} predicate type(s)"
        ),
        metadata=metadata,
    )


def _intoto_statement_shape(
    parsed: ParsedIntotoStatement,
) -> tuple[EvidenceType, EvidenceStatus, str, str, str]:
    """Return ``(evidence_type, status, source_kind, producer, summary)``.

    Recognized predicates get a real evidence type so they flow through
    the same lanes as natively-parsed evidence: a test-result becomes
    ``test_result``, a vulns scan becomes ``sca_scan`` and reaches the
    EPSS/KEV enrichment. An unknown predicate becomes a
    ``generic_attestation`` marked UNKNOWN — recorded and visible, with
    no verdict invented on its behalf.
    """
    if parsed.predicate_type == SVR_PREDICATE_TYPE:
        producer = (parsed.verifier_id or "in-toto-svr")[:100]
        return (
            EvidenceType.ARTIFACT_ATTESTATION,
            EvidenceStatus.GENERATED,
            "in-toto-svr",
            producer,
            f"SVR from {producer}: {len(parsed.properties)} verified property(ies)",
        )
    if parsed.predicate_type == TEST_RESULT_PREDICATE_TYPE:
        status = {
            "PASSED": EvidenceStatus.PASSED,
            "FAILED": EvidenceStatus.FAILED,
            # The test ran to completion but flagged warnings. Calling that
            # PASSED would hide the warning; calling it FAILED would block a
            # release the attestation never said was broken.
            "WARNED": EvidenceStatus.COMPLETED,
        }.get(parsed.test_result or "", EvidenceStatus.UNKNOWN)
        return (
            EvidenceType.TEST_RESULT,
            status,
            "in-toto-test-result",
            "in-toto-test-result",
            (
                f"in-toto test result {parsed.test_result or 'UNKNOWN'}: "
                f"{parsed.passed_tests} passed, {parsed.warned_tests} warned, "
                f"{parsed.failed_tests} failed"
            ),
        )
    if parsed.predicate_type == VULNS_PREDICATE_TYPE:
        blocking = parsed.findings_count.get("critical", 0) + parsed.findings_count.get("high", 0)
        producer = (parsed.scanner_uri or "in-toto-vulns")[:100]
        return (
            EvidenceType.SCA_SCAN,
            EvidenceStatus.FAILED if blocking > 0 else EvidenceStatus.PASSED,
            "in-toto-vulns",
            producer,
            f"{producer} reported {len(parsed.vuln_ids)} vulnerability(ies)",
        )
    return (
        EvidenceType.GENERIC_ATTESTATION,
        EvidenceStatus.UNKNOWN,
        "in-toto-statement",
        "in-toto-statement",
        f"in-toto Statement with unrecognized predicate {parsed.predicate_type}",
    )


def normalize_intoto_statement(
    parsed: ParsedIntotoStatement,
    release: ReleaseContext,
    *,
    artifact_root: str | None = None,
    index: int = 0,
) -> NormalizedEvidence:
    """Build evidence from any in-toto Statement without a dedicated parser.

    Recognized predicates (SVR, test-result, vulns) are mapped to their
    natural evidence type. Anything else is preserved as a
    ``generic_attestation`` rather than dropped — the collector records
    that an attestation was supplied and what it claimed to be, and lets
    a human decide what it is worth.

    Confidence is MEDIUM, not HIGH: unlike the dedicated parsers, nothing
    here validated the predicate against its schema.
    """
    evidence_type, status, source_kind, producer, summary = _intoto_statement_shape(parsed)
    subject_ref = (parsed.subject_name or release.artifact_digest or release.release_id)[:500]
    metadata: dict[str, Any] = {
        "predicate_type": parsed.predicate_type,
        "envelope": parsed.envelope,
        "predicate_recognized": parsed.recognized,
    }
    if parsed.verifier_id:
        metadata["verifier_id"] = parsed.verifier_id
    if parsed.properties:
        metadata["properties"] = list(parsed.properties)
    if parsed.time_created:
        metadata["time_created"] = parsed.time_created
    if parsed.test_result:
        metadata["test_result"] = parsed.test_result
        metadata["passed_tests"] = parsed.passed_tests
        metadata["warned_tests"] = parsed.warned_tests
        metadata["failed_tests"] = parsed.failed_tests
    if parsed.test_url:
        metadata["test_url"] = parsed.test_url
    if parsed.scanner_uri:
        metadata["scanner_uri"] = parsed.scanner_uri
    if parsed.scanner_version:
        metadata["scanner_version"] = parsed.scanner_version
    # A JSONL can carry several Statements with the same predicate type, and
    # the file hash, the predicate and the release are then identical for all
    # of them. The position in the file tells them apart. It joins the id only
    # from the second Statement on, so a one-Statement file keeps the id it
    # always had.
    id_parts = [parsed.artifact.integrity_hash, parsed.predicate_type]
    if index:
        id_parts.append(str(index))
    return NormalizedEvidence(
        evidence_id=_new_evidence_id("stmt", *id_parts, release.release_id),
        evidence_type=evidence_type,
        source=EvidenceSource(name=producer, kind=source_kind),
        producer=producer,
        subject_type=SubjectType.ARTIFACT,
        subject_ref=subject_ref,
        status=status,
        confidence=ConfidenceLevel.MEDIUM,
        release_id=release.release_id,
        commit_sha=release.commit_sha,
        generated_at=None,
        raw=_raw_ref(parsed.artifact, artifact_root),
        findings_count=dict(parsed.findings_count),
        cve_ids=list(parsed.vuln_ids),
        summary=summary,
        metadata=metadata,
    )


def normalize_garak(
    parsed: ParsedGarak,
    release: ReleaseContext,
    *,
    artifact_root: str | None = None,
) -> NormalizedEvidence:
    """Build a ``prompt_injection_test_result`` evidence from a garak report.

    Any non-zero hit count fails the gate; a clean run passes. The
    per-probe rollup travels in ``metadata.probes`` so consumers can
    decide whether a single failing probe should block the release.
    """
    status = EvidenceStatus.FAILED if parsed.total_hits > 0 else EvidenceStatus.PASSED
    metadata: dict[str, Any] = {
        "probes": [
            {"probe": p.probe, "attempts": p.attempts, "hits": p.hits} for p in parsed.probes
        ],
        "total_attempts": parsed.total_attempts,
        "total_hits": parsed.total_hits,
    }
    if parsed.model_id:
        metadata["ai_model_id"] = parsed.model_id
    if parsed.model_provider:
        metadata["ai_model_provider"] = parsed.model_provider
    subject_ref = parsed.model_id or release.release_id
    return NormalizedEvidence(
        evidence_id=_new_evidence_id(
            "garak", parsed.artifact.integrity_hash, subject_ref, release.release_id
        ),
        evidence_type=EvidenceType.PROMPT_INJECTION_TEST_RESULT,
        source=EvidenceSource(name="garak", kind="ai-eval", version=parsed.tool_version),
        producer="garak",
        subject_type=SubjectType.AI_MODEL,
        subject_ref=subject_ref,
        status=status,
        confidence=ConfidenceLevel.HIGH,
        release_id=release.release_id,
        commit_sha=release.commit_sha,
        generated_at=None,
        raw=_raw_ref(parsed.artifact, artifact_root),
        findings_count=dict(parsed.findings_count),
        summary=(
            f"garak ran {parsed.total_attempts} prompt-injection attempts across "
            f"{len(parsed.probes)} probe(s); {parsed.total_hits} hit(s)"
        ),
        metadata=metadata,
    )


def normalize_lm_eval(
    parsed: ParsedLmEval,
    release: ReleaseContext,
    *,
    artifact_root: str | None = None,
) -> NormalizedEvidence:
    """Build an ``ai_safety_eval`` evidence from an lm-eval-harness report."""
    metadata: dict[str, Any] = {
        "tasks": [{"task": t.task, "metrics": dict(t.metrics)} for t in parsed.tasks],
        "total_tasks": parsed.total_tasks,
    }
    if parsed.model_id:
        metadata["ai_model_id"] = parsed.model_id
    subject_ref = parsed.model_id or release.release_id
    return NormalizedEvidence(
        evidence_id=_new_evidence_id(
            "lmeval", parsed.artifact.integrity_hash, subject_ref, release.release_id
        ),
        evidence_type=EvidenceType.AI_SAFETY_EVAL,
        source=EvidenceSource(name="lm-eval-harness", kind="ai-eval", version=parsed.tool_version),
        producer="lm-eval-harness",
        subject_type=SubjectType.AI_MODEL,
        subject_ref=subject_ref,
        status=EvidenceStatus.GENERATED,
        confidence=ConfidenceLevel.HIGH,
        release_id=release.release_id,
        commit_sha=release.commit_sha,
        generated_at=None,
        raw=_raw_ref(parsed.artifact, artifact_root),
        findings_count=dict(parsed.findings_count),
        summary=(
            f"lm-eval-harness covered {parsed.total_tasks} task(s) on "
            f"{parsed.model_id or 'unknown model'}"
        ),
        metadata=metadata,
    )


def normalize_model_card(
    parsed: ParsedModelCard,
    release: ReleaseContext,
    *,
    artifact_root: str | None = None,
) -> NormalizedEvidence:
    """Build a ``model_card`` evidence from an HF / Google MCT model card."""
    metadata: dict[str, Any] = {"shape": parsed.shape}
    if parsed.model_id:
        metadata["ai_model_id"] = parsed.model_id
    if parsed.license:
        metadata["license"] = parsed.license
    if parsed.datasets:
        metadata["datasets"] = list(parsed.datasets)
    if parsed.metrics:
        metadata["metrics"] = dict(parsed.metrics)
    if parsed.intended_use:
        metadata["intended_use"] = parsed.intended_use
    subject_ref = parsed.model_id or release.release_id
    return NormalizedEvidence(
        evidence_id=_new_evidence_id(
            "modelcard", parsed.artifact.integrity_hash, subject_ref, release.release_id
        ),
        evidence_type=EvidenceType.MODEL_CARD,
        source=EvidenceSource(name=parsed.shape, kind="model-card"),
        producer=parsed.shape,
        subject_type=SubjectType.AI_MODEL,
        subject_ref=subject_ref,
        status=EvidenceStatus.GENERATED,
        confidence=ConfidenceLevel.HIGH,
        release_id=release.release_id,
        commit_sha=release.commit_sha,
        generated_at=None,
        raw=_raw_ref(parsed.artifact, artifact_root),
        findings_count={},
        summary=(f"Model card ({parsed.shape}) for {parsed.model_id or 'unknown model'}"),
        metadata=metadata,
    )


def normalize_croissant(
    parsed: ParsedCroissant,
    release: ReleaseContext,
    *,
    artifact_root: str | None = None,
) -> NormalizedEvidence:
    """Build ``ai_training_data_lineage`` evidence from Croissant dataset metadata."""
    metadata: dict[str, Any] = {
        "croissant_version": parsed.croissant_version,
        "licenses": list(parsed.licenses),
        "provenance": list(parsed.provenance),
        "usage_policy": parsed.has_usage_policy,
        "record_sets": parsed.record_set_count,
        "distribution_files": parsed.distribution_count,
        "distribution_files_with_sha256": parsed.distribution_with_sha256,
    }
    if parsed.name:
        metadata["dataset_name"] = parsed.name
    if parsed.dataset_version:
        metadata["dataset_version"] = parsed.dataset_version
    if parsed.date_published:
        metadata["date_published"] = parsed.date_published
    subject_ref = parsed.url or parsed.name or release.release_id
    return NormalizedEvidence(
        evidence_id=_new_evidence_id(
            "croissant", parsed.artifact.integrity_hash, subject_ref, release.release_id
        ),
        evidence_type=EvidenceType.AI_TRAINING_DATA_LINEAGE,
        source=EvidenceSource(name="croissant", kind="dataset-metadata"),
        producer="croissant",
        subject_type=SubjectType.AI_DATASET,
        subject_ref=subject_ref,
        status=EvidenceStatus.GENERATED,
        # Name and license are what a lineage review starts from; without them
        # the file proves a dataset exists more than where it came from.
        confidence=(
            ConfidenceLevel.HIGH if parsed.name and parsed.licenses else ConfidenceLevel.MEDIUM
        ),
        release_id=release.release_id,
        commit_sha=release.commit_sha,
        generated_at=None,
        raw=_raw_ref(parsed.artifact, artifact_root),
        findings_count={},
        summary=(
            f"Croissant {parsed.croissant_version} metadata for dataset {parsed.name or 'unnamed'}"
        ),
        metadata=metadata,
    )


def normalize_zap(
    parsed: ParsedZap,
    release: ReleaseContext,
    *,
    artifact_root: str | None = None,
) -> NormalizedEvidence:
    """Build a `dast_scan` evidence from an OWASP ZAP JSON report."""
    blocking = parsed.findings_count.get("critical", 0) + parsed.findings_count.get("high", 0)
    status = EvidenceStatus.FAILED if blocking > 0 else EvidenceStatus.PASSED
    primary_target = parsed.target_urls[0] if parsed.target_urls else release.release_id
    return NormalizedEvidence(
        evidence_id=_new_evidence_id(
            "dast", parsed.tool_name, parsed.artifact.integrity_hash, primary_target
        ),
        evidence_type=EvidenceType.DAST_SCAN,
        source=EvidenceSource(name=parsed.tool_name, kind="dast", version=parsed.tool_version),
        producer=parsed.tool_name,
        subject_type=SubjectType.APPLICATION,
        subject_ref=primary_target,
        status=status,
        confidence=ConfidenceLevel.HIGH,
        release_id=release.release_id,
        commit_sha=release.commit_sha,
        generated_at=None,
        raw=_raw_ref(parsed.artifact, artifact_root),
        findings_count=dict(parsed.findings_count),
        summary=(
            f"{parsed.tool_name} DAST reported {parsed.total_findings} findings "
            f"across {len(parsed.target_urls) or 1} target(s); "
            f"high/critical={blocking}"
        ),
        metadata={"targets": parsed.target_urls},
    )


def normalize_junit(
    parsed: ParsedJUnit,
    release: ReleaseContext,
    *,
    artifact_root: str | None = None,
) -> NormalizedEvidence:
    failed = parsed.failures + parsed.errors
    executed = parsed.total - parsed.skipped
    if failed:
        status = EvidenceStatus.FAILED
    elif executed <= 0:
        # Zero failures out of zero tests is not a passing test run, and it
        # used to be recorded as `passed` at HIGH confidence — satisfying the
        # test-result control outright. The realistic trigger is not a hostile
        # file: a test job whose glob matched nothing, a build that failed
        # before the suite ran, a runner that wrote an empty report. All of
        # those produce a release certified as tested on the strength of a
        # suite that never executed, which is the failure mode this tool
        # exists to make impossible.
        #
        # `invalid` is the enum's documented value for "present but does not
        # demonstrate what it claims", and the control engine does not count
        # it as satisfying, so the control comes out MISSING with the file
        # still visible in the bundle for the auditor.
        status = EvidenceStatus.INVALID
    else:
        status = EvidenceStatus.PASSED
    return NormalizedEvidence(
        evidence_id=_new_evidence_id(
            "test",
            parsed.suite_name or "junit",
            parsed.artifact.integrity_hash,
            release.commit_sha,
        ),
        evidence_type=EvidenceType.TEST_RESULT,
        source=EvidenceSource(name="junit", kind="junit-xml"),
        producer=parsed.suite_name or "junit",
        subject_type=SubjectType.COMMIT,
        subject_ref=release.commit_sha,
        status=status,
        confidence=ConfidenceLevel.HIGH,
        release_id=release.release_id,
        commit_sha=release.commit_sha,
        generated_at=None,
        raw=_raw_ref(parsed.artifact, artifact_root),
        findings_count={
            "total": parsed.total,
            "failures": parsed.failures,
            "errors": parsed.errors,
            "skipped": parsed.skipped,
        },
        summary=(
            f"{parsed.total} tests reported, {executed} executed, "
            f"{parsed.failures} failures, {parsed.errors} errors, "
            f"{parsed.skipped} skipped, duration {parsed.time_seconds:.2f}s"
            + (" — no test actually ran, so this proves nothing" if executed <= 0 else "")
        ),
    )


def normalize_attestation(
    parsed: ParsedAttestation,
    release: ReleaseContext,
    *,
    artifact_root: str | None = None,
) -> NormalizedEvidence:
    return NormalizedEvidence(
        evidence_id=_new_evidence_id(
            "att",
            str(parsed.evidence_type),
            parsed.artifact.integrity_hash,
            parsed.subject_ref,
        ),
        evidence_type=parsed.evidence_type,
        source=EvidenceSource(name="manual-attestation", kind="attestation"),
        producer=parsed.producer,
        subject_type=parsed.subject_type,
        subject_ref=parsed.subject_ref,
        status=parsed.status,
        confidence=parsed.confidence,
        release_id=release.release_id,
        commit_sha=release.commit_sha,
        generated_at=parsed.generated_at,
        raw=_raw_ref(parsed.artifact, artifact_root),
        summary=parsed.summary,
        metadata=dict(parsed.metadata),
        manual=True,
    )


def normalize_pr_metadata(
    payload: dict[str, Any],
    release: ReleaseContext,
) -> NormalizedEvidence:
    """Normalize a GitHub PR metadata payload collected by the GitHub adapter.

    Expected keys (see `collectors.github`): `number`, `reviewers_required`,
    `reviewers_approved`, `last_approval_after_last_commit`, `html_url`,
    `merged`, `base`, `head`, `title`, `author`.
    """
    approved = int(payload.get("reviewers_approved", 0))
    required = int(payload.get("reviewers_required", 1))
    after_last_commit = bool(payload.get("last_approval_after_last_commit", False))
    status: EvidenceStatus
    if approved >= required and after_last_commit:
        status = EvidenceStatus.PASSED
    elif approved > 0:
        status = EvidenceStatus.FAILED
    else:
        status = EvidenceStatus.MISSING
    subject_ref = f"PR-{payload.get('number', '?')}"
    pr_digest_key = f"{payload.get('number', '?')}|{payload.get('html_url', '')}"
    collected_at = payload.get("collected_at")
    if isinstance(collected_at, str):
        try:
            collected_at_dt = datetime.fromisoformat(collected_at.replace("Z", "+00:00"))
        except ValueError:
            collected_at_dt = datetime.now(tz=UTC)
    elif isinstance(collected_at, datetime):
        collected_at_dt = collected_at
    else:
        collected_at_dt = datetime.now(tz=UTC)
    return NormalizedEvidence(
        evidence_id=_new_evidence_id("cr", pr_digest_key, release.commit_sha),
        evidence_type=EvidenceType.CODE_REVIEW,
        source=EvidenceSource(name="github", kind="scm", uri=payload.get("html_url")),
        producer="github-pull-request",
        subject_type=SubjectType.PULL_REQUEST,
        subject_ref=subject_ref,
        status=status,
        confidence=ConfidenceLevel.HIGH,
        release_id=release.release_id,
        commit_sha=release.commit_sha,
        generated_at=None,
        collected_at=collected_at_dt,
        summary=(
            f"PR {subject_ref}: {approved}/{required} approvals, "
            f"last_approval_after_last_commit={after_last_commit}"
        ),
        metadata=payload,
    )


def normalize_workflow_run(
    payload: dict[str, Any],
    release: ReleaseContext,
) -> NormalizedEvidence:
    """Normalize a GitHub Actions workflow run payload."""
    conclusion = str(payload.get("conclusion", "")).lower()
    if conclusion == "success":
        status = EvidenceStatus.PASSED
    elif conclusion in {"failure", "timed_out", "cancelled", "startup_failure"}:
        status = EvidenceStatus.FAILED
    else:
        status = EvidenceStatus.COMPLETED
    return NormalizedEvidence(
        evidence_id=_new_evidence_id(
            "wf",
            str(payload.get("run_id", "unknown")),
            str(payload.get("workflow_name", "")),
            release.commit_sha,
        ),
        evidence_type=EvidenceType.WORKFLOW_RUN,
        source=EvidenceSource(
            name="github-actions",
            kind="ci",
            uri=payload.get("html_url"),
            version=payload.get("workflow_name"),
        ),
        producer="github-actions",
        subject_type=SubjectType.WORKFLOW_RUN,
        subject_ref=str(payload.get("run_id", "unknown")),
        status=status,
        confidence=ConfidenceLevel.HIGH,
        release_id=release.release_id,
        commit_sha=release.commit_sha,
        generated_at=None,
        summary=(
            f"workflow {payload.get('workflow_name')} run "
            f"{payload.get('run_id')} ended with {conclusion or 'unknown'}"
        ),
        metadata=payload,
    )
