# Secure SDLC Evidence Collector v2.0.0

First public release of the Secure SDLC Evidence Collector at the v2.0 line.

This release consolidates Tier 6 work — the v2.0 cut — into a single
public version aligned with the 2026 supply-chain ecosystem. Every
change in v2.0 is additive against the v1.x evidence schema, so
pipelines that produced v1.2.x bundles can move to 2.0 without
changing their artifacts and see the new fields appear as opt-in
extras.

---

## Highlights

- Added a CycloneDX 1.7 (ECMA-424 2nd Edition) parser that reads `metadata.lifecycles[]` into `evidence.metadata.lifecycle_phases` and surfaces `vulnerabilities[*].analysis` inline VEX through the OpenVEX exporter
- Added an OSV / OSV-Scanner native parser that consumes both the `results[]` envelope and a single OSV record, with auto-detection in the LocalArtifactCollector and ecosystem tracking in `evidence.metadata.ecosystems`
- Added in-toto Statement v1 predicate-type variants: `evidence-bundle` (default), `witness`, and `slsa-provenance` selectable via `sdlc-evidence statement --predicate-type`
- Added an opt-in SSDF 1.2 catalog (`catalog-ssdf-1.2.yaml`) that refines PS.3 to require both SBOM and `artifact_attestation` and introduces the new PW.6 build-process security control
- Added a reproducible wheel gate in `publish-pypi.yml` that pins `SOURCE_DATE_EPOCH` from the tag commit and rebuilds the wheel to verify SHA-256 stability
- Added five AI evidence types — `model_card`, `prompt_injection_test_result`, `ai_safety_eval`, `mcp_tool_inventory`, `ai_training_data_lineage` — and three new `SubjectType` values: `ai_model`, `ai_agent`, `ai_dataset`
- Added three AI parsers — garak (JSONL prompt-injection report), lm-evaluation-harness (per-task metrics), and Model Card (Hugging Face Hub + Google Model Card Toolkit shapes) — with frozen-fixture testing so CI does not depend on internet or model weights
- Added an opt-in AI catalog (`catalog-ai.yaml`) with ten controls mapped to NIST SP 800-218A (SSDF AI Profile), OWASP LLM Top 10, and OWASP Agentic AI Top 10
- Added a risk-weighted verdict mode via `sdlc-evidence run --risk-mode epss-weighted` that re-derives `release_status` from the EPSS + CISA KEV signal already in the bundle, with explicit "only downgrades, never upgrades" semantics
- Added a multi-VEX consumer via `sdlc-evidence vex --consume <file> --policy first-wins|last-wins|fail` that ingests OpenVEX, CycloneDX VEX, and CSAF documents and merges them with the bundle-derived statements
- Added an optional `Reachability` field on `NormalizedEvidence` that records the upstream verdict from CodeQL reachability, Endor Labs, Semgrep Pro, or a manual review, with canonical `reachable | not_reachable | unknown` states
- Added two regulatory profiles via `sdlc-evidence run --profile cra-2026` and `--profile fedramp-20x` that annotate evidence with the regulator-shaped projections (CRA 24-hour disclosure deadline + FedRAMP 20x 10-year retention)
- Added an opt-in FedRAMP 20x KSI catalog (`catalog-fedramp-20x-ksi.yaml`) covering the Low and Moderate baselines the collector can satisfy with existing evidence types
- Added a GUAC adapter via `sdlc-evidence guac` that emits a `guac-collect` v1.0 container ingestible by `guacone collect files` in a single shot
- Added a reusable GitHub Actions workflow (`.github/workflows/reusable-evidence-collection.yml`) and a GitLab CI template (`examples/gitlab-ci/secure-sdlc-evidence.yml`) so pipelines can adopt the collector with a single `uses:` or `include:` line
- Added a devcontainer + Codespaces configuration with Python 3.12, cosign, syft, trivy, and conftest pre-installed for a zero-config onboarding path
- Added an honest comparison page (`docs/comparison.md`) crosswalking the collector against Chainguard Enforce, Scribe Trust Hub, GUAC, Kusari Trustify, Lineaje, OpenSSF Scorecard, and Snyk / Mend / Sonatype, including explicit "honesty check" cases where another tool is the right answer
- Added ADRs 0007 through 0012 covering every Tier 6 design decision, plus a Publication Runbook and pre-drafted OpenSSF Best Practices Passing-tier answers for the public-launch flow

---

## Improvements

- Cleaner alignment with the 2026 supply-chain standards landscape across CycloneDX, OSV, in-toto, SLSA, NIST SSDF 1.2 (preview), SSDF AI Profile, OpenVEX, CycloneDX VEX, CSAF, and GUAC
- More reliable risk decisions through the EPSS + KEV-weighted verdict path that complements the presence-based default without changing it
- Better separation between "exploitable in the ecosystem" (EPSS + KEV) and "exploitable in this code base" (reachability) so consumers can filter findings by both axes
- Stronger structural-hash stability through `application/integrity.py` automatically stripping null optional fields before hashing, which preserves byte-identical bundles for pre-v2.0 inputs
- Better regulator-readiness for the September 2026 deadlines (EU CRA 2026-09-11 and FedRAMP 20x 2026-09-30) without forcing every consumer to opt in
- Clearer AI evidence story with a dedicated guide (`docs/ai-evidence.md`) that explains how to instrument a release for SSDF AI Profile coverage
- Stronger CI integration through reusable GitHub Actions and GitLab CI surfaces that hide all of the collector's CLI complexity behind a small set of inputs
- More predictable build outputs through the reproducible wheel gate that proves the wheel is bit-for-bit identical on back-to-back builds
- Better community-readiness through the honest comparison page, the developer-adoption devcontainer, and the seeded set of ADRs that explain every non-obvious design decision

---

## Validation

Local release gates passed before tagging:

- `python -m ruff check src tests scripts`
- `python -m ruff format --check src tests scripts`
- `python -m mypy src tests` (strict mode, 118 source files)
- `python -m pytest --cov=evidence_collector`
- `python -m mkdocs build --strict`
- `gitleaks detect --source . --no-banner --redact`

Test result: 328 passed, 82.94% coverage (gate 80%).
Static-analysis result: 0 issues across `ruff`, `mypy --strict`, and `gitleaks` (0 findings across 79 commits + the working tree).

---

## Notes

- This is the first public release of the Secure SDLC Evidence Collector at the v2.0 line; previous v1.x cuts existed in code but were not published outside this repository
- The release focuses on aligning the collector with the 2026 supply-chain ecosystem and on covering the September 2026 EU CRA and FedRAMP 20x regulatory deadlines without forcing every consumer to opt in
- Every new field on the bundle is optional and defaults to `None`; consumers that already accepted v1.2 bundles work unchanged against v2.0 output
- CLI defaults preserve v1.2 behaviour: `--risk-mode off`, `--profile none`, default catalog still SSDF 1.1
- The bundle's `schema_version` is unchanged at `1.0.0`; the additive design avoids forcing schema migrations on consumers
- The release ships under Apache License 2.0, replacing the placeholder MIT license referenced in the v1.0.0 release notes
- Watch daemon (`sdlc-evidence watch`) is intentionally deferred from v2.0 to v2.1 — documented in `docs/limitations.md §17`
- SPDX VEX consumer is intentionally deferred to v2.1 due to low industry adoption
- Future releases will expand the catalog set, add adapter coverage to additional VEX, attestation, and AI-evaluation formats, and harden the watch / continuous-ATO surface

---

**License:** Apache-2.0
