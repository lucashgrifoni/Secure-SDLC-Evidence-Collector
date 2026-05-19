# Tier 6 / v2.0 — implementation plan

This is the in-repo copy of the approved plan. The original is at
`~/.claude/plans/fa-a-uma-pesquisa-detalhada-squishy-lovelace.md` (local
to the maintainer's machine). This file mirrors it so contributors can
read the plan without needing access to the maintainer's plan store.

## Context

The Secure SDLC Evidence Collector is at `feat/tier-5-evidence-enrichment`
(v1.2.0 prep, PR #25 open). It already speaks NIST SSDF 1.1, OWASP SAMM,
OSCAL Catalog + Assessment Results 1.1.2, OpenVEX 0.2.0, in-toto
Statement v1 + DSSE, and ships EPSS + CISA KEV enrichment. The 2026 OSS
landscape moved fast in four directions the current tool surface does
not yet cover: (1) standards everyone *already* adopted but our parsers
still miss — CycloneDX 1.7 (ECMA-424), OSV Schema as the lingua franca
of OSS vulnerability data, Witness/SBOMit attestation predicates;
(2) AI evidence — SP 800-218A SSDF AI Profile, OWASP LLM/MCP/Agentic Top
10 — where zero OSS scanner ingests evaluation artifacts as bundle
evidence; (3) imminent regulatory deadlines — EU CRA (2026-09-11) and
FedRAMP 20x (2026-09-30) — that require machine-readable evidence packs;
(4) the graph + continuous layer (GUAC graduated to OpenSSF Incubating;
watch daemons are the operational complement to "continuous ATO"). The
user picked **v2.0 as a single release** to communicate the OSS-first /
standards-aligned pivot in one move, with AI track at full scope and
the community/sustainability track included. Constraint: **100% OSS**,
no proprietary SDKs as required deps, all upstream projects/standards
must be free and Apache-2.0 (or equivalent) compatible.

The intended outcome is a release that lands the collector as the
canonical OSS evidence aggregator for Secure SDLC: speaks every open
standard a 2026 consumer expects, handles AI workloads the same way it
handles traditional ones, and carries enough community signals
(OpenSSF Best Practices Badge passing, governance docs, reproducible
wheels, ready-to-use Rego/Kyverno policy snippets) to be credibly
adopted by external teams.

## v2.0 — single release, internal phases

Six work phases inside one cut. v2.0 ships after v1.2.0 lands publicly
(PRs #24 + #25 + external actions in
[`EXTERNAL-ACTIONS-2026-05-18.md`](EXTERNAL-ACTIONS-2026-05-18.md)).
New work begins on `feat/tier-6-v2.0` branched off `main` once v1.2.0 is
tagged.

All schema changes are **additive**: new optional fields, new evidence
type enum members, new commands. No removal, no rename, no flag flip.
The x.0 jump is positional (signals the standards-alignment pivot), not
breaking.

### Phase A — Standards alignment (~10 working days)

#### T6.1 — CycloneDX 1.7 parser update (M, ~3 days)

- **Why:** ECMA-424 standard since 2026-03-25. Adds `lifecycles`,
  `tlp`, `distribution`, inline `vulnerabilities[].analysis`
  (consumable as VEX without a sidecar).
- **Surface:** extend `src/evidence_collector/parsers/sbom.py`.
  Version detection via `specVersion`. 1.5/1.6 stays supported.
- **OSS deps:** none new. Optional `cyclonedx-python-lib` (Apache-2.0)
  as dev dep for validation.
- **Acceptance:**
  - Parses `bomFormat:CycloneDX specVersion:1.7` without falling back
    to "unknown driver".
  - Inline `vulnerabilities[].analysis` round-trips into
    `exporters/vex.py` as a second VEX source (sets up T6.7).
  - `lifecycles[]` surfaces as `evidence.metadata.lifecycle_phase`.
  - `tlp` and `distribution` parsed into bundle metadata, advisory
    only (no impact on control evaluation).
  - Backward-compatible: existing 1.5 fixtures produce byte-identical
    bundles.
- **Tests:** 3 unit fixtures (1.5 baseline, 1.7 minimal, 1.7 with
  inline VEX); 1 hypothesis property on `specVersion` parsing;
  integration in `tests/integration/test_bundle_snapshot.py`.

#### T6.2 — OSV parser + OSV-Scanner driver in SARIF parser (M, ~4 days)

- **Why:** OSV Schema is the lingua franca (GHSA + PyPA + RustSec +
  NVD aggregate). OSV-Scanner v2.3.5 is what OSS-only teams actually
  run.
- **Surface:** new parser `src/evidence_collector/parsers/osv.py`
  (consume native `osv.json`); driver row added to
  `src/evidence_collector/parsers/sarif.py` for OSV-Scanner SARIF
  mode.
- **OSS deps:** none — plain JSON.
- **Acceptance:**
  - Accepts both `osv-scanner --format json` (native) and
    `--format sarif`.
  - Maps `ecosystem` (PyPI, npm, Go, Maven, Cargo, …) into
    `evidence.metadata.ecosystem`.
  - `withdrawn` records → `EvidenceStatus.INVALID` (don't pollute
    findings).
  - CVE IDs flow into `intelligence/enricher.py` identically to SARIF
    SCA today.
  - `sdlc-evidence collect` auto-detects `osv.json` in the artifact dir.
- **Tests:** 4 unit fixtures (pip transitive, npm direct,
  multi-ecosystem, withdrawn); 1 integration through `enrich`.

#### T6.3 — in-toto Witness predicate type (S, ~2 days)

- **Why:** SBOMit + Witness are converging on specific in-toto
  predicate types. Our T5.5 export uses a generic project predicate
  type only.
- **Surface:** new flag
  `--predicate-type witness|evidence-bundle|slsa-provenance` on
  `src/evidence_collector/cli/commands/statement.py` backed by
  `src/evidence_collector/exporters/intoto.py`.
- **Acceptance:**
  - `--predicate-type witness` produces an artifact
    `witness verify-statement` accepts.
  - DSSE envelope shape unchanged.
  - New ADR `docs/adr/0007-attestation-predicate-types.md`.
  - Default stays `evidence-bundle` (no behavior break for v1.2 users).
- **Tests:** 3 unit (one per predicate type) + 1 integration that
  round-trips through `cosign verify-blob-attestation` when cosign
  present (skip otherwise).

#### T6.4 — SSDF 1.2 catalog (`catalog-ssdf-1.2.yaml`) (S, ~2 days)

- **Why:** NIST SP 800-218 Rev. 1 finalizes 2026. Refines PS.3 build
  provenance, PW.7 design review, RV.* vulnerability response cadence.
- **Surface:** new file under
  `src/evidence_collector/controls/data/`. Default catalog stays 1.1;
  SSDF 1.2 is opt-in via `--catalog`.
- **Acceptance:**
  - 1.2 catalog covers PS.3.1/3.2, PW.7, RV.1.3/2.2.
  - `sdlc-evidence controls --catalog catalog-ssdf-1.2.yaml` lists
    deltas vs default.
  - `docs/traceability.md` adds an SSDF-1.1-vs-1.2 crosswalk section.
  - Existing fixtures evaluated against the 1.2 catalog produce a
    documented score delta with no fixture changes.

### Phase B — AI track (~9 working days)

#### T6.5 — AI catalog + AI evidence types (L, ~1.5 weeks)

- **Why:** SP 800-218A (SSDF AI Profile), OWASP LLM Top 10 2026,
  OWASP MCP Top 10, OWASP Agentic Top 10. **Zero OSS scanners ingest
  these as bundle evidence today.** Highest-ROI greenfield slot for
  v2.0.
- **Surface:**
  - New `EvidenceType` enum members in
    `src/evidence_collector/domain/enums.py`: `MODEL_CARD`,
    `PROMPT_INJECTION_TEST_RESULT`, `AI_SAFETY_EVAL`,
    `MCP_TOOL_INVENTORY`, `AI_TRAINING_DATA_LINEAGE`.
  - New parsers under `src/evidence_collector/parsers/`:
    `garak.py` (NVIDIA garak `report.jsonl`), `lm_eval.py`
    (EleutherAI lm-eval-harness `results.json`, HELM-compatible),
    `model_card.py` (Hugging Face model card YAML front-matter;
    OSAID v1.0 license check).
  - New `catalog-ai.yaml` (~10 controls mapping SP 800-218A +
    OWASP LLM/MCP/Agentic).
  - No new CLI verb; flows through `collect` + `evaluate`.
- **OSS deps:** none — all parsers consume plain JSON/YAML. HELM,
  lm-evaluation-harness, garak are upstream Apache-2.0; we do not
  import them.
- **Acceptance:**
  - `--catalog catalog-ai.yaml` evaluates a fixture project mixing
    traditional + AI evidence.
  - `garak report.jsonl` parsed; prompt-injection / DAN / xss probes
    surface as `prompt_injection_test_result`.
  - `lm-eval results.json` parsed; benchmark scores surface as
    `ai_safety_eval`.
  - Hugging Face model card YAML parsed; missing
    `model_details.license` or `evaluation` sections flagged in
    `EvidenceStatus.INVALID`.
  - MCP tool inventory schema documented in new
    `docs/evidence-types-ai.md`.
- **Tests:** unit per parser (5 fixtures: garak, lm-eval, model card,
  MCP inventory, training data lineage); 1 integration evaluating a
  synthetic LLM-product fixture against the AI catalog.

### Phase C — Risk-weighted verdict + multi-VEX (~7 working days)

#### T6.6 — Risk-based release status (EPSS-weighted) (M, ~3 days)

- **Why:** Closes the "checklist theater" critique. Today
  `release_status` only sees evidence presence; this lets it see
  exploit probability.
- **Surface:** new `src/evidence_collector/scoring/risk.py`; new flag
  `evaluate --risk-mode epss-weighted` (default off; opt-in for v2.0).
- **OSS deps:** none new (EPSS + KEV already wired via T5.1).
- **Acceptance:**
  - With `--risk-mode epss-weighted`, a `met` control with ≥1
    KEV-listed unfixed CVE downgrades to `partial`.
  - EPSS ≥ 0.5 on ≥3 findings in the same control downgrades from
    `met` to `partial`.
  - Threshold values live in the catalog YAML (`risk_thresholds:`
    block), not hard-coded.
  - Rationale string in the evaluation names the specific CVE that
    triggered the downgrade.
  - Default mode produces byte-identical bundles to v1.2.0.
- **Tests:** 4 unit (no enrichment → no-op; single high-EPSS → no
  downgrade; high-EPSS cluster → downgrade; single KEV → downgrade);
  1 integration on lab fixtures with documented verdict shift.

#### T6.7 — Multi-VEX consumer (OpenVEX + CycloneDX VEX + CSAF VEX) (M, ~4 days)

- **Why:** Vendors ship different VEX dialects. Whoever consolidates
  wins.
- **Surface:** new parser `src/evidence_collector/parsers/vex_input.py`;
  new CLI mode `sdlc-evidence vex --consume <file>` that normalizes
  input to the internal OpenVEX representation before merging.
- **OSS deps:** none — all three dialects are JSON/XML.
- **Acceptance:**
  - Accepts OpenVEX 0.2.0, CycloneDX VEX (standalone + inline from
    T6.1), CSAF 2.0 JSON.
  - Same product+CVE with conflicting status → documented error with
    `--vex-conflict-policy first-wins|last-wins|fail`.
  - Merged output emits OpenVEX 0.2.0 (single canonical dialect).
  - SPDX VEX explicitly deferred (low adoption); documented in
    `docs/limitations.md`.
- **Tests:** unit per dialect (3 fixtures); 1 conflict-resolution
  test per policy; 1 integration round-tripping a CycloneDX 1.7
  inline-VEX bundle.

### Phase D — Regulatory + Graph (~10 working days)

#### T6.8 — EU CRA mode + FedRAMP 20x KSI catalog (M, ~5 days)

- **Why:** EU CRA reporting obligations start 2026-09-11; FedRAMP 20x
  OSCAL mandate 2026-09-30. Two deadlines, same release.
- **Surface:** new flag `run --profile cra-2026`; new
  `catalog-fedramp-20x-ksi.yaml`. CRA profile is a *filter* over
  existing evidence + extra metadata, not a new catalog.
- **Acceptance:**
  - `--profile cra-2026` outputs a `cra/` subdirectory containing:
    machine-readable SBOM (CycloneDX 1.7), VEX, signed in-toto
    Statement, vulnerability response timeline (RV.* evidence), all
    under one `manifest.json` that names retention period (10y).
  - `--catalog catalog-fedramp-20x-ksi.yaml` evaluates against the
    published KSI set and emits OSCAL AR using KSI control IDs.
  - New `docs/compliance/eu-cra.md` and
    `docs/compliance/fedramp-20x.md` document the mapping.
  - Self-release fixture passes both profiles cleanly.
- **Tests:** 2 integration (one per profile) against lab fixtures.

#### T6.9 — GUAC adapter + watch daemon (L, ~1.5 weeks)

- **Why:** GUAC is the OSS supply-chain graph; "continuous ATO" is
  the operational pattern the CRA codifies.
- **Surface:**
  - New CLI `sdlc-evidence guac --bundle <file> --output <dir>`
    exporter mapping our in-toto Statement + SBOM + VEX to GUAC's
    GraphQL ingestion contract (emits the JSON `guacingest`
    consumes; no live GUAC required at export time).
  - New CLI `sdlc-evidence watch` daemon under the `[watch]` extra:
    webhook receivers for GitHub + GitLab + a local poll mode.
    State persisted in `.sdlc-evidence/state.json`. Health endpoint
    at `/healthz`.
- **OSS deps:** `watchdog` (MIT) for fs polling; `uvicorn` (BSD)
  already pulled in by the `[api]` extra. No GUAC SDK.
- **Acceptance:**
  - `guac` exporter output accepted by
    `guacingest --strategy files <dir>`.
  - `watch --webhook github` re-runs collection on
    `workflow_run.completed`; persists historical bundles under
    `output/history/<sha>.json`.
  - Daemon survives restart (durable cursor).
  - Graceful shutdown (`SIGTERM` → flush state, exit 0).
- **Tests:** unit on GUAC mapping (3 fixtures); integration spinning
  the daemon, posting a synthetic webhook, asserting a new history
  entry.

### Phase E — Community / sustainability (~6 working days, parallel)

#### T6.C1 — OpenSSF Best Practices Badge — *passing* tier (S, ~1 day)

- Self-assessment at <https://www.bestpractices.dev/>.
- Almost all criteria already met. Gaps: explicit "report security
  vulnerabilities via …" link in README (currently only in
  `SECURITY.md`), static-analysis-on-every-release claim (have it
  via CodeQL, needs the badge URL).
- **Acceptance:** badge live in README; entry in
  [`docs/MATURITY_STATUS.md`](../MATURITY_STATUS.md); v2.0 release
  notes mention it.

#### T6.C2 — GitHub Secure Open Source Fund application (S, ~1 day)

- April 2026 cohort window. Repo qualifies (Apache-2.0, security
  tooling, public `SECURITY.md`, threat model, SBOM of the tool
  itself, 261 tests).
- **Acceptance:** application submitted; URL recorded in
  `docs/program/community.md`.
- **Backup plan if rejected:** Alpha-Omega Tier 2 candidacy after
  6 months of measurable public adoption.

#### T6.C3 — Governance + contributor ladder docs (S, ~1 day)

- New `GOVERNANCE.md` (BDFL model documented honestly), new
  `MAINTAINERS.md`, refresh `CONTRIBUTING.md` to add the "how to
  become a maintainer" section (currently focused on workflow only).
- **Why:** prerequisite for OpenSSF Best Practices Badge Silver tier
  (future) and for the GitHub Secure OSS Fund application narrative.

#### T6.C4 — Reproducible wheel build (S, ~2 days)

- Adopt `setuptools-reproducible` or `uv --reproducible`. Bundle
  output is already deterministic; the wheel itself is not.
- **Acceptance:** `make build` produces a wheel whose SHA-256 matches
  across Linux/Windows/macOS runners. New gate in
  `.github/workflows/publish-pypi.yml`.

#### T6.C5 — Rego/Kyverno policy snippets (S, ~1 day)

- Ship `policies/rego/release-ready.rego` and
  `policies/kyverno/require-evidence.yaml`.
- **Why:** admission controllers consuming our bundle work out of
  the box; closes the "what do I do with this JSON" question for
  OPA/Kyverno operators.
- **Acceptance:** snippets tested with `conftest test` +
  `kyverno apply --policy …` in a new
  `.github/workflows/policy-tests.yml`; CI gate green.

## Out of scope

Already out of scope in [`MATURITY_ROADMAP.md`](../MATURITY_ROADMAP.md):

- Multi-tenant SaaS deployment.
- Web dashboard / analytics surface.
- Custom signing format.

New for v2.0:

- **SPDX VEX consumer** — low real-world adoption; revisit if a major
  SBOM vendor commits. Documented in
  [`docs/limitations.md`](../limitations.md).
- **Source-track SLSA** — spec deferred upstream; Build track L3 is
  enough.
- **Paid scanner parsers** (Snyk, Veracode, Mend.io, JFrog Xray) —
  forbidden by Tier 6 OSS constraint.
- **In-house EPSS-like model** — FIRST's feed is free and trusted;
  rolling our own is rent-seeking.
- **OpenSSF Best Practices Badge Gold tier** — requires
  multi-maintainer + bug bounty; not a v2.x goal. **Silver** is a
  v2.1+ goal once governance docs (T6.C3) have a track record.
- **AI agent execution.** We *ingest* AI evidence; we do not *run*
  prompts. The watch daemon is a webhook receiver, not an agentic loop.

## Sequencing

Suggested commit/branch layout, all on `feat/tier-6-v2.0`:

1. Branch off `main` after v1.2.0 tag.
2. Phase A: one commit per item (T6.1, T6.2, T6.3, T6.4).
3. Phase B: one commit for enum + each parser, one commit for the
   catalog, one commit for the fixture lab.
4. Phase C: one commit per item.
5. Phase D: one commit for CRA + KSI; one commit for GUAC exporter;
   one commit for watch daemon (likely two: skeleton + webhook).
6. Phase E community items can land as their own commits at any phase
   boundary — they are independent of code.
7. Final commit: `chore(release): prepare v2.0.0` bumping
   `pyproject.toml`, `__init__.py`,
   `.github/.release-please-manifest.json`, README badge, and renaming
   `docs/program/RELEASE-NOTES-v2.0.0-draft.md` to the publish-ready
   form.

After merge, the `release-please` workflow recognises the `feat:` and
`fix:` commits and opens the version PR; merging that triggers the
existing `publish-pypi.yml` (cosign keyless, SLSA L3, multi-arch GHCR,
signed SBOM, PyPI Trusted Publisher).
