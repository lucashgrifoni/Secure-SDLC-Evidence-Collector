# Release notes draft — v2.0.0

Human-curated draft for the GitHub Release body when `v2.0.0` is cut.
`release-please` will generate a mechanical changelog from `feat:`,
`fix:`, `docs:` commits; the GitHub Release page itself reads better
when a maintainer adds the framing, the upgrade note, and the OSS
positioning.

**When to publish.** After v1.2.0 ships publicly (Blocks A–H in
[`EXTERNAL-ACTIONS-2026-05-18.md`](EXTERNAL-ACTIONS-2026-05-18.md)) and
the v2.0 implementation branch (`feat/tier-6-v2.0`) merges in `main`.
Suggestion: keep `"draft": true` in
`.github/release-please-config.json` for this first major-version cut
so you can review the auto-built page before publishing.

---

## v2.0.0 — OSS-first, standards-aligned

**Release date:** TBD (after v1.2.0 + Tier 6 implementation phases A–E).

**Headline.** First major version. The collector now speaks every
open standard a 2026 consumer expects (CycloneDX 1.7, OSV Schema, OSCAL
AR, in-toto v1 + Witness predicate, OpenVEX + CycloneDX VEX + CSAF VEX),
ingests AI evidence the same way it ingests traditional evidence
(SP 800-218A SSDF AI Profile, OWASP LLM/MCP/Agentic Top 10), folds
exploit-probability (EPSS + KEV) into the release verdict, and ships
ready-to-use Rego/Kyverno policy snippets so admission controllers
consuming our bundle work out of the box. The whole release is **100 %
open source** — no proprietary SDKs, no paid integrations as required
deps.

**Why a major version.** v1.x was already wire-compatible, but the
combined surface of new evidence types, new catalogs, new exporters,
and the new `watch` daemon makes v2.0 the right positional signal: the
project pivots from "evidence-first CLI" to "the OSS evidence
aggregator for Secure SDLC". Schema additions are still backwards
compatible — a v1.x consumer reading a v2.x bundle still parses every
field it knew. No flag removal, no rename.

### Why upgrade

- **Speaks the standards you adopted last year.** CycloneDX 1.7
  (ECMA-424) parser handles `lifecycles`, `tlp`, `distribution`, and
  inline VEX. OSV Schema parser ingests `osv-scanner --format json`
  natively. in-toto Witness predicate type makes the signed Statement
  consumable by SBOMit + GUAC + Sigstore cosign without bespoke envelope
  code on either side.
- **AI evidence, same shape as traditional.** New `EvidenceType`
  members (`MODEL_CARD`, `PROMPT_INJECTION_TEST_RESULT`,
  `AI_SAFETY_EVAL`, `MCP_TOOL_INVENTORY`, `AI_TRAINING_DATA_LINEAGE`)
  feed a new `catalog-ai.yaml` mapping SP 800-218A + OWASP LLM/MCP/
  Agentic Top 10. Parsers for garak, lm-eval-harness, and Hugging Face
  model cards mean an AI workload is just another set of artifacts.
- **Risk-weighted release status.** `evaluate --risk-mode
  epss-weighted` lets a control with KEV-listed unfixed CVEs (or an
  EPSS-high cluster) downgrade from `met` to `partial` even when
  evidence is technically present. Default mode unchanged — opt-in.
- **Regulatory profiles ready before the deadlines.** `run --profile
  cra-2026` packages SBOM + VEX + signed Statement + RV.* timeline into
  a CRA-shaped pack with 10y retention metadata; `catalog-fedramp-20x-ksi.yaml`
  evaluates against published KSIs and emits OSCAL AR using KSI
  control IDs.
- **Continuous evidence.** New `sdlc-evidence watch` daemon under the
  `[watch]` extra accepts GitHub + GitLab webhooks, re-runs collection,
  persists historical bundles under `output/history/<sha>.json`. State
  is durable; daemon survives restart.
- **Graph-ready.** `sdlc-evidence guac` exporter maps our in-toto
  Statement + SBOM + VEX to GUAC's GraphQL ingestion contract; no GUAC
  instance needed at export time.

### Added

- **Parsers**
  - `parsers/sbom.py` — CycloneDX 1.7 support (1.5/1.6 stay supported).
  - `parsers/osv.py` (new) — OSV native + OSV-Scanner SARIF mode.
  - `parsers/garak.py` (new) — NVIDIA garak `report.jsonl`.
  - `parsers/lm_eval.py` (new) — EleutherAI lm-eval-harness
    `results.json` (HELM-compatible).
  - `parsers/model_card.py` (new) — Hugging Face model card YAML
    front-matter, OSAID v1.0 license check.
  - `parsers/vex_input.py` (new) — multi-VEX consumer (OpenVEX +
    CycloneDX VEX + CSAF VEX).
- **Exporters**
  - `exporters/intoto.py` — new `--predicate-type witness` mode.
  - `exporters/guac.py` (new) — GUAC ingestion JSON.
- **Catalogs**
  - `controls/data/catalog-ssdf-1.2.yaml` (new) — NIST SP 800-218 Rev. 1.
  - `controls/data/catalog-ai.yaml` (new) — SP 800-218A + OWASP LLM/MCP/Agentic.
  - `controls/data/catalog-fedramp-20x-ksi.yaml` (new) — FedRAMP 20x KSIs.
- **Scoring**
  - `scoring/risk.py` (new) — EPSS + KEV weighted release status.
- **CLI**
  - New: `sdlc-evidence guac`, `sdlc-evidence watch`.
  - Extended: `sdlc-evidence statement --predicate-type
    witness|evidence-bundle|slsa-provenance`, `sdlc-evidence vex
    --consume <file>`, `sdlc-evidence evaluate --risk-mode
    epss-weighted`, `sdlc-evidence run --profile cra-2026`.
- **Domain**
  - `EvidenceType`: 5 new members for AI evidence.
- **Extras**
  - New `[watch]` extra pulling `watchdog` (MIT) and `uvicorn` (BSD).

### Community / sustainability (T6.C1–C5)

- **OpenSSF Best Practices Badge — passing tier.** Badge URL in README.
- **GitHub Secure Open Source Fund** application submitted (Apr 2026 cohort).
- **Governance docs.** New `GOVERNANCE.md` + `MAINTAINERS.md`;
  `CONTRIBUTING.md` refreshed with the "how to become a maintainer"
  section.
- **Reproducible wheel build.** `make build` produces a wheel whose
  SHA-256 matches across Linux/Windows/macOS. New gate in
  `publish-pypi.yml`.
- **Rego/Kyverno policy snippets** shipped under `policies/`. CI gate
  in new `.github/workflows/policy-tests.yml` validates them with
  `conftest test` + `kyverno apply --policy`.

### Migration

None for the schema. v2.0 bundle.json is wire-compatible with v1.2.0:

- New `EvidenceType` members are optional. Consumers that don't
  understand them ignore the records (same convention as the existing
  `unknown` evidence type handling).
- New top-level keys in `assessment-results` / VEX exports are only
  emitted when the new exporters are invoked.
- No CLI flag removed; no command removed.
- No public Python API changed; new symbols are additive.

For users of the cross-OS structural SHA-256 baseline, regenerate the
snapshot once — the additional fields change canonical JSON layout.
Snapshot fixture bumped from v1.2's `7d8b94c781ae…` to a new value
documented in `tests/fixtures/sample_release_snapshot.sha256`.

### Verifying this release

After publish:

```bash
# Wheel (now reproducible — same SHA on every runner)
pip download secure-sdlc-evidence-collector==2.0.0
shasum -a 256 secure_sdlc_evidence_collector-2.0.0-py3-none-any.whl

# Cosign signature (keyless, Sigstore Rekor)
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/.github/workflows/publish-pypi.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --signature secure_sdlc_evidence_collector-2.0.0-py3-none-any.whl.sig \
  secure_sdlc_evidence_collector-2.0.0-py3-none-any.whl

# Container
docker pull ghcr.io/lucashgrifoni/secure-sdlc-evidence-collector:v2.0.0
cosign verify ghcr.io/lucashgrifoni/secure-sdlc-evidence-collector:v2.0.0 \
  --certificate-identity-regexp 'https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# in-toto Statement with Witness predicate (NEW in v2.0)
sdlc-evidence statement /path/to/bundle.json --predicate-type witness \
  --output statement.intoto.json
cosign attest --predicate statement.intoto.json --type custom \
  --certificate-identity-regexp '...' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  <subject-ref>

# OSCAL AR for FedRAMP 20x (NEW in v2.0)
sdlc-evidence oscal --kind assessment-results \
  --bundle /path/to/bundle.json \
  --catalog catalog-fedramp-20x-ksi.yaml \
  --output ar.json

# EU CRA evidence pack (NEW in v2.0)
sdlc-evidence run --profile cra-2026 --artifact-dir <dir>

# Admission-time gate (NEW in v2.0)
conftest test --policy policies/rego/release-ready.rego bundle.json
kyverno apply policies/kyverno/require-evidence.yaml --resource bundle.json
```

### Acknowledgements

This release came out of two structured passes that surfaced concrete
gaps: a 2026-05-18 OSS market scan (NIST SSDF 1.2 + 218A, EU CRA,
FedRAMP 20x, OpenVEX/CycloneDX/CSAF, in-toto Witness, GUAC, EPSS/KEV,
OWASP LLM/MCP/Agentic Top 10) and an OSS-first constraint that ruled
out every paid SaaS surface as a required dependency.

Roadmap for v2.1+:
- T6.4 SSDF 1.2 maturity once SP 800-218r1 is final (was draft at v2.0
  cut).
- T6.C2 OpenSSF Best Practices Badge **Silver** once governance docs
  (T6.C3) have track record.
- Source-track SLSA when the upstream spec stabilises.

Plan: [`docs/program/plan-tier-6-v2.0.md`](plan-tier-6-v2.0.md).
Validation pack from the v1.2.0 hardening pass remains under
`output/publication-2026-05-17/`.
