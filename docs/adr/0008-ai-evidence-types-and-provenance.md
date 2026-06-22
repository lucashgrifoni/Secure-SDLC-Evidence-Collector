# ADR 0008 — AI evidence types and provenance

- Status: accepted
- Date: 2026-05-19
- Deciders: Lucas Henrique Grifoni
- Supersedes: none
- Superseded by: none

## Context

Through v1.2.0 the collector only modelled "classical" Secure SDLC
evidence (SAST, SCA, secrets, SBOM, signature, attestation, code
review, threat model, etc). It did not capture artifacts specific to
shipping AI / LLM / agentic systems:

- model cards (intended use, evaluation metrics, license, training
  data)
- prompt-injection probe results (garak and equivalents)
- safety / bias / refusal evaluations (lm-evaluation-harness and
  equivalents)
- MCP / tool-use inventories for agentic systems
- training data lineage manifests

The market direction in 2026 makes this gap costly:

- NIST published **SP 800-218A "SSDF Community Profile for Generative
  AI"** in 2024-07. PW.4.AI, PS.AI.1, PS.AI.2 expect evidence the
  collector did not previously model.
- OWASP **Top 10 for LLM Applications** (2025 edition: LLM01 prompt
  injection through LLM10 unbounded consumption) and the OWASP **Top
  10 for Agentic Applications (2026)** describe risks that require
  AI-specific evidence to mitigate.
- The CRA window (2026-09-11) and FedRAMP 20x window (2026-09-30) do
  not currently mandate AI-specific evidence, but customers shipping
  AI products are already expected to demonstrate it.

## Decision

Add an **AI evidence track** to the existing schema, additively:

1. **Five new `EvidenceType` values** — `model_card`,
   `prompt_injection_test_result`, `ai_safety_eval`,
   `mcp_tool_inventory`, `ai_training_data_lineage`.
2. **Three new `SubjectType` values** — `ai_model`, `ai_agent`,
   `ai_dataset` — so AI evidence can attach to the right subject
   instead of being forced onto `artifact` / `application`.
3. **Three new parsers** under `evidence_collector.parsers` —
   `garak`, `lm_eval`, `model_card`. Each consumes the canonical
   output of its tool family and emits a typed dataclass; no IO is
   done outside `ensure_file` / `load_json`.
4. **Three new normalizers** — `normalize_garak`,
   `normalize_lm_eval`, `normalize_model_card` — each producing a
   `NormalizedEvidence` with `subject_type = ai_model` and the
   parser-specific metadata under `evidence.metadata`.
5. **A new opt-in catalog** — `catalog-ai.yaml` — that exposes ten
   AI-aware controls mapped to SSDF AI Profile + OWASP Top 10 for LLM
   Applications (2025) + OWASP Top 10 for Agentic Applications (2026).
   The default catalog is unchanged.
6. **Auto-detection** in `LocalArtifactCollector` for the three new
   shapes, gated by both filename heuristics and content sniffing so
   generic JSON files are not mis-classified.

The bundle `schema_version` does **not** change. Pipelines that do
not ship AI artifacts see no difference. Pipelines that do can opt
in either by passing `--catalog catalog-ai.yaml` or by dropping the
new artifact files into their existing `artifacts/` directory.

### Crosswalk: SSDF AI Profile + OWASP LLM + OWASP Agentic

OWASP LLM IDs use the 2025 numbering (https://genai.owasp.org/llm-top-10/);
the Agentic column references the OWASP Top 10 for Agentic Applications (2026)
by theme rather than by ID.

| Control (catalog-ai.yaml) | SSDF AI Profile | OWASP LLM (2025) | OWASP Agentic (2026) |
|---|---|---|---|
| `AI-MODEL-CARD` | PS.AI.1 | LLM02 | — |
| `AI-PROMPT-INJ` | PW.4.AI | LLM01 | — |
| `AI-SAFETY-EVAL` | PW.4.AI | LLM01 / LLM02 | — |
| `AI-TRAINING-LINEAGE` | PS.AI.2 | LLM04 | — |
| `AI-MCP-INVENTORY` | PW.4.AI | LLM06 | tool misuse / excessive tool reach |
| `AI-THREAT-MODEL` | PW.1.AI | — | agentic blast radius |
| `AI-SBOM` | PS.3 | LLM03 | — |
| `AI-SCA` | PW.4 | LLM03 | — |
| `AI-SAST` | PW.7 | LLM05 | tool misuse |
| `AI-RELEASE-APPROVAL` | (org-internal) | — | — |

## Consequences

- **Backward-compatible.** No existing parser, normalizer, evidence
  type, control, or exporter changes meaning. Bundles produced before
  Sprint 2 remain byte-stable.
- **Schema-stable.** No `schema_version` bump. Consumers that
  enumerate `EvidenceType` should accept the new values via the same
  StrEnum membership check they used before.
- **Catalog is opt-in.** Promoting any AI control to the default
  catalog would silently raise the bar for non-AI users. The
  per-project decision lives in pipeline configuration, not in the
  collector.
- **CI does not depend on internet or HF tokens.** Fixtures for
  garak / lm-eval / model-card are frozen JSON committed under
  `tests/`. The fixture-refresh procedure is documented in the
  fixture README; CI never downloads model weights or hits HF.
- **Provenance handling for AI artifacts.** The bundle carries the
  artifact integrity hash and (when present) the model identifier in
  `evidence.metadata.ai_model_id`. Hash-of-weights provenance for
  the model itself is **not** handled here — that is supply-chain
  territory and should be covered by an SBOM + signature on the model
  weights artifact, the same as any other binary the release ships.

## Alternatives considered

- **Separate AI bundle schema.** Considered but rejected: forces
  consumers to track two schemas, makes the verdict logic split, and
  makes mixed-mode releases (classical app + AI add-on) harder to
  evaluate.
- **Per-attestor parsers (PromptFoo, NeMo Guardrails, OpenAI
  Evals, Hugging Face Evaluate).** Considered. We start with garak +
  lm-eval + Hugging Face / Google MCT model cards because they are
  the OSS canonicals; extending to the others is additive and
  follows the parser plugin pattern already used elsewhere.
- **Compute pass/fail from metric thresholds inside the parser.**
  Rejected — threshold logic belongs in the catalog, not in the
  parser. The parser emits raw evidence; the catalog decides
  whether 0.42 acc on TruthfulQA is acceptable for this release.

## Verification

`pytest tests/unit/test_ai_parsers.py tests/unit/test_ai_normalizers.py tests/unit/test_catalog_edges.py`
exercises the parsers, normalizers, the auto-detect path of
`LocalArtifactCollector`, and the catalog. All fixtures are frozen
JSON; no network access is required.
