# AI evidence — how to instrument an AI / LLM / agentic system

The Secure SDLC Evidence Collector supports five evidence types
specific to AI / LLM / agentic systems and ships an opt-in catalog
that gates releases on them. This page explains what to produce and
where to put it. The full mapping to **NIST SP 800-218A** (SSDF AI
Profile), the **OWASP Top 10 for LLM Applications (2025)**, and the
**OWASP Top 10 for Agentic Applications (2026)** lives
in [ADR-0008](./adr/0008-ai-evidence-types-and-provenance.md).

## Quick start

```bash
# 1. Drop AI artifacts next to your existing scanner output.
artifacts/
├── trivy.sarif             # SCA (unchanged)
├── sbom.cdx.json           # SBOM (unchanged)
├── run.garak.jsonl         # prompt-injection probe results
├── model.lm-eval.json      # lm-evaluation-harness output
├── model-card.json         # HF or Google MCT model card
└── dataset.croissant.json  # Croissant dataset metadata (training-data lineage)

# 2. Free-schema manifests go in as attestations.
attestations/
├── tool-inventory.yaml     # evidence_type: mcp_tool_inventory
└── training-lineage.yaml   # evidence_type: ai_training_data_lineage (if no Croissant file)

# 3. Run with the AI catalog.
sdlc-evidence run \
  --application acme/llm-coach \
  --repository acme/llm-coach \
  --release-id 2026.05.19 \
  --commit-sha "$(git rev-parse HEAD)" \
  --artifacts-dir artifacts \
  --attestations-dir attestations \
  --catalog catalog-ai.yaml
```

The collector auto-detects each AI file in the artifacts directory via
filename + content sniff and routes it to the right parser. A
free-schema JSON file dropped there (a tool list, a hand-written
dataset manifest) matches no parser and is not collected, so those go
in as attestations instead.

## Evidence types

### `model_card`

Two shapes accepted:

- **Hugging Face Hub** — model card YAML frontmatter serialised to
  JSON. The collector reads `model_id` / `model_name`, `license`,
  `datasets`, `intended_use`, and `model-index[*].results[*].metrics`.
- **Google Model Card Toolkit** — proto-shaped JSON. The collector
  reads `model_details.name`, `model_details.licenses[*]`,
  `quantitative_analysis.performance_metrics[*]`, and
  `considerations.use_cases[*].description`.

File names recognised: `model-card.json`, `model_card.json`,
`*.modelcard.json`. Content sniff also matches files that carry
`model_details` or `model-index` at the top level.

Mapped control: `AI-MODEL-CARD` (SSDF PS.AI.1, OWASP LLM02:2025).

### `prompt_injection_test_result`

Output of **garak** (https://github.com/leondz/garak). The collector
reads the JSON-Lines report with these entry kinds:

- `init` — garak version, model under test
- `digest` — per-probe attempts + hits (preferred when present)
- `attempt` — per-attempt verdict (fallback for partial runs)

Pass / fail is decided by the parser: any probe with `hits > 0`
fails the gate. The per-probe rollup travels in
`evidence.metadata.probes` so the consumer can decide whether a
single failing probe should block the release.

File names recognised: `*.garak.json`, `*.garak.jsonl`,
`*.report.jsonl`, `garak.json`, `garak.jsonl`.

Mapped control: `AI-PROMPT-INJ` (SSDF PW.4.AI, OWASP LLM01:2025).

### `ai_safety_eval`

Output of **lm-evaluation-harness**
(https://github.com/EleutherAI/lm-evaluation-harness). The collector
reads the top-level JSON object and extracts:

- `results[<task>][<metric>]` — per-task numeric metrics. Non-numeric
  cells (`"N/A"`, strings) are skipped.
- `config.model_args` (`pretrained=<id>`) or `config.model` — model
  identifier; `config.model_args` wins when both exist because it
  carries the more specific id.

Pass / fail is **not** decided by the parser. lm-eval surfaces raw
metrics; threshold logic lives in the control catalog.

File names recognised: `*.lm-eval.json`, `*.lm_eval.json`,
`lm-eval.json`. Content sniff also matches files that carry
`results: {…}` and `versions: {…}` together.

**Inspect** (UK AI Security Institute, https://inspect.aisi.org.uk) eval
logs are read too, in their JSON form: write them with
`--log-format json` or convert an `.eval` file with `inspect log convert`.
They are recognised by content, whatever the file name, and only log
format version 2 is accepted. The evidence records `eval.task`,
`eval.model`, the run status, every metric as `scorer/metric` from
`results.scores`, and the sample counts. Only a run with
`status: success` counts; an errored, cancelled or unfinished run is
recorded as `invalid`, so it stays visible but does not satisfy the
control. A log that includes every sample can exceed the collector's
25 MB input limit, in which case it is refused like any other oversized
input.

**promptfoo** (https://www.promptfoo.dev) eval output, written with
`promptfoo eval -o results.json`, is read as well, recognised by its
envelope (`results.version`, `results.stats`, `results.results`). promptfoo
publishes no formal schema, so only output version 3 is accepted. The
evidence records the passed, failed and errored test counts from
`results.stats`, the assertion tally from each row's
`gradingResult.componentResults` (skipped on rows that have none), and
which assertion types failed. Unlike lm-eval, promptfoo decides pass or
fail per test, so the evidence carries its verdict: `passed` when every
test passed, `failed` when any test failed or errored, and `invalid`
when no test produced a verdict. Only `passed` satisfies the control.

Mapped control: `AI-SAFETY-EVAL` (SSDF PW.4.AI).

### `mcp_tool_inventory`

A free-schema JSON manifest declaring the MCP / tool surface an
agentic system can reach. Recommended fields:

- `tools[*].name`, `tools[*].description`
- `tools[*].scopes` — what each tool is allowed to touch
- `tools[*].network_egress` — outbound destinations the tool may
  reach
- `tools[*].risk_class` — short label (e.g. `read-only`, `write`,
  `external-network`)

The collector does not parse a tool inventory, and a file dropped in
the artifacts directory is not collected. Supply it as an attestation
in the attestations directory, with the manifest under `metadata`, so
a reviewer can inspect blast radius from the bundle:

```yaml
evidence_type: mcp_tool_inventory
producer: platform-team
subject_ref: acme/llm-coach
status: passed
metadata:
  tools:
    - name: search
      scopes: [read]
      risk_class: low
```

Mapped control: `AI-MCP-INVENTORY` (OWASP Top 10 for Agentic
Applications 2026 — tool misuse / excessive tool reach; OWASP
LLM06:2025 excessive agency).

### `ai_training_data_lineage`

Two sources.

**Croissant dataset metadata** (MLCommons, spec 1.0 and 1.1). Any
`.json` file whose dataset-level `conformsTo` (or `dct:conformsTo`)
names `http://mlcommons.org/croissant/1.0` or `/1.1` is recognised by
content, whatever its file name; in 1.1 `conformsTo` may be a list. The
evidence records the Croissant version, dataset name, version, URL and
licenses, `datePublished`, which PROV-O terms are present
(`wasDerivedFrom`, `wasGeneratedBy`, `wasAttributedTo`), whether
`usageInfo` carries a usage policy, and how many record sets and
distribution files there are and how many of those carry a `sha256`.
Confidence is high when the file names the dataset and a license, and
medium otherwise.

**A free-schema manifest** of the datasets used to train / fine-tune
the model, supplied as an attestation (`evidence_type:
ai_training_data_lineage`) in the attestations directory, with the
manifest under `metadata`, the same way as the tool inventory above. A
manifest file dropped in the artifacts directory is not collected.
Recommended fields:

- `datasets[*].name`, `datasets[*].version`
- `datasets[*].source` — URL or repository
- `datasets[*].license`
- `datasets[*].pii_review` — boolean / link to a PII assessment
- `datasets[*].fingerprint` — content hash, when available

Mapped control: `AI-TRAINING-LINEAGE` (SSDF PS.AI.2, OWASP LLM04:2025).

## What the verdict looks like

With the AI catalog selected, the bundle's `release_status` reflects
both classical and AI controls:

```
release_status: conditional
controls_met: 7/10
controls_missing: 2/10   # AI-MCP-INVENTORY, AI-TRAINING-LINEAGE
controls_waived: 1/10    # AI-RELEASE-APPROVAL (waived under exception EX-7)
```

You can mix the AI catalog with the classical one by writing a merged
catalog YAML; the collector accepts any valid catalog under
`--catalog`.

## What this is **not**

- **Not** an evaluator. The collector ingests garak / lm-eval output;
  it does not run probes or metrics against the model.
- **Not** a runtime guardrail. The MCP tool inventory is evidence of
  intent, not enforcement.
- **Not** a substitute for a real threat model. `AI-THREAT-MODEL`
  expects a threat model document with explicit AI sections; the
  collector verifies presence and provenance, not quality.
- **Not** a content-safety filter. Safety evaluation is delegated to
  lm-eval and equivalent tools; the collector records the result.

## Fixture handling and CI safety

The fixtures used to validate the parsers are **frozen JSON**, not
live tool runs. CI does not download model weights, does not call
Hugging Face, and does not require any AI dependency at runtime.
Fixture refresh procedure lives in `tests/fixtures/ai/README.md` (to
be added when first refresh is needed). Every fixture carries the
tool version it was captured from so the parser stays pinned to a
specific schema.

## References

- NIST SP 800-218A — https://csrc.nist.gov/publications/detail/sp/800-218A/final
- OWASP Top 10 for LLM Applications (2025) — https://genai.owasp.org/llm-top-10/
- OWASP Top 10 for Agentic Applications (2026) — https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- garak — https://github.com/leondz/garak
- lm-evaluation-harness — https://github.com/EleutherAI/lm-evaluation-harness
- Hugging Face model cards — https://huggingface.co/docs/hub/model-cards
- Google Model Card Toolkit — https://github.com/tensorflow/model-card-toolkit
- ADR-0008 — [`docs/adr/0008-ai-evidence-types-and-provenance.md`](./adr/0008-ai-evidence-types-and-provenance.md)
