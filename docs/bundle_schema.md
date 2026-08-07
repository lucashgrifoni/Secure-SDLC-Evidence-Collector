# Bundle schema reference

Bundle schema version: **`2.0.0`**

Top-level document produced by every `run` / `evaluate` invocation. All
timestamps are ISO 8601 UTC. All enum values serialize as their string form.

`bundle_version` versions the *contract*, not the tool, and it moves whenever
a bundle can no longer validate against the previous version. Because the
schema sets `additionalProperties: false` at every level, adding a field is
breaking even though it is additive: a validator pinned to `1.0.0` rejects a
bundle that carries anything it does not know.

`2.0.0` adds `collection_errors`. A bundle that hit no collection problem
omits the field entirely rather than emitting an empty list, so a clean run
still validates against `1.0.0` and only bundles that genuinely report a
failed input require the newer contract.

## Machine-readable schema

A self-describing JSON Schema (Draft 2020-12, with `$schema` and `$id`) for the
`EvidenceBundle` is published at a stable URL:

```
https://lucashgrifoni.github.io/Secure-SDLC-Evidence-Collector/docs/evidence-bundle.schema.json
```

It is generated from the Pydantic models and committed at
[`docs/evidence-bundle.schema.json`](evidence-bundle.schema.json); a test gate
fails CI if it ever drifts. Regenerate it locally with:

```bash
sdlc-evidence schema --output docs/evidence-bundle.schema.json
```

Associate it with your bundle files in your editor to get live validation — do
this **externally**, never by adding a `$schema` key inside a bundle: the
contract sets `additionalProperties: false` (and the model forbids extras), so
any unknown top-level member would fail validation. In VS Code, map the schema
in `.vscode/settings.json`:

```json
{
  "json.schemas": [
    {
      "fileMatch": ["**/bundle.json", "**/*.evidence-bundle.json"],
      "url": "https://lucashgrifoni.github.io/Secure-SDLC-Evidence-Collector/docs/evidence-bundle.schema.json"
    }
  ]
}
```

Most editors also auto-associate schemas published on
[SchemaStore](https://www.schemastore.org/) by filename, with no per-repo
configuration, once the contract is registered there.

```jsonc
{
  "bundle_version": "2.0.0",
  "bundle_id": "bundle-20260410-payments-api-2026.04.10-ab12cd34",
  "generated_at": "2026-04-10T12:20:00Z",
  "application": {
    "name": "payments-api",
    "repository": "acme/payments-api",
    "environment": "production",
    "owner_team": "payments-core"
  },
  "release": {
    "release_id": "2026.04.10",
    "commit_sha": "abc123...",
    "branch": "main",
    "pipeline_run_id": "gha-93821",
    "build_id": "build-2041",
    "artifact_digest": "sha256:...",
    "tag": "v2026.04.10"
  },
  "evidence": [ /* NormalizedEvidence[] */ ],
  "control_evaluations": [ /* ControlEvaluation[] */ ],
  "gaps": [ /* Gap[] */ ],
  "summary": { /* Summary */ }
}
```

## NormalizedEvidence

| Field | Type | Notes |
|-------|------|-------|
| `evidence_id` | string | Unique within the bundle. |
| `evidence_type` | enum | See `EvidenceType`. |
| `source` | `EvidenceSource` | origin system (`name`, `kind`, `version`, `uri`). |
| `producer` | string | Human-readable tool or actor. |
| `subject_type` | enum | `repository`, `commit`, `pull_request`, `workflow_run`, `build`, `artifact`, `release`, `application`. |
| `subject_ref` | string | Stable identifier for the subject. |
| `status` | enum | `passed`, `failed`, `completed`, `generated`, `missing`, `invalid`, `unknown`. |
| `confidence` | enum | `high`, `medium`, `low`. Manual evidence is downgraded automatically. |
| `release_id`, `commit_sha` | string | Anchors the evidence to the release context. |
| `generated_at`, `collected_at` | datetime | ISO 8601 UTC. |
| `raw` | `RawEvidenceRef?` | `artifact_path` + `integrity_hash` for audit. |
| `findings_count` | `{ string: int }` | Aggregated counters (e.g. severity breakdown). |
| `summary` | string | One-line description suitable for reports. |
| `metadata` | object | Opaque payload preserved for auditors. |
| `manual` | bool | `true` for attestations; influences confidence. |

## ControlEvaluation

| Field | Type | Notes |
|-------|------|-------|
| `control_id`, `control_name`, `framework` | string | Maps to the control catalog. |
| `evaluation_status` | enum | `met`, `partial`, `missing`, `waived`, `not_applicable`. |
| `criticality` | enum | `critical`, `high`, `medium`, `low`. Drives release gate. |
| `evidence_refs` | string[] | IDs of `NormalizedEvidence` satisfying the control. |
| `missing_required_evidence_types` | enum[] | What is still missing as required. |
| `missing_recommended_evidence_types` | enum[] | Non-blocking gaps. |
| `confidence` | enum | Lowest supporting confidence, downgraded if any supporting evidence is manual. |
| `rationale` | string | Human-readable explanation of the verdict. |
| `evaluated_at` | datetime | When the engine ran. |
| `exception_refs` | string[] | Reserved for Phase 2 exception workflow. |

## Gap

| Field | Type | Notes |
|-------|------|-------|
| `control_id` | string | Control whose evidence is missing or weak. |
| `evidence_type` | enum? | Specific evidence type, when known. |
| `criticality` | enum | Inherited from the control (or `low` for recommended-only gaps). |
| `description` | string | Why the evidence is considered missing. |
| `remediation` | string | How to satisfy the gap. |

## Summary

| Field | Type | Notes |
|-------|------|-------|
| `evidence_coverage_score` | 0–100 | Ratio of earned/total weight across required + recommended evidence. |
| `confidence_score` | 0–100 | Average of `confidence` across satisfied evaluations. |
| `release_status` | enum | `ready`, `conditional`, `not_ready`. |
| `missing_critical_evidence` | string[] | `control_id:evidence_type` pairs for critical/high gaps. |
| `total_controls` / `controls_met` / `controls_partial` / `controls_missing` / `controls_waived` / `controls_not_applicable` | int | Counters validated against `total_controls`. |

## Invariants enforced by the schema

- `NormalizedEvidence.evidence_id` is unique across the bundle, so a
  reference resolves to exactly one record,
- every `ControlEvaluation.evidence_refs` entry must match an existing
  `NormalizedEvidence.evidence_id` in the bundle,
- `Summary` control counters must sum to `total_controls`,
- `commit_sha` is normalized to lowercase hex; non-hex input is rejected,
- manual evidence cannot carry `confidence = high` (downgraded to `medium`),
- `RawEvidenceRef` requires at least one of `artifact_path` or `artifact_uri`,
- `ControlDefinition` must declare at least one required or recommended
  evidence type.
