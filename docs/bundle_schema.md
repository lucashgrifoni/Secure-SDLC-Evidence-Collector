# Bundle schema reference

Bundle schema version: **`2.1.0`**

Top-level document produced by every `run` / `evaluate` invocation. All
timestamps are ISO 8601 UTC. All enum values serialize as their string form.

`bundle_version` versions the *contract*, not the tool, and it moves whenever
a bundle can no longer validate against the previous version. Because the
schema sets `additionalProperties: false` at every level, adding a field is
breaking even though it is additive: a validator pinned to `1.0.0` rejects a
bundle that carries anything it does not know.

`2.0.0` adds `collection_errors`. A bundle that hit no collection problem
omits the field entirely rather than emitting an empty list. When `2.0.0`
shipped, that kept a clean run valid against `1.0.0`; since `2.1.0` every
bundle carries `catalog`, so no bundle this version writes validates against
`1.0.0` any more, clean or not.

`2.1.0` adds `catalog`, naming the control catalog the evaluations were
produced against. Every verdict in a bundle is relative to a catalog and
`--catalog` lets you supply your own, so without this a bundle could not be
checked by whoever received it: the same evidence yields `not_ready` and exit
`2` against the shipped catalog and `conditional` and exit `0` against one
whose required evidence types have been moved to recommended. `verify
--expected` proves a bundle has not changed since it was generated; `catalog`
is what says against which standard. Unlike `collection_errors` it is never
omitted — there is no empty case worth hiding.

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
  "bundle_version": "2.1.0",
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
  "catalog": {
    "origin": "builtin",
    "name": "catalog.yaml",
    "sha256": "b34bf0f9f3eacef6634f01a6da267778965ef5a1d3eb45690376144f7da4ad08",
    "control_count": 13
  },
  "evidence": [ /* NormalizedEvidence[] */ ],
  "control_evaluations": [ /* ControlEvaluation[] */ ],
  "gaps": [ /* Gap[] */ ],
  "exceptions": [ /* EvidenceException[] */ ],
  "collection_errors": [ /* CollectionError[]; omitted when empty */ ],
  "summary": { /* Summary */ }
}
```

## Application

| Field | Type | Notes |
|---|---|---|
| `name` | string | `--application`. |
| `repository` | string | `--repository`, e.g. `acme/payments-api`. |
| `environment` | string | Defaults to `production`. |
| `owner_team` | string? | `--owner-team`, when given. |

## ReleaseContext

| Field | Type | Notes |
|---|---|---|
| `release_id` | string | `--release-id`. |
| `commit_sha` | string | 7 to 64 hex characters, normalized to lowercase. |
| `branch` | string | Defaults to `main`. |
| `pipeline_run_id`, `build_id`, `tag` | string? | Optional CI identifiers. |
| `artifact_digest` | string? | Digest of the published artifact, e.g. `sha256:...`. |

## CatalogRef

Which control catalog produced the evaluations. Present on every bundle this
version writes; absent on bundles written before `2.1.0`.

| Field | Type | Notes |
|---|---|---|
| `origin` | enum | `builtin` for a catalog shipped inside the package, `custom` for one loaded from a path you supplied. Decided by identity, not by filename: `catalog.yaml` is both the packaged default and the likeliest name for your own file. |
| `name` | string | Filename only, never a path. Which directory you keep a catalog in is the kind of detail `--artifact-root` exists to keep out of a published bundle. |
| `sha256` | string | SHA-256 of the catalog file's bytes as read, so `sha256sum` on the same file matches. Taken over the file rather than the parsed model: two YAML files differing only in key order or comments describe the same controls, and an auditor comparing against a published catalog is asking about the file. |
| `control_count` | int | How many controls the catalog defines. |

Inside the structural hash, so `verify --expected` rejects a bundle whose
catalog record has been edited.

## NormalizedEvidence

| Field | Type | Notes |
|-------|------|-------|
| `evidence_id` | string | Unique within the bundle. |
| `evidence_type` | enum | `sast_scan`, `sca_scan`, `secrets_scan`, `dast_scan`, `iac_scan`, `sbom`, `test_result`, `code_review`, `pr_metadata`, `workflow_run`, `threat_model`, `release_approval`, `rollback_plan`, `artifact_signature`, `artifact_attestation`, `generic_attestation`, `model_card`, `prompt_injection_test_result`, `ai_safety_eval`, `mcp_tool_inventory`, `ai_training_data_lineage`. |
| `source` | `EvidenceSource` | origin system (`name`, `kind`, `version`, `uri`). |
| `producer` | string | Human-readable tool or actor. |
| `subject_type` | enum | `repository`, `commit`, `pull_request`, `workflow_run`, `build`, `artifact`, `release`, `application`, `ai_model`, `ai_agent`, `ai_dataset`. |
| `subject_ref` | string | Stable identifier for the subject. |
| `status` | enum | `passed`, `failed`, `completed`, `generated`, `missing`, `invalid`, `unknown`. |
| `confidence` | enum | `high`, `medium`, `low`. Manual evidence is downgraded automatically. |
| `classification` | `EvidenceClassification?` | How `evidence_type` was decided. The built-in normalizers set it for SARIF, OSV / OSV-Scanner and native Trivy JSON records, and leave it `null` for every other format. Evidence passed in to `evaluate` keeps whatever value it carries. |
| `release_id`, `commit_sha` | string | Anchors the evidence to the release context. |
| `generated_at` | datetime? | When the producing tool generated the artifact, when known. ISO 8601 UTC. |
| `collected_at` | datetime | When the collector read it. ISO 8601 UTC. |
| `raw` | `RawEvidenceRef?` | `artifact_path` and/or `artifact_uri`, plus `integrity_hash` (`sha256:...`), `content_type` and `size_bytes`. |
| `findings_count` | `{ string: int }` | Aggregated counters (e.g. severity breakdown). |
| `summary` | string? | One-line description suitable for reports. |
| `metadata` | object | Opaque payload preserved for auditors. |
| `manual` | bool | `true` for attestations; influences confidence. |
| `cve_ids` | string[] | Distinct CVE IDs the parser could extract (SARIF tags, CycloneDX vulnerabilities). Empty when none apply. |
| `vulnerability_intelligence` | `VulnerabilityIntelligence?` | EPSS / CISA KEV summary for `cve_ids`. Only `sdlc-evidence enrich` sets it; `null` otherwise. |
| `reachability` | `Reachability?` | Upstream reachability verdict, stored as supplied; the collector never computes it. |

### EvidenceClassification

| Field | Type | Notes |
|---|---|---|
| `confidence` | enum | `high`, `medium`, `low`. |
| `reason` | string | `driver_match`, `manual_override` or `fallback_sast`; see [limitations §2](limitations.md). |
| `driver_name` | string? | The tool name the decision was based on: the SARIF driver name, the OSV tool name, or `trivy`. |

### VulnerabilityIntelligence

| Field | Type | Notes |
|---|---|---|
| `cve_count` | int | CVEs considered. |
| `max_epss_score`, `max_epss_percentile` | number? | Highest EPSS values, 0 to 1. |
| `cves_in_kev_count`, `cves_known_ransomware_count` | int | CVEs listed in CISA KEV, and those flagged for known ransomware use. |
| `top_risk_cves` | `TopRiskCve[]` | Highest-EPSS CVEs first: `cve_id`, `epss_score`, `epss_percentile`, `in_kev`, `known_ransomware`. |
| `epss_feed_date`, `kev_feed_date` | string? | `YYYY-MM-DD` of the feeds used. |
| `epss_model_version` | string? | EPSS model version from the feed header. |
| `enriched_at` | datetime? | When `enrich` ran; stripped before the structural hash. |

### Reachability

| Field | Type | Notes |
|---|---|---|
| `status` | string | `reachable`, `not_reachable` or `unknown`. |
| `source` | string | Tool or review that produced the verdict. |
| `method` | string | `data_flow`, `function_call` or `manual_review` (default). |
| `evidence_ref` | string? | Pointer to the supporting evidence. |

## ControlEvaluation

| Field | Type | Notes |
|-------|------|-------|
| `control_id`, `control_name` | string | Maps to the control catalog. |
| `framework` | enum | `NIST_SSDF`, `OWASP_SAMM`, `ORG_INTERNAL`. |
| `evaluation_status` | enum | `met`, `partial`, `missing`, `waived`, `not_applicable`. |
| `criticality` | enum | `critical`, `high`, `medium`, `low`. Drives release gate. |
| `evidence_refs` | string[] | IDs of `NormalizedEvidence` satisfying the control. |
| `missing_required_evidence_types` | enum[] | What is still missing as required. |
| `missing_recommended_evidence_types` | enum[] | Non-blocking gaps. |
| `confidence` | enum | Lowest supporting confidence, downgraded if any supporting evidence is manual. |
| `rationale` | string | Human-readable explanation of the verdict. |
| `evaluated_at` | datetime | When the engine ran. |
| `exception_refs` | string[] | `exception_id` of every waiver in force for this control (matching scope, inside its approval window). Each entry must match an entry in the top-level `exceptions`. |

Every required evidence type needs at least one record with status
`passed`, `completed` or `generated`. A record with any other status,
such as `failed` or `invalid`, does not satisfy the control and counts
as missing. When every required type is satisfied the control is `met`,
or `partial` if a recommended type is not. A record of a required or
recommended type that did not satisfy never changes the verdict and is
not in `evidence_refs`. A `met` or `partial` rationale names each such
record with its status, ending with a sentence such as `Evidence
promptfoo-1a4d6017fd82 (failed) of type ai_safety_eval did not count.`
A `missing` rationale says that records of a missing required type are
present but did not satisfy the control. Types with no record at all are
still reported as "missing required evidence types". A `waived`
rationale names the exception, not the records.

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
| `risk_assessment` | `RiskAssessment?` | Present only when the bundle was built with `--risk-mode epss-weighted`; `null` with the default `off`. |

### RiskAssessment

| Field | Type | Notes |
|---|---|---|
| `mode` | string | `epss-weighted`. |
| `epss_percentile_threshold` | number | 0 to 1; EPSS percentile at or above which a CVE counts as exploitable. |
| `kev_blocks` | bool | Whether a KEV-listed CVE with known ransomware use forces `not_ready`. |
| `exploitable_cve_count`, `kev_cve_count`, `kev_ransomware_cve_count`, `high_epss_cve_count` | int | Counters the verdict was derived from. |
| `base_release_status` | enum | The presence-based verdict before the risk mode applied. The mode only ever makes it worse. |
| `rationale` | string | Short explanation; at most 400 characters. |

## EvidenceException

Top-level `exceptions` lists every waiver loaded from `--exceptions-dir`,
whether or not it applied to this release. Which ones did apply is recorded
per control in `exception_refs`.

| Field | Type | Notes |
|---|---|---|
| `exception_id` | string | Unique within the bundle. |
| `control_id` | string | Control the waiver covers. |
| `approver` | string | Who approved it. |
| `approved_at`, `expires_at` | datetime | Timezone required; `expires_at` must be after `approved_at`. |
| `justification` | string | At least 10 characters. |
| `reference` | string? | Ticket or document where the waiver was recorded. |
| `scope` | object | Optional `application` and `release_id`; an unset field matches any value. |

## CollectionError

Top-level `collection_errors` lists inputs that were supplied but could not be
ingested (unreadable, malformed, oversized), and evidence anchored to a
different commit than the release. The key is omitted when the list is empty.

| Field | Type | Notes |
|---|---|---|
| `path` | string | The input concerned, at most 500 characters. |
| `reason` | string | Why it was not ingested, at most 1000 characters. |

## Invariants enforced by the schema

- `NormalizedEvidence.evidence_id` is unique across the bundle, so a
  reference resolves to exactly one record,
- every `ControlEvaluation.evidence_refs` entry must match an existing
  `NormalizedEvidence.evidence_id` in the bundle,
- `EvidenceException.exception_id` is unique, and every
  `ControlEvaluation.exception_refs` entry must match one,
- `Summary` control counters must sum to `total_controls`,
- `commit_sha` is normalized to lowercase hex; non-hex input is rejected,
- manual evidence cannot carry `confidence = high` (downgraded to `medium`),
- `RawEvidenceRef` requires at least one of `artifact_path` or `artifact_uri`,
- `ControlDefinition` must declare at least one required or recommended
  evidence type.
