# Secure SDLC Evidence Collector

[![CI](https://img.shields.io/badge/ci-github--actions-blue)](./.github/workflows/ci.yml)
![Python 3.12](https://img.shields.io/badge/python-3.12-blue)
![License Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-green)

**CLI-first AppSec/DevSecOps tool that answers: "Which evidence proves this
release followed a minimum Secure SDLC process?"**

The Secure SDLC Evidence Collector collects, normalizes, evaluates, and
packages engineering-native evidence (SAST/SCA/secrets scans, SBOM, tests,
code review, attestations, release approvals, rollback plans, artifact
signatures, GitHub Actions runs) into a single, auditable bundle per release.
It then emits a **release readiness verdict** — `ready`, `conditional`, or
`not_ready` — backed by explicit gaps and lineage, not by opinion.

> The tool does not claim "compliance automatic." It reports which controls
> have evidence, which rely on human interpretation, and which remain
> unproven — with rationale you can audit.

---

## Why this exists

Organizations run Semgrep, Trivy, CycloneDX, JUnit, PR reviews, CAB approvals
and Actions workflows every day, but the evidence is scattered across tools.
When an auditor, a release manager, or an AppSec Lead asks "prove this
release is ready," the answer is usually a checklist full of screenshots.

This collector reframes the question around **evidence, not findings**:

- consolidates engineering signals into a canonical schema,
- maps them to a small, strong Secure SDLC control set (NIST SSDF + org),
- produces a **deterministic** `bundle.json`, a human-readable `report.md`,
  and a stakeholder-friendly `summary.html`,
- ships a release gate exit code for pipelines.

---

## Feature overview

| Capability | Implementation |
|-----------|----------------|
| Evidence ingestion | SARIF (Semgrep, CodeQL, SonarQube, Snyk Code, Trivy, Grype, Gitleaks, …), CycloneDX & SPDX SBOMs, JUnit XML, YAML/JSON attestations |
| GitHub integration | PR approvals + "last approval after last commit" correctness, GitHub Actions workflow runs |
| Controls catalog | 10 Secure SDLC controls mapped to NIST SSDF and org-internal IDs, override via `--catalog` |
| Scoring | Deterministic coverage score + confidence score, explainable rationale per control |
| Release verdict | `ready` / `conditional` / `not_ready` driven by criticality of gaps, not by the score alone |
| Outputs | `bundle.json` (byte-stable), `report.md`, `summary.html` |
| CLI | `run`, `collect`, `evaluate`, `bundle`, `controls` (Typer + rich) |
| Quality bar | `ruff`, `mypy --strict`, `pytest` with 70% coverage gate, GitHub Actions CI |

---

## Architecture at a glance

```
┌──────────────┐   ┌────────────┐   ┌─────────────┐   ┌──────────────┐
│  collectors  │──▶│  parsers   │──▶│ normalizers │──▶│   controls   │
│ local/github │   │ SARIF/SBOM │   │  canonical  │   │  evaluation  │
└──────────────┘   │ JUnit/YAML │   │  evidence   │   │    engine    │
                   └────────────┘   └─────────────┘   └──────┬───────┘
                                                             ▼
                                           ┌─────────────────────────┐
                                           │  scoring + release_status│
                                           └────────────┬────────────┘
                                                        ▼
                                             ┌──────────────────┐
                                             │ exporters JSON / │
                                             │     MD / HTML    │
                                             └──────────────────┘
```

- **Domain** (`src/evidence_collector/domain/`) — Pydantic v2 entities, enums,
  invariants. Zero framework / IO dependencies.
- **Parsers** — format readers; return plain dataclasses.
- **Normalizers** — build `NormalizedEvidence` from parsed artifacts.
- **Collectors** — drive file-system and GitHub ingestion.
- **Controls / scoring** — evaluate the canonical set against the control
  catalog and compute coverage/confidence/release_status.
- **Exporters** — Jinja2 templates for Markdown/HTML; stable JSON output.
- **CLI** (`cli/main.py`) — the primary entrypoint, thin wrapper over
  `application/orchestrator.py`.

---

## Install

```bash
python -m pip install -e ".[dev]"
```

Requires Python 3.12+.

The console-script `sdlc-evidence` is installed automatically.

### Smoke test (one command)

```bash
python -m evidence_collector.cli.main run \
    --application payments-api \
    --repository acme/payments-api \
    --release-id 2026.04.10 \
    --commit-sha abcdef1234567890 \
    --branch main \
    --artifacts-dir examples/sample_release/artifacts \
    --attestations-dir examples/sample_release/attestations \
    --output-dir output/sample_release
```

Expected verdict: `release_status = ready`, coverage 100/100, 10/10 controls
met, `bundle.json`, `report.md`, `summary.html` in `output/sample_release/`.

Drop the `--attestations-dir` flag to see `release_status = not_ready` with
explicit missing critical evidence.

---

## CLI

```
sdlc-evidence run        # full pipeline: collect + evaluate + export
sdlc-evidence collect    # walk directories, emit an evidence JSON list
sdlc-evidence evaluate   # evaluate an existing evidence list, export bundle
sdlc-evidence bundle     # alias of evaluate
sdlc-evidence controls   # print the active control catalog
sdlc-evidence --version
```

Every command exits `0` when the release status meets `--fail-on`, `2` when
the release is `not_ready`, `1` when `conditional`. This makes the CLI a
drop-in gate in any pipeline.

### Release context (required on `run`)

- `--application` · `--repository` · `--release-id` · `--commit-sha`
- optional: `--branch`, `--environment`, `--owner-team`, `--pipeline-run-id`,
  `--build-id`, `--artifact-digest`, `--tag`

### Ingestion options

- `--artifacts-dir PATH` — folder with SARIF, SBOM, JUnit files
  (repeatable).
- `--attestations-dir PATH` — folder with YAML/JSON attestations
  (repeatable).
- `--catalog FILE.yaml` — override the default control catalog.

### GitHub integration (opt-in)

```bash
export GITHUB_TOKEN=ghp_...
sdlc-evidence run \
  --application payments-api \
  --repository acme/payments-api \
  --release-id 2026.04.10 \
  --commit-sha abcdef1234567890 \
  --pull-request 184 \
  --workflow-run 1001 \
  --artifacts-dir artifacts \
  --output-dir output
```

The GitHub collector never logs tokens and reads them from environment only.

---

## Control catalog

The default catalog ships with 10 controls covering SAST, SCA, secrets
scanning, SBOM, tests, code review, threat model, release approval,
rollback plan, and artifact signing. They are mapped to NIST SSDF practices
when applicable (PS.2/PS.3/PW.1/PW.4/PW.7/PW.8) and to org-internal IDs for
everything else.

Inspect it with `sdlc-evidence controls`, or replace it with your own via
`--catalog path/to/your_catalog.yaml`. Schema:

```yaml
controls:
  - control_id: "MY-ORG-1"
    framework: "ORG_INTERNAL"
    name: "..."
    description: "..."
    criticality: "critical|high|medium|low"
    required_evidence_types: ["sast_scan", "sca_scan", ...]
    recommended_evidence_types: ["pr_metadata", ...]
```

### Evidence types (enum)

`sast_scan`, `sca_scan`, `secrets_scan`, `dast_scan`, `sbom`, `test_result`,
`code_review`, `pr_metadata`, `workflow_run`, `threat_model`,
`release_approval`, `rollback_plan`, `artifact_signature`,
`artifact_attestation`, `generic_attestation`.

---

## Release status rules

| Rule | Verdict |
|------|---------|
| Every critical & high control has required evidence | `ready` |
| Only recommended evidence is missing, or medium-criticality controls lack evidence | `conditional` |
| A critical control lacks required evidence | `not_ready` |

Release status is **derived from the criticality of gaps**, never from the
numeric score, so a cosmetic "high score" cannot override a missing
critical control. Scores exist only to signal coverage direction over time.

---

## Repository layout

```
src/evidence_collector/
  domain/         # Pydantic entities, enums, invariants
  application/    # end-to-end orchestrator
  collectors/     # local filesystem + github adapters
  parsers/        # SARIF, SBOM, JUnit, attestation readers
  normalizers/    # parsed artifact -> NormalizedEvidence
  controls/       # catalog loader + evaluation engine (data/catalog.yaml)
  scoring/        # coverage/confidence/release-status computation
  exporters/      # JSON/MD/HTML exporters + Jinja2 templates
  cli/            # Typer CLI entrypoint
tests/
  unit/           # models, parsers, normalizers, controls, scoring, exporters
  integration/    # orchestrator + CLI end-to-end, sample-release fixtures
examples/
  sample_release/ # realistic evidence set used in docs and tests
.github/
  workflows/ci.yml  # lint + types + tests + sample bundle job
```

---

## Development

```bash
make install-dev
make lint          # ruff check
make format        # ruff format + fix
make typecheck     # mypy --strict on src/
make test          # pytest with coverage gate (>=70%)
make run-example   # generate the sample bundle
```

The repository ships `.pre-commit-config.yaml` for local hooks (optional).

---

## Security posture

The tool itself follows the security rules it enforces on others:

- no hardcoded secrets; `GITHUB_TOKEN` read from the environment and never
  logged,
- 25 MB safety cap per ingested artifact to avoid resource exhaustion,
- strict Pydantic schema (`extra='forbid'`) on every canonical type —
  unexpected fields in an attestation or bundle are a hard error,
- deterministic JSON serialization so audit integrity hashes are stable,
- XML parsing without external entity resolution,
- no PR body, reviewer email, or token ever written to logs.

---

## Roadmap (post-MVP)

- GitLab / Azure DevOps collectors
- Exception / waiver workflow with approver + expiration
- Historical analytics (coverage over time per repo/team)
- `evidence_exception` first-class entity in the bundle
- API surface (FastAPI) once the CLI is stable

---

## License

[Apache-2.0](./LICENSE) © Lucas Henrique Grifoni.
