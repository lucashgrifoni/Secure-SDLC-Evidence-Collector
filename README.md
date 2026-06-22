# Secure SDLC Evidence Collector

[![CI](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/actions/workflows/github-ci-cd.yml/badge.svg)](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/actions/workflows/github-ci-cd.yml)
[![Security CI](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/actions/workflows/security-ci-cd.yml/badge.svg)](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/actions/workflows/security-ci-cd.yml)
[![PyPI](https://img.shields.io/pypi/v/secure-sdlc-evidence-collector)](https://pypi.org/project/secure-sdlc-evidence-collector/)
![Python 3.12 & 3.13](https://img.shields.io/badge/python-3.12%20%7C%203.13-blue)
![License Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-green)
[![Cosign signing configured](https://img.shields.io/badge/release%20signing-cosign%20keyless%20(configured)-9cf)](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/actions/workflows/publish-pypi.yml)
<!--
  T6.C1 — OpenSSF Best Practices Badge (passing tier). After the
  maintainer completes the self-assessment at https://www.bestpractices.dev/
  and the project receives its public project ID (PROJECT_ID), replace
  the placeholder below with:
    [![OpenSSF Best Practices](https://www.bestpractices.dev/projects/PROJECT_ID/badge)](https://www.bestpractices.dev/projects/PROJECT_ID)
  Tracking for the public project ID lives in the maintainer issue queue.
-->
![OpenSSF Best Practices (registration pending)](https://img.shields.io/badge/openssf%20best%20practices-registration%20pending-lightgrey)

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
| Evidence ingestion | SARIF (Semgrep, CodeQL, SonarQube, Snyk Code, Trivy, Grype, Gitleaks, Bandit, pip-audit, …), CycloneDX & SPDX SBOMs, OSV / OSV-Scanner, JUnit XML, OWASP ZAP JSON (DAST), in-toto SLSA VSA (Verification Summary Attestation), YAML/JSON attestations and exceptions |
| SCM integrations | GitHub (PR approvals with "last approval after last commit" verification, Actions runs) and GitLab (MR approvals, pipeline runs) |
| Controls catalog | 13 controls mapped to NIST SSDF, OWASP SAMM and org-internal IDs; override via `--catalog` |
| Scoring | Deterministic coverage + confidence scores with per-control rationale |
| Release verdict | `ready` / `conditional` / `not_ready` driven by gap criticality, never by the score alone |
| Waivers | Time-bound exceptions with scope (application/release) and expiry — plain YAML/JSON, auditable |
| Outputs | Deterministic `bundle.json`, Jinja2 `report.md`, and `summary.html` |
| CLI | `run` · `collect` · `evaluate` · `bundle` · `controls` · `compare` · `oscal` · `plugins` · `schema` · `doctor` · `verify` · `enrich` · `vex` · `statement` · `guac` · `exceptions list/validate` |
| Packaging | Reusable GitHub Action (`action.yml`), non-root Docker image, wheel + sdist build verified locally; published to PyPI as [`secure-sdlc-evidence-collector`](https://pypi.org/project/secure-sdlc-evidence-collector/) via OIDC Trusted Publisher. |
| Release integrity | `publish-pypi.yml` is configured to perform cosign keyless signing + Sigstore Rekor transparency log + SLSA Build Level 3 provenance on tag push. `2.0.0` was the first public release; the current published version is shown by the PyPI badge above (the v1.1.0 cut prepared in code stayed internal, and the Tier 5/Tier 6 work landed on top, so SemVer required the 2.0 line). |
| Quality bar | `ruff`, `mypy --strict`, `pytest` with coverage gate, GitHub Actions CI, Dependabot |

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

Install the published package from PyPI (recommended for most users):

```bash
python -m pip install secure-sdlc-evidence-collector
```

Or install from a clone for development:

```bash
git clone https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector.git
cd Secure-SDLC-Evidence-Collector
python -m pip install -e ".[dev]"
```

Requires Python 3.12+. The console-script `sdlc-evidence` is installed
automatically.

📖 **Documentation:** the full docs site is published at
<https://lucashgrifoni.github.io/Secure-SDLC-Evidence-Collector/docs/>.
To run the collector inside a pipeline, see
[Using the GitHub Action](./docs/github_action.md).

### Smoke test (one command)

This smoke test uses the bundled `examples/sample_release/` fixtures, so run
it from a clone of the repository. If you installed from PyPI, the
`sdlc-evidence` console script is equivalent to
`python -m evidence_collector.cli.main`.

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

Expected verdict: `release_status = ready`, coverage 100/100, 13/13 controls
met, `bundle.json`, `report.md`, `summary.html` in `output/sample_release/`.

Drop the `--attestations-dir` flag to see `release_status = not_ready` with
explicit missing critical evidence.

---

## CLI

```
sdlc-evidence run                    # full pipeline: collect + evaluate + export
sdlc-evidence collect                # walk directories, emit an evidence JSON list
sdlc-evidence evaluate               # evaluate an existing evidence list, export bundle
sdlc-evidence bundle                 # alias of evaluate
sdlc-evidence controls               # print the active control catalog
sdlc-evidence compare BEFORE AFTER   # diff two bundles (coverage, status, per-control)
sdlc-evidence oscal [--output PATH]  # render the control catalog as OSCAL Catalog JSON
sdlc-evidence plugins                # list parser and collector entry-point plugins
sdlc-evidence schema [--output PATH] # emit JSON Schema for EvidenceBundle
sdlc-evidence doctor [--json]        # run local environment health checks
sdlc-evidence verify BUNDLE          # recompute (and optionally verify) a bundle's structural SHA-256
sdlc-evidence enrich BUNDLE          # attach EPSS + CISA KEV intelligence to a bundle
sdlc-evidence vex BUNDLE             # emit an OpenVEX document from a bundle
sdlc-evidence statement BUNDLE       # wrap a bundle as an in-toto Statement v1
sdlc-evidence guac BUNDLE [-o PATH]  # emit a GUAC-collector container from a bundle
sdlc-evidence exceptions validate F  # validate a single waiver file
sdlc-evidence exceptions list DIR    # list every valid waiver in a directory
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
- `--artifact-root PATH` — base directory that absolute artifact paths
  are rewritten against, so the bundle records repo-relative paths
  instead of leaking local filesystem locations. Recommended in CI.

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

The default catalog ships with **13 controls** covering SAST, SCA, secrets
scanning, SBOM, tests, code review, threat model, release approval, rollback
plan, artifact signing, and three OWASP SAMM practices (Threat Assessment,
Secure Build, Security Testing). They are mapped to NIST SSDF practices when
applicable (PS.2/PS.3/PW.1/PW.4/PW.7/PW.8), to OWASP SAMM practice IDs
(DESIGN-TA-1, IMPL-SB-2, VERIF-ST-1), and to org-internal IDs for everything
else.

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
  workflows/
    github-ci-cd.yml        # lint + types + tests + build + sample bundle
    security-ci-cd.yml      # semgrep + pip-audit + trivy + actionlint
    publish-pypi.yml             # quality gates, build, cosign keyless, GitHub Release
    deploy-github-pages.yml # regenerate the dogfood summary site
```

---

## Development

```bash
make install-dev
make lint          # ruff check on src, tests and scripts
make format        # ruff format + fix
make typecheck     # mypy --strict on src/ and tests/
make test          # pytest with coverage gate (>=85%)
make run-example   # generate the sample bundle
```

The repository ships `.pre-commit-config.yaml` for local hooks (optional).

---

## Validation and evidence

The collector is dogfooded on every push and on every release:

- **`examples/sample_release/`** — synthetic but realistic positive fixture
  (Semgrep + Trivy + Gitleaks SARIF, CycloneDX SBOM, JUnit, ZAP baseline,
  YAML attestations). Expected verdict `ready`, 13/13 controls met.
- **`examples/self_release/`** — dogfood attestation templates and commands
  for the collector's own pipeline evidence. Generated scanner outputs and
  release bundles are intentionally ignored instead of committed.
- **`examples/labs/`** — lab scenario documentation and regeneration scripts
  for the external vulnerable-app suite. Raw scanner dumps, logs, SBOMs, and
  bundles are generated locally or in CI and intentionally not committed.
- **Release readiness checklist** — go/no-go criteria for public releases
  live in [`docs/release-readiness.md`](./docs/release-readiness.md).
- **Known limitations** — parser scope, heuristics, and classification
  boundaries are documented in [`docs/limitations.md`](./docs/limitations.md).

Bundle comparison across runs is available via `sdlc-evidence compare
before.json after.json` and is used in CI to catch regressions.

---

## What the collector does **not** do

- It does **not** scan source code, containers, or infrastructure. It
  reads the output of tools that do (Semgrep, CodeQL, Trivy, Gitleaks,
  Syft, ZAP, JUnit, …) and evaluates whether the evidence set satisfies
  the control catalog.
- It does **not** replace compliance decisions. A `ready` verdict means
  "every required critical/high control has evidence attached", not "this
  release is legally compliant".
- It does **not** re-run scanners or assert findings severity. Severity
  and exploitability interpretation remain a human judgement on top of
  the bundle.
- It classifies SARIF results into `sast_scan` / `sca_scan` /
  `secrets_scan` by the driver tool's name. Ambiguous drivers (e.g. a
  Trivy SARIF that mixes vuln and secret scans) default to the more
  conservative label; edge cases are listed in `docs/limitations.md`.

---

## Security posture

> **Reporting a vulnerability.** Please do **not** open a public GitHub
> issue. Email [lucas.henriquegrifoni@gmail.com](mailto:lucas.henriquegrifoni@gmail.com)
> with a subject line starting `[secure-sdlc-evidence-collector]`. Full
> policy, response SLA, and disclosure timeline live in
> [`SECURITY.md`](./SECURITY.md).

The tool itself follows the security rules it enforces on others:

- no hardcoded secrets; `GITHUB_TOKEN` read from the environment and never
  logged,
- 25 MB safety cap per ingested artifact to avoid resource exhaustion,
- strict Pydantic schema (`extra='forbid'`) on every canonical type —
  unexpected fields in an attestation or bundle are a hard error,
- **structurally deterministic** JSON: the bundle is byte-stable across
  runs once the four evaluation-time fields (`bundle_id`, `generated_at`,
  per-evidence `collected_at`, per-control `evaluated_at`) are stripped.
  Integrity hashes, evidence ordering, control verdicts, gaps, and
  scores are byte-stable. Enforced by a CI gate that re-runs the sample
  pipeline and compares normalized SHA-256.
- XML parsing without external entity resolution,
- no PR body, reviewer email, or token ever written to logs.

---

## Roadmap

### Shipped in `1.0.0`

- GitLab / GitLab CI collector (MRs + pipelines).
- OWASP SAMM secondary framework mapping.
- OWASP ZAP DAST parser and `dast_scan` evidence type.
- Time-bound exception (waiver) workflow with scope and expiry.
- Bundle `compare` command and canonical JSON Schema export.
- OSS governance (CONTRIBUTING, CoC, SECURITY, CODEOWNERS, Dependabot,
  issue/PR templates).

### Shipped in `1.1.0`

Tier 1-4 maturity work. **Configured in code or workflow** — every
externally verifiable signal (signed assets on PyPI / GHCR, public
Scorecard score, CodeQL alerts on the Security tab) materialises only
after a public release runs end-to-end against the configured GitHub,
PyPI, GHCR, and OpenSSF project surfaces.

- OpenSSF Scorecard, native CodeQL, expanded `pre-commit`,
  structural-determinism gate, `sdlc-evidence doctor` health check.
- `publish-pypi.yml` configured with SLSA Build Level 3 provenance via
  `slsa-github-generator`, cosign keyless signing of wheel/sdist/bundle/SBOM,
  collector self-SBOM (CycloneDX), multi-arch (amd64+arm64) container
  image to `ghcr.io` signed and SBOM-attested with cosign.
- Property-based testing (Hypothesis), 5 ADRs, public threat model,
  mkdocs-material site at `/docs/`, CI matrix Python 3.12 + 3.13.
- Plugin entry-point system, optional FastAPI read-only surface,
  OSCAL exporter, `release-please` workflow.

### Shipped in `2.0.0`

Tier 6 — standards-alignment cut, and the first public release line.

- CycloneDX 1.7 parser; OSV / OSV-Scanner parser; in-toto Statement v1
  predicate-type variants (witness / evidence-bundle / slsa-provenance);
  SSDF 1.2 opt-in catalog.
- AI evidence track: 5 evidence types, 3 parsers (garak / lm-eval /
  model-card), AI catalog mapped to NIST SP 800-218A + OWASP LLM /
  Agentic Top 10.
- Risk-weighted verdict (`--risk-mode epss-weighted`); multi-VEX
  consumer; optional reachability field.
- EU CRA + FedRAMP 20x profiles + FedRAMP 20x KSI catalog; GUAC adapter.
- Reproducible wheel gate, reusable GitHub Actions workflow, GitLab CI
  template, devcontainer + Codespaces, comparison page, ADRs 0007–0012.

### Deferred to `2.1`

- `sdlc-evidence watch` daemon (see `docs/limitations.md`).
- SPDX VEX consumer (low industry adoption today).
- IaC scan as its own `evidence_type`.
- `compare --policy` (Rego for acceptable regression).
- Sigstore policy-controller recipe.
- OpenTelemetry tracing via the `[otel]` extra.

### Considered for future versions

These are open ideas, not commitments — none has design, ADR, or
scheduled milestone behind it yet. They are listed so users can see
the direction of travel and open a Discussion if any becomes
load-bearing for their use case.

- Azure DevOps collector (PRs + Pipelines).
- Historical analytics (coverage trend per repo/team) and a read-only
  dashboard over saved bundles.
- Additional exporters (SPDX provenance, CycloneDX VEX linking).
- Policy-as-code catalog validation (e.g. Rego plug-in).

---

## License

[Apache-2.0](./LICENSE) © Lucas Henrique Grifoni.
