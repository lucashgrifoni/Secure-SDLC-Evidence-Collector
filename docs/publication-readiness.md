# Public repository readiness gate

Target publication date: **2026-06-05**  
Current status: **NO-GO until every mandatory gate below has evidence**  
Scope: public exposure of the repository, not only a package release.

This gate supersedes the older 2026-05-01 publication target. The repository
must not be made public because a calendar date arrived. It can be made public
only when the evidence proves that the project is functional, mature,
reproducible, secure, documented, stable, usable, and maintainable after
publication.

## Project-specific interpretation

The original checklist uses the word `profiles`. This project does not have
profiles. For this repository, the equivalent public-readiness scope is:

- the 13 bundled controls in `src/evidence_collector/controls/data/catalog.yaml`;
- the evidence types accepted by the parsers and normalizers;
- the CLI commands exposed by `sdlc-evidence`;
- the optional read-only API surface;
- the GitHub Action contract in `action.yml`;
- the sample, self-release, and lab fixtures under `examples/`;
- the GitHub Actions workflows and release pipeline;
- the public documentation and governance files.

Do not create new controls, evidence types, CLI flags, schemas, or profiles just
to satisfy this gate. If a gap requires a new product capability, record it as
a future conceptual gap and do not represent it as implemented.

## Absolute go/no-go rule

The publication decision is `GO` only if all P0 and P1 items in this document
are complete and linked to evidence.

The decision is `NO-GO` when any of these are true:

- any critical bug is open;
- any exposed secret, token, private path, or sensitive sample data is found;
- any primary CLI flow is broken;
- any public claim lacks a matching test, fixture, limitation, or evidence link;
- any required control or capability has no positive and negative validation;
- the clean setup path fails on a fresh environment;
- the Docker image cannot be built and smoke-tested;
- security scans fail without a documented and accepted exception;
- GitHub/PyPI/GHCR/release external setup remains unvalidated;
- the repository still contains dead scratch files, generated caches, or local
  author-only artifacts.

`GO WITH CAVEATS` is allowed for internal hardening, but not for turning the
repository public unless every caveat is explicitly accepted as non-blocking in
this document and in `docs/limitations.md`.

## Required evidence index

Before publication, create or refresh an evidence record for each row below.
The evidence can be a command output, CI run URL, generated bundle, fixture,
test name, GitHub/PyPI API result, or documentation link.

| Gate | Required evidence | Blocking level |
|---|---|---|
| Full project functionality | Local and CI run covering CLI, examples, schema, OSCAL, plugins, doctor, exceptions, GitHub Action, and optional API imports | P0 |
| Control maturity | Traceability matrix covering all 13 controls and every required/recommended evidence type | P0 |
| False-positive control | Documented definition of false positive for this tool plus regression cases for misleading `ready`, wrong evidence type, and incorrect control status | P0 |
| External lab validation | Current run or recorded artifacts from `App vuln - teste`, mapped in `docs/traceability.md` | P0 |
| Per-control scenario coverage | Positive, negative, edge, regression, misuse, incomplete config, and conflicting config cases per relevant capability | P0 |
| Promise-to-delivery traceability | Matrix linking claim, implementation, test, evidence, expected result, and obtained result | P0 |
| Reproducibility | Fresh install, clean venv, local run, Docker build/run, CI run, examples run from documented commands | P0 |
| Project security | Gitleaks, Trivy, pip-audit/project audit, actionlint, workflow permission review, path exposure review | P0 |
| Scope clarity | README, limitations, release readiness, traceability, and docs index distinguish what is implemented, partial, planned, and out of scope | P1 |
| Public artifacts quality | README, examples, changelog, license, security policy, contributing guide, issue templates, roadmap, release notes, and control docs reviewed | P1 |
| Output stability | Repeated runs over the same inputs produce stable control status and stable normalized output except documented volatile fields | P0 |
| Formal release criteria | This gate and `docs/release-readiness.md` must define objective GO/NO-GO criteria | P0 |
| Real-world benchmark | At least one controlled vulnerable repo/app scenario outside the ideal sample fixture is validated | P1 |
| User experience | CLI output, errors, logs, help text, and remediation guidance reviewed from an end-user perspective | P1 |
| Post-publication governance | Issue triage, contribution rules, versioning, breaking changes, false-positive reports, and security reports documented | P1 |

## Mandatory acceptance criteria

### 1. Full project functionality

Required outcome:

- Every public CLI command runs successfully in a documented scenario:
  `run`, `collect`, `evaluate`, `bundle`, `controls`, `compare`, `oscal`,
  `plugins`, `schema`, `doctor`, and `exceptions validate/list`.
- The sample release produces `release_status=ready`.
- The sample release without attestations produces `release_status=not_ready`
  with expected missing critical controls.
- `compare` reports no unexpected deltas for equivalent bundles.
- `schema` emits a valid current bundle schema.
- `oscal` emits a valid catalog representation.
- `doctor` accurately reports required vs optional local dependencies.
- The optional API surface imports and its unit tests pass.
- The GitHub Action command line matches the real CLI contract.

Blocking evidence:

```powershell
python -m evidence_collector.cli.main --help
python -m evidence_collector.cli.main doctor --json
python -m evidence_collector.cli.main controls
python -m evidence_collector.cli.main plugins
python -m evidence_collector.cli.main schema --output output\publication-schema\bundle.schema.json
python -m evidence_collector.cli.main oscal --output output\publication-oscal\catalog.json
python -m evidence_collector.cli.main run --application payments-api --repository acme/payments-api --release-id publication-ready --commit-sha abcdef1234567890 --artifacts-dir examples\sample_release\artifacts --attestations-dir examples\sample_release\attestations --output-dir output\publication-ready
python -m evidence_collector.cli.main run --application missing-attestations --repository acme/payments-api --release-id publication-negative --commit-sha abcdef1234567890 --artifacts-dir examples\sample_release\artifacts --output-dir output\publication-negative
```

### 2. Control maturity

Required outcome:

- All 13 controls are listed in `docs/traceability.md`.
- Each control has implementation location, positive fixture, negative fixture,
  expected result, obtained result, and limitation if applicable.
- No control is described as "perfect" or "complete for extreme situations"
  unless the evidence proves that statement.
- Controls that depend on upstream scanners or human review must say so.

Important project-specific rule:

This tool validates the presence, classification, lineage, and release-readiness
impact of evidence. It does not prove that an application is vulnerability-free.
That limitation must remain explicit.

### 3. False-positive control

Required outcome:

For this project, a false positive means one of these conditions:

- the collector marks a control as `met` without valid matching evidence;
- the collector classifies evidence under the wrong evidence type;
- the collector returns `ready` when a critical or high required control is
  missing;
- the report implies security/compliance assurance beyond the evidence;
- an exception/waiver hides a required gap without explicit scope and expiry;
- CLI output misleads the user about what was validated.

Acceptance:

- Regression tests or fixtures cover misleading `ready`, missing attestations,
  invalid exceptions, malformed inputs, ambiguous SARIF classification, and
  conflicting evidence where feasible.
- Known classification caveats are documented in `docs/limitations.md`.

### 4. External test environment validation

Target:

`C:\Users\Lucas Grifoni\Downloads\My Projects - AppSec & DevSecOps\App vuln - teste`

Required outcome:

- The validation must prove what this collector actually promises: ingestion of
  scanner outputs, classification into evidence types, control evaluation,
  release-readiness status, gaps, reports, and bundle stability.
- Do not claim the collector itself "finds vulnerabilities" unless the finding
  comes from an upstream scanner artifact and the collector is only reporting
  the evidence.
- Every app/scenario used from `App vuln - teste` must map to:
  expected evidence types, expected missing controls, expected release status,
  obtained release status, and generated bundle/report paths.

Acceptance:

- `examples/labs/` or refreshed output from the external lab documents the
  scenarios.
- `docs/traceability.md` links each lab scenario to the relevant controls and
  limitations.

### 5. Scenario coverage by control and capability

Required minimum scenarios:

- positive case;
- negative case;
- edge case;
- regression case;
- misuse case;
- incomplete configuration;
- conflicting configuration.

Application to this project:

- Parsers: malformed SARIF/SBOM/JUnit/ZAP/attestation/exception inputs.
- Normalizers: ambiguous scanner names and mixed evidence sets.
- Controls: missing required evidence, only recommended evidence missing,
  waived evidence, not-applicable evidence, and conflicting evidence.
- CLI: nonexistent path, invalid evidence JSON, invalid catalog, unsupported
  `--fail-on`, and output directory handling.
- Reports: JSON, Markdown, HTML, OSCAL, schema export, and compare output.

### 6. Promise-to-delivery traceability

Required outcome:

Every public claim in README, docs, changelog, action metadata, and release
notes must be mapped to:

- promise;
- implementation location;
- test or fixture;
- generated evidence;
- expected result;
- obtained result;
- limitation or caveat.

Acceptance:

- `docs/traceability.md` is current for the publication candidate.
- No README marketing claim remains unmapped.
- Claims not yet supported are downgraded to "planned", "configured", or
  "known limitation".

### 7. Reproducibility

Required outcome:

A contributor must be able to reproduce the project from a clean environment.

Acceptance commands:

```powershell
python -m venv .venv-publication-check
.\.venv-publication-check\Scripts\python.exe -m pip install --upgrade pip
.\.venv-publication-check\Scripts\python.exe -m pip install -e ".[dev,api,docs]"
.\.venv-publication-check\Scripts\python.exe -m pytest -q
.\.venv-publication-check\Scripts\python.exe -m evidence_collector.cli.main --version
```

Docker acceptance, when Docker daemon is available:

```powershell
docker build -t sdlc-evidence:publication-check .
docker run --rm sdlc-evidence:publication-check --version
```

CI acceptance:

- GitHub CI/CD run succeeds.
- Security CI/CD run succeeds or has documented accepted exceptions.
- CodeQL run succeeds.
- Pages deploy succeeds.
- Scorecard run exists and is reviewed.

### 8. Security of the project itself

Required outcome:

- No exposed secrets.
- No local author paths in tracked public files, except fixtures explicitly
  scrubbed or documented.
- No sensitive sample data.
- No debug-only configuration exposed.
- No vulnerable project dependencies without treatment.
- No excessive workflow permissions.
- No unsafe artifact publishing or release workflow assumptions.

Acceptance commands:

```powershell
gitleaks detect --source . --no-git --redact --exit-code 1
python -m pip_audit .
trivy fs --scanners vuln,secret,misconfig --severity HIGH,CRITICAL .
Get-ChildItem .github\workflows\*.yml | ForEach-Object { actionlint $_.FullName }
```

Workflow review must also verify:

- least-privilege `permissions`;
- `persist-credentials: false` where applicable;
- SHA-pinned third-party actions or documented tag-pin exceptions;
- no token printed in logs;
- protected release environments where needed.

### 9. Scope clarity

Required outcome:

The public docs must clearly separate:

- implemented;
- partially implemented;
- configured but not remotely validated;
- planned;
- out of scope;
- known limitation.

Hard requirement:

The docs must explicitly say the collector does not scan code by itself. It
ingests and evaluates evidence produced by scanners and attestations.

### 10. Public artifact quality

Required outcome:

These artifacts must be professional and current:

- `README.md`;
- `CHANGELOG.md`;
- `LICENSE`;
- `SECURITY.md`;
- `CONTRIBUTING.md`;
- `CODE_OF_CONDUCT.md`;
- `.github/ISSUE_TEMPLATE/*`;
- `.github/pull_request_template.md`;
- `docs/`;
- `examples/`;
- `action.yml`;
- `Dockerfile`;
- release notes for the publication release.

Acceptance:

- No stale version claims.
- No dead badges.
- No broken links.
- No duplicated legacy prompt files in the public root.
- No public doc points to a removed local-only file.

### 11. Output stability

Required outcome:

For the same inputs:

- release status is stable;
- control status is stable;
- evidence ordering is stable;
- output is deterministic after documented volatile fields are stripped;
- compare output does not show unexpected deltas.

Acceptance:

- Determinism test passes.
- Back-to-back `run` and `compare` commands are captured in the publication
  evidence.

### 12. Formal release criteria

Minimum acceptance:

- 0 critical bugs open.
- 0 exposed secrets.
- 0 untriaged high/critical dependency vulnerabilities.
- 0 broken primary CLI features.
- 100% of the 13 controls mapped in traceability.
- 100% of primary CLI commands validated.
- 100% of public claims mapped to evidence or limitation.
- False-positive risks documented and covered by regression tests where feasible.
- External lab evidence current or explicitly marked as not revalidated.
- Docs complete enough for a third party to install and run.
- Public repository governance configured.

### 13. Benchmark against realistic scenarios

Required outcome:

At least one scenario beyond the ideal sample fixture must be validated:

- vulnerable controlled repo/app;
- intentionally incomplete evidence set;
- conflicting evidence set;
- malformed artifact set;
- lab scenario from `App vuln - teste`;
- self-release dogfood bundle.

Acceptance:

- The benchmark has expected vs obtained results.
- Unexpected drift is triaged before publication.

### 14. User experience

Required outcome:

The tool must be understandable to an end user without private context:

- help text is accurate;
- errors are actionable;
- reports explain gaps;
- severity/status language is consistent;
- JSON output is machine-readable;
- Rich output is readable by humans;
- docs explain how to interpret `ready`, `conditional`, and `not_ready`.

Acceptance:

- A "first-time user" smoke pass is recorded: install, run sample, inspect
  report, run negative sample, interpret gaps.

### 15. Post-publication governance

Required outcome:

The project must define how it will be maintained after opening:

- issue triage rules;
- false-positive report handling;
- security vulnerability handling;
- contribution workflow;
- versioning and release policy;
- breaking-change policy;
- dependency update policy;
- accepted limitation and exception process.

Acceptance:

- `CONTRIBUTING.md`, `SECURITY.md`, issue templates, PR template, changelog,
  roadmap/status docs, and release-readiness docs are aligned.

## Publication-day checklist

On 2026-06-05, do not publish until these commands and external checks are
green or explicitly accepted:

```powershell
git status --short --branch
python -m ruff check src tests scripts
python -m ruff format --check src tests scripts
python -m mypy src tests
python -m pytest -q
python -m pip_audit .
gitleaks detect --source . --no-git --redact --exit-code 1
trivy fs --scanners vuln,secret,misconfig --severity HIGH,CRITICAL .
Get-ChildItem .github\workflows\*.yml | ForEach-Object { actionlint $_.FullName }
python -m evidence_collector.cli.main doctor --json
python -m evidence_collector.cli.main run --application payments-api --repository acme/payments-api --release-id public-readiness --commit-sha abcdef1234567890 --artifacts-dir examples\sample_release\artifacts --attestations-dir examples\sample_release\attestations --output-dir output\public-readiness
python -m evidence_collector.cli.main run --application missing-attestations --repository acme/payments-api --release-id public-readiness-negative --commit-sha abcdef1234567890 --artifacts-dir examples\sample_release\artifacts --output-dir output\public-readiness-negative
```

External checks:

- GitHub Actions has successful runs.
- Branch protection is enabled.
- Code scanning is enabled and reviewed.
- Secret scanning is enabled where available.
- PyPI Trusted Publisher is configured before package publication.
- GitHub Pages works for root and `/docs/`.
- Dependabot PRs and alerts are triaged.
- Release signing/provenance evidence exists before claiming signed release
  artifacts.

## Final publication decision template

Use this exact decision language:

```text
Publication decision for 2026-06-05: GO | GO WITH CAVEATS | NO-GO

Summary:
- Functional readiness:
- Control/capability maturity:
- False-positive risk:
- External lab evidence:
- Reproducibility:
- Security:
- Documentation:
- Output stability:
- Governance:

Blocking issues:
- ...

Accepted caveats:
- ...

Evidence links:
- ...
```

For public exposure, the default decision is `NO-GO` unless the evidence says
otherwise.
