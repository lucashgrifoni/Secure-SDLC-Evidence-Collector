# Threat Model — Secure SDLC Evidence Collector

This document is the public threat model for the collector itself —
the project ships secure-SDLC tooling, so it owes its users a visible
analysis of how its **own** trust boundaries are protected.

The model targets the v1.x line; major-version changes that alter
attack surface (REST API, plugin loading, persistent storage) require
an update before they ship.

---

## 1 · System overview

### Trust boundaries

```
┌─────────────────────────────────────────────────────────────────────┐
│  Operator's machine (CI runner or local dev)                        │
│                                                                     │
│   ┌────────────┐    ┌──────────────┐    ┌───────────────────┐       │
│   │  Artifacts │ ─▶ │  Collector   │ ─▶ │  Bundle outputs   │       │
│   │  on disk   │    │  (Python)    │    │ (JSON/MD/HTML)    │       │
│   └────────────┘    └──────┬───────┘    └───────────────────┘       │
│                            │                                        │
└────────────────────────────│────────────────────────────────────────┘
                             │ (only when --pull-request, --workflow-run,
                             │  or GitLab equivalents are used)
                             ▼
                  ┌─────────────────────┐
                  │  GitHub / GitLab    │  ← outbound HTTPS only
                  │  REST APIs          │
                  └─────────────────────┘
```

### Assets

| Asset                       | Why it matters                                                          |
|-----------------------------|-------------------------------------------------------------------------|
| **`bundle.json`**           | Authoritative release-readiness statement; consumed by signing + audit. |
| **Tokens** (`GITHUB_TOKEN`, `GITLAB_TOKEN`) | Allow read-access to private metadata; must never appear in logs. |
| **Source artifacts**        | The integrity hash stored in the bundle binds the artifact byte-for-byte; corrupting it breaks audit chain. |
| **Cosign signing identity** | Issued by Sigstore via OIDC; abuse would let an attacker sign a fake bundle. |

### Adversaries in scope

- **Malicious artifact author** — somebody with write access to the
  evidence directory can plant a crafted SARIF/SBOM/JUnit/ZAP/YAML
  file that exploits the parser.
- **Repository write attacker** — somebody who got merge rights or
  forced a malicious commit to `main` and wants the next release
  bundle to lie.
- **Network attacker on the runner** — exfiltrating tokens, MITM-ing
  GitHub or GitLab API calls.
- **Downstream relying party who got a tampered bundle** — tries to
  detect it.

Out of scope: pre-image attacks against SHA-256, compromise of the
operator's GitHub/Sigstore account, supply-chain compromise of Python
itself.

---

## 2 · STRIDE-by-component analysis

### 2.1 Local parsers (`src/evidence_collector/parsers/`)

| Threat                            | Mitigation                                                                                                                |
|-----------------------------------|---------------------------------------------------------------------------------------------------------------------------|
| **DoS via huge file** (zip-bomb-style SARIF/SBOM/JUnit) | 25 MB cap per artifact (`MAX_INPUT_BYTES` in `_common.py`); enforced before parsing.                                      |
| **XML external entity / billion laughs** | All XML parsing goes through `defusedxml.ElementTree`. The stdlib `ElementTree` is imported only for typing.              |
| **Malicious YAML deserialization** | `yaml.safe_load` exclusively; never `yaml.load` or `yaml.full_load`.                                                      |
| **Path traversal via `../` in attestation paths** | Paths in attestations are stored verbatim in metadata but never resolved or read by the collector.                        |
| **Symbolic link target outside artifacts dir** | `ensure_file()` resolves to absolute and rejects unreadable files; we do not follow links into a different filesystem.    |
| **Pydantic validation bypass via `extra` fields** | Every domain model sets `extra="forbid"`; unknown keys are a hard error.                                                  |

Residual risk: a malformed file that satisfies the formal schema but
encodes nonsense (e.g. negative test counts) is accepted. We treat
this as the operator's responsibility — the bundle records the
artifact's SHA-256 so tampering after-the-fact is detectable.

### 2.2 Collectors (`src/evidence_collector/collectors/`)

| Threat                                | Mitigation                                                                                                                                    |
|---------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------|
| **Token leakage in logs**             | `GITHUB_TOKEN` / `GITLAB_TOKEN` are read from the environment, never echoed to stdout/stderr; `_configure_logging` does not include env vars. |
| **SSRF via attacker-controlled URL**  | Both collectors accept a fixed `api_base` (defaults to `https://api.github.com` / `https://gitlab.com/api/v4`) and a `repository`/`project` slug; raw URLs are never accepted from artifacts.  |
| **MITM on the API call**              | `httpx` defaults to verifying TLS chains against the system trust store; we never set `verify=False`.                                         |
| **PR body / reviewer comment exfiltration** | We extract structured fields (approvals, run state) and explicitly *do not* persist PR description or comments to the bundle.                |
| **Token-replay**                      | Tokens are short-lived OIDC-issued runner tokens or PATs; the collector does not cache, rotate, or persist them.                              |

Residual risk: an attacker with network access to the runner could
observe metadata (which repos we're reading). We accept this.

### 2.3 Scoring + control engine

| Threat                                | Mitigation                                                                                                                  |
|---------------------------------------|-----------------------------------------------------------------------------------------------------------------------------|
| **Catalog override that disables critical controls** | `--catalog` fully replaces the default catalog by design (ADR-0005); the operator explicitly opted in. The bundle records the catalog source so an auditor can review it. |
| **Waiver abuse** (perpetual exception) | Exceptions are time-bound (`expires_at`) and validated; expired waivers do not apply. Justifications under 10 chars are rejected at the Pydantic layer to discourage rubber-stamp text. |
| **Score manipulation via duplicate evidence** | Evidence is normalized and deduplicated by SHA-256; duplicate paths producing the same hash count once.                     |

### 2.4 Outputs and signing

| Threat                                | Mitigation                                                                                                                  |
|---------------------------------------|-----------------------------------------------------------------------------------------------------------------------------|
| **Bundle drift / nondeterminism**     | Structural-determinism CI gate (ADR-0002) re-runs the pipeline and compares SHA-256 after stripping volatile fields.        |
| **Bundle tampering after sign**       | `cosign sign-blob` keyless, with the signature recorded on the Sigstore Rekor public transparency log.                      |
| **Wheel/sdist tampering**             | Same cosign keyless flow; SLSA Build Level 3 in-toto provenance produced by `slsa-github-generator`.                        |
| **Container image tampering**         | Image is signed with `cosign sign` keyless; SBOM is attached as a `cosign attest` predicate (CycloneDX type).               |
| **Schema drift between collector and consumer** | `sdlc-evidence schema` exports the Pydantic-derived JSON Schema; CI re-validates the sample bundle against it on every run. |

### 2.5 Supply chain of the collector itself

| Threat                                | Mitigation                                                                                                                  |
|---------------------------------------|-----------------------------------------------------------------------------------------------------------------------------|
| **Compromised third-party action**    | All third-party actions in workflows are pinned by SHA, with the semantic tag in a trailing comment. Dependabot opens PRs to refresh SHAs (Actions ecosystem; major bumps blocked to require human review).  |
| **Compromised Python dependency**     | `Dependabot` covers `pip`, `github-actions` and `docker` ecosystems weekly. `pip-audit` runs in security-ci-cd.yml.         |
| **PyPI package squatting / build hijack** | PyPI publish uses OIDC Trusted Publisher (no long-lived `PYPI_API_TOKEN`); only the `release.yml` workflow can publish.    |
| **Container base image vulnerabilities** | Base image is `python:3.12-slim-bookworm`; Trivy filesystem + image scan in security-ci-cd.yml; SBOM attestation lets consumers re-scan.  |

---

## 3 · Acknowledged residual risks

1. **No multi-tenant isolation.** The collector is a CLI/Action;
   anyone running it has full access to the artifacts they pass in.
   We do not protect against the operator themselves.
2. **No rate limiting on collectors.** A pathological run pulling
   thousands of PRs would exhaust the runner's GitHub API quota; we
   surface the failure but do not throttle proactively.
3. **No anti-replay on signed bundles.** A consumer who got a valid
   bundle could re-present it as if it were freshly produced. The
   `generated_at` timestamp lets relying parties enforce freshness;
   we do not enforce it inside the collector.
4. **Catalog substitution attack.** An attacker with write access to
   the repo can change the override YAML to weaken controls. The
   bundle records the catalog source path so post-hoc detection is
   possible, but pre-hoc enforcement (e.g. signed catalogs) is not
   in 1.x.

These are tracked in [`docs/MATURITY_ROADMAP.md`](./docs/MATURITY_ROADMAP.md)
under the appropriate tier and revisited at each major version.

---

## 4 · Reporting

Coordinated-disclosure process is documented in [`SECURITY.md`](./SECURITY.md).
Threat-model concerns that are not yet a confirmed vulnerability can
also be filed there, marked as "design feedback".
