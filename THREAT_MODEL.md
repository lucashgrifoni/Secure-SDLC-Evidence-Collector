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

### 2.5 Tier 4 surfaces — FastAPI, plugins, OSCAL

These three surfaces shipped in v1.1.0 and add attack surface beyond
the original CLI / parser / collector loop. They are listed
separately because they are **opt-in** and most operators will not
turn them on.

| Surface | Threat | Mitigation |
|---|---|---|
| **FastAPI read-only API** (`src/evidence_collector/api/app.py`, behind `[api]` extra) | Unauthenticated HTTP server exposing schema/catalog/plugins/version/healthz. Run on a public network, an attacker can fingerprint the deployment and read the active control catalog. | Endpoints are **read-only** — no `POST/PUT/DELETE`, no bundle ingestion, no token in the response. The `[api]` extra is opt-in, the binding host is the operator's choice (FastAPI default `127.0.0.1` if started via the example `uvicorn` invocation in `docs/`), and the surface is documented as "internal/CI-side, do not expose to the public internet" in the README and the FastAPI section of the docs. No auth is enforced because the operator who runs the API is also the one who has read access to the bundle inputs; adding token auth without a real multi-tenant requirement would be theatre. |
| **Plugin entry-point system** (`evidence_collector.parsers` and `evidence_collector.collectors` groups, discovered by `evidence_collector.plugins`) | Any package installed in the same Python environment can register itself as a parser or collector and be discovered by `sdlc-evidence plugins`. A typo-squatted PyPI package could pose as a legitimate parser. | Discovery is **list-only** today — `sdlc-evidence plugins` enumerates registered entry points and `docs/plugins.md` documents the contract, but auto-wiring into `LocalArtifactCollector` is **explicitly deferred** (see `MATURITY_STATUS.md` T4.1 note). Until auto-wiring lands, third-party plugins must be invoked by the operator deliberately, so a typo-squat does not get loaded just by being installed. When auto-wiring lands, the bundle must record `provider` (entry-point name + version) per evidence so a downstream auditor can see which plugin produced what. |
| **OSCAL exporter** (`sdlc-evidence oscal`) | Outputs an OSCAL 1.1.x Catalog of the active control catalog. A malicious catalog override + OSCAL export could publish a misleading catalog to a downstream OSCAL consumer. | OSCAL output is read-only and deterministic; the catalog source path is captured in the bundle so the OSCAL document can always be tied back to its source. The same `--catalog` substitution risk applies as in §2.3 row 1. |

Residual risk: an operator who runs the FastAPI surface bound to `0.0.0.0` on a runner with a public IP exposes the catalog and schema. We surface this in the docs but do not refuse to bind there — that decision belongs to the operator.

### 2.6 Supply chain of the collector itself

| Threat                                | Mitigation                                                                                                                  |
|---------------------------------------|-----------------------------------------------------------------------------------------------------------------------------|
| **Compromised third-party action**    | Third-party actions in workflows are pinned by full SHA with the semantic tag in a trailing comment, with two documented structural exceptions: `slsa-framework/slsa-github-generator/.../v2.0.0` (the SLSA generator's reusable-workflow contract requires tag-pin) and `pypa/gh-action-pypi-publish@release/v1` (the PyPA Trusted Publisher pattern). The full inventory and rationale are in `docs/program/actions-pinning-inventory.md`. Dependabot opens PRs to refresh SHAs (Actions ecosystem; major bumps land only after human review and a local validation note in `docs/program/dependabot-triage.md`). |
| **Compromised Python dependency**     | `Dependabot` covers `pip`, `github-actions` and `docker` ecosystems weekly. `pip-audit` runs in security-ci-cd.yml.         |
| **PyPI package squatting / build hijack** | PyPI publish uses OIDC Trusted Publisher (no long-lived `PYPI_API_TOKEN`); only the `publish-pypi.yml` workflow can publish.    |
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
