# Secure SDLC Evidence Collector — Technical documentation

This is the technical site for the Secure SDLC Evidence Collector.
The product README at the repository root tells you **what the tool
does**; this site tells you **how to integrate it, extend it, and
operate it in a real pipeline**.

## What you'll find here

- **[Bundle schema reference](./bundle_schema.md)** — the canonical
  shape of `bundle.json` that pipelines consume and policy engines
  validate.
- **[GitHub Action documentation](./github_action.md)** — inputs,
  outputs, examples, and recipes for using the action in your release
  workflows.
- **[Release readiness model](./release-readiness.md)** — how
  `ready` / `conditional` / `not_ready` is decided, and how to wire
  the verdict into pipeline gates.
- **[Public repository readiness gate](./publication-readiness.md)** —
  mandatory acceptance criteria before making the repository public.
- **[Limitations](./limitations.md)** — what the collector explicitly
  does not do, so adopters do not assume coverage that is not there.
- **[Traceability matrix](./traceability.md)** — control-to-evidence
  mapping with NIST SSDF and OWASP SAMM coordinates.
- **[Maturity roadmap](./MATURITY_ROADMAP.md)** and
  **[live status](./MATURITY_STATUS.md)** — the four-tier plan and
  the current snapshot of progress against it.
- **[Architecture decision records](./adr/README.md)** — the
  non-obvious decisions that shape this project and the reasoning
  behind them.

## Where the product lives

| Surface                              | Location                                                                                  |
|--------------------------------------|-------------------------------------------------------------------------------------------|
| CLI (`sdlc-evidence`)                | `src/evidence_collector/cli/main.py`                                                      |
| GitHub Action                        | [`action.yml`](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/blob/main/action.yml) |
| Container image                      | `publish-pypi.yml` builds and signs `ghcr.io/lucashgrifoni/secure-sdlc-evidence-collector` (multi-arch, cosign keyless + SBOM attestation) on tag push. The first publicly verifiable image will be `:v1.1.0`. |
| Wheel + sdist                        | Built and signed by `publish-pypi.yml`; PyPI publishing is configured but still depends on the external Trusted Publisher setup tracked in `MATURITY_STATUS.md`. |
| Bundle JSON Schema                   | Exported by `sdlc-evidence schema`; validated in CI on every run.                         |

## Verifying signatures

`publish-pypi.yml` is configured to sign every release artifact with
**cosign keyless** and to record each signature on the **Sigstore
Rekor** transparency log. Once the first signed `v1.1.0` release is
published, you can verify the wheel with:

```bash
cosign verify-blob \
  --certificate signatures/secure_sdlc_evidence_collector-1.1.0-py3-none-any.whl.pem \
  --signature signatures/secure_sdlc_evidence_collector-1.1.0-py3-none-any.whl.sig \
  --certificate-identity-regexp 'https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  secure_sdlc_evidence_collector-1.1.0-py3-none-any.whl
```

To verify the container image (after the first published `v1.1.0`):

```bash
cosign verify ghcr.io/lucashgrifoni/secure-sdlc-evidence-collector:v1.1.0 \
  --certificate-identity-regexp 'https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

To inspect the SBOM attestation:

```bash
cosign download attestation \
  ghcr.io/lucashgrifoni/secure-sdlc-evidence-collector:v1.1.0
```

## Reporting issues

- **Security**: see [`SECURITY.md`](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/blob/main/SECURITY.md).
- **Bugs and feature requests**: GitHub Issues.
- **Threat-model concerns**: tracked in [`THREAT_MODEL.md`](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/blob/main/THREAT_MODEL.md).
