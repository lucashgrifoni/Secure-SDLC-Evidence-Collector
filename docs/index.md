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
- **[Limitations](./limitations.md)** — what the collector explicitly
  does not do, so adopters do not assume coverage that is not there.
- **[Traceability matrix](./traceability.md)** — control-to-evidence
  mapping with NIST SSDF and OWASP SAMM coordinates.
- **[Maturity roadmap](./MATURITY_ROADMAP.md)** — the public roadmap for
  future hardening and adoption work.
- **[Architecture decision records](./adr/README.md)** — the
  non-obvious decisions that shape this project and the reasoning
  behind them.

## Where the product lives

| Surface                              | Location                                                                                  |
|--------------------------------------|-------------------------------------------------------------------------------------------|
| CLI (`sdlc-evidence`)                | `src/evidence_collector/cli/main.py`                                                      |
| GitHub Action                        | [`action.yml`](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/blob/main/action.yml) |
| Container image                      | `publish-pypi.yml` builds and signs `ghcr.io/lucashgrifoni/secure-sdlc-evidence-collector` (multi-arch, cosign keyless + SBOM attestation) on tag push. Every release since `2.0.0` is published and verifiable. |
| Wheel + sdist                        | Built and signed by `publish-pypi.yml`; PyPI publishing depends on the repository's Trusted Publisher configuration in PyPI. |
| Bundle JSON Schema                   | Exported by `sdlc-evidence schema`; validated in CI on every run.                         |

## Verifying signatures

`publish-pypi.yml` is configured to sign every release artifact with
**cosign keyless** and records each signature on the **Sigstore Rekor**
transparency log. `2.0.0` was the first public release; every release since is
signed, so the commands below work today against any published tag. Set the
version you want to verify — the examples use the installed one:

```bash
VERSION=$(sdlc-evidence --version)
```

Download the wheel and its signature assets from the matching
[GitHub Release](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/releases),
then verify the wheel:

```bash
cosign verify-blob \
  --certificate "secure_sdlc_evidence_collector-${VERSION}-py3-none-any.whl.pem" \
  --signature "secure_sdlc_evidence_collector-${VERSION}-py3-none-any.whl.sig" \
  --certificate-identity-regexp 'https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "secure_sdlc_evidence_collector-${VERSION}-py3-none-any.whl"
```

Verify the container image:

```bash
cosign verify "ghcr.io/lucashgrifoni/secure-sdlc-evidence-collector:v${VERSION}" \
  --certificate-identity-regexp 'https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

Inspect the SBOM attestation:

```bash
cosign download attestation \
  "ghcr.io/lucashgrifoni/secure-sdlc-evidence-collector:v${VERSION}"
```

## Reporting issues

- **Security**: see [`SECURITY.md`](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/blob/main/SECURITY.md).
- **Bugs and feature requests**: GitHub Issues.
- **Threat-model concerns**: tracked in [`THREAT_MODEL.md`](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/blob/main/THREAT_MODEL.md).
