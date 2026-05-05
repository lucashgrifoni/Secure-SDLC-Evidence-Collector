# Security Policy

## Reporting a vulnerability

**Do not open a public GitHub issue for security problems.**

Please email [lucas.henriquegrifoni@gmail.com](mailto:lucas.henriquegrifoni@gmail.com)
with a subject line starting with `[secure-sdlc-evidence-collector]` and
include:

- a clear description of the vulnerability,
- the affected version or commit SHA,
- a reproducer (command, input, or minimal code sample),
- any mitigation you've already applied.

We aim to acknowledge reports within **3 business days** and provide a
remediation plan within **10 business days** for confirmed
vulnerabilities.

## Supported versions

| Version line | Status |
|--------------|--------|
| `1.x` | actively supported |
| `0.x` | best-effort only; please upgrade |

## Disclosure policy

We practice coordinated disclosure:

1. You report the issue privately.
2. We confirm, fix, and release a patched version (and a CVE when
   applicable).
3. We credit you in the release notes unless you prefer to remain
   anonymous.
4. Public disclosure lands no earlier than 24 hours after the patched
   version is available, or 90 days after initial report — whichever
   comes first.

## Product security posture

The tool is designed with the same rules it enforces on others:

- no hardcoded secrets; tokens read from the environment only,
- 25 MB safety cap per ingested artifact,
- SHA-256 integrity hash recorded for every ingested file,
- strict Pydantic schema (`extra='forbid'`) on every canonical type,
- XML parsing via `defusedxml` (no external entity resolution),
- no PR body, reviewer email, or token ever written to logs,
- deterministic bundle JSON so audit integrity hashes are stable,
- `release.yml` is configured to sign releases keyless with cosign
  (Sigstore Rekor transparency log) and to attach SLSA Build Level 3
  provenance. The first signed public release will be `v1.1.0`; until
  that release ships, no public artefact in this project carries a
  cosign signature.

## Scope

In scope for bug bounty / reports:

- parser injection or resource-exhaustion via malformed SARIF / SBOM /
  JUnit / attestation / exception inputs,
- escape of `--output-dir` boundaries,
- evaluation rules that mark `ready` when a required critical control
  is genuinely missing,
- leakage of secrets via logs, error messages, or generated bundles,
- dependency confusion or supply-chain risk in our release pipeline.

Out of scope:

- issues in third-party SARIF / SBOM tools themselves,
- DoS that requires privileged filesystem access,
- missing security headers in the `summary.html` artifact when served
  outside the tool's default invocation.
