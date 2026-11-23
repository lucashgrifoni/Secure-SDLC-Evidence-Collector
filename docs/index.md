---
hide:
  - navigation
---

# Documentation

Collect the security evidence of a release, check it against a control
catalog, and get a verdict you can gate a pipeline on.
{ .home-lede }

<div class="home-install" markdown>

```text
python -m pip install secure-sdlc-evidence-collector
```

</div>

## Start in five minutes

Each path goes from install to a first verdict in
[Getting started](getting-started.md).

<div class="grid cards home-paths" markdown>

-   <span class="home-kicker">CLI</span>

    **[Run it locally](getting-started.md#cli-with-pip)**

    Install with pip, run the sample release and read the verdict. Needs
    Python 3.12 or 3.13.

-   <span class="home-kicker">GitHub Actions</span>

    **[Add the Action](getting-started.md#github-action)**

    One step after your scanners. The verdict lands in the job summary;
    start in observe mode with `fail-on: none`.

-   <span class="home-kicker">GitLab CI/CD</span>

    **[Use the component](getting-started.md#gitlab-cicd-catalog-component)**

    Include it from the CI/CD Catalog after your scanner jobs. It fails
    the job on `conditional` by default.

-   <span class="home-kicker">Docker</span>

    **[Run the image](getting-started.md#docker-image)**

    No Python on the host. Build the image from the repository and mount
    your scanner output.

</div>

## Read the verdict

Every run ends with one of three verdicts. `run`, `evaluate` and `bundle`
turn it into the exit code below.

<div class="grid cards home-verdicts" markdown>

-   <span class="verdict-pill verdict-pill--ok">ready</span>

    Every control is met, waived or not applicable.

    <span class="verdict-exit">exit 0</span>

-   <span class="verdict-pill verdict-pill--warn">conditional</span>

    No critical control lacks required evidence, but at least one control is
    partial or missing: a high, medium or low control lacks required
    evidence, or a control lacks recommended evidence.

    <span class="verdict-exit">exit 0, or 1 with --fail-on conditional</span>

-   <span class="verdict-pill verdict-pill--bad">not_ready</span>

    A critical control lacks required evidence.

    <span class="verdict-exit">exit 2</span>

</div>

A failure that is not a verdict, such as unreadable input, exits `3`. The
GitLab component gates on `conditional` by default; the CLI, the Action and
the reusable workflow gate on `not_ready`. The full matrix is in the CLI reference's
[Exit codes](cli-reference.md#exit-codes)
section, and what a verdict does not prove is in [Limitations](limitations.md).

## Find it by task

<div class="grid home-tasks" markdown>

<div markdown>

**Integrate**

- [GitHub Action inputs and outputs](github_action.md)
- [Run it as a reusable workflow](reusable_workflow.md)
- [Write the attestations no scanner produces](getting-started.md#add-your-own-attestations)
- [Evidence profile migration](evidence-profile-migration.md)

</div>

<div markdown>

**Understand the output**

- [`bundle.json` schema](bundle_schema.md)
- [Events in `--json-logs`](json-logs.md)
- [What the collector does not do](limitations.md)
- [Control to evidence traceability](traceability.md)

</div>

<div markdown>

**Operate**

- [Upgrading between versions](upgrading.md)
- [Verify a release signature](#verifying-signatures)
- [Roll back a release](rollback.md)
- [Troubleshooting](troubleshooting.md)

</div>

<div markdown>

**Plan**

- [Maturity roadmap](MATURITY_ROADMAP.md)
- [Architecture decisions](adr/README.md)
- [Release readiness checklist](release-readiness.md)
- [Comparison with alternatives](comparison.md)

</div>

</div>

## Verifying signatures

`publish-pypi.yml` is configured to sign every release artifact with
**cosign keyless** and records each signature on the **Sigstore Rekor**
transparency log. `2.0.0` was the first public release; every release since is
signed, so the commands below work against any published tag. The one
exception is `3.0.0`: its release pipeline failed before anything was signed,
so it has no release assets, PyPI upload or container image. Set the version
you want to verify — the examples use the installed one:

```bash
VERSION=$(sdlc-evidence --version)
```

Download the wheel and its signature assets from the matching
[GitHub Release](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/releases),
then verify the wheel. `--certificate-identity` pins the signer to the
release workflow running for that exact tag, so a signature made by any other
workflow or branch of the repository does not verify:

```bash
cosign verify-blob \
  --certificate "secure_sdlc_evidence_collector-${VERSION}-py3-none-any.whl.pem" \
  --signature "secure_sdlc_evidence_collector-${VERSION}-py3-none-any.whl.sig" \
  --certificate-identity "https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/.github/workflows/publish-pypi.yml@refs/tags/v${VERSION}" \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "secure_sdlc_evidence_collector-${VERSION}-py3-none-any.whl"
```

Verify the container image:

```bash
cosign verify "ghcr.io/lucashgrifoni/secure-sdlc-evidence-collector:v${VERSION}" \
  --certificate-identity "https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/.github/workflows/publish-pypi.yml@refs/tags/v${VERSION}" \
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
