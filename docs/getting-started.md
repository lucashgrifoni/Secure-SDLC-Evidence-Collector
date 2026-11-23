# Getting started

The collector reads the files your scanners and reviewers already produce,
checks them against a control catalog, and writes a bundle (`bundle.json`,
`report.md`, `summary.html`) with a release verdict: `ready`, `conditional`
or `not_ready`. Pick the path that matches where you want it to run:

| Path | Use it when | Needs |
|------|-------------|-------|
| [CLI with pip](#cli-with-pip) | you want to try it locally or call it from any CI system | Python 3.12 or 3.13 |
| [GitHub Action](#github-action) | your release runs on GitHub Actions | a workflow in your repository |
| [GitLab CI/CD Catalog component](#gitlab-cicd-catalog-component) | your release runs on GitLab CI/CD | a `.gitlab-ci.yml` in your project |
| [Docker image](#docker-image) | you want no Python on the host | Docker |

Start with the CLI even if you will end up in CI: the sample release below
shows in a minute what each verdict looks like. When something does not go
as described here, see [Troubleshooting](troubleshooting.md).

## CLI with pip

**Prerequisites:** Python 3.12 or 3.13, preferably in a virtual environment,
and `git` to get the sample files.

Install the package and check that the command is on your path:

```bash
python -m pip install secure-sdlc-evidence-collector
sdlc-evidence --version
```

The sample scanner output and attestations live in the repository, not in
the package, so clone it and run from the clone:

```bash
git clone https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector.git
cd Secure-SDLC-Evidence-Collector
```

Run the sample release in bash (Linux, macOS, Git Bash):

```bash
sdlc-evidence run \
  --application payments-api \
  --repository acme/payments-api \
  --release-id 2026.04.10 \
  --commit-sha abcdef1234567890 \
  --artifacts-dir examples/sample_release/artifacts \
  --attestations-dir examples/sample_release/attestations \
  --output-dir output/sample_release
```

In PowerShell, end each line with a backtick instead of a backslash:

```powershell
sdlc-evidence run `
  --application payments-api `
  --repository acme/payments-api `
  --release-id 2026.04.10 `
  --commit-sha abcdef1234567890 `
  --artifacts-dir examples/sample_release/artifacts `
  --attestations-dir examples/sample_release/attestations `
  --output-dir output/sample_release
```

**What you see:** a summary table, then the three files it wrote. The bundle
ID changes on every run.

```text
 Release status  ready
 Scores          coverage=100 confidence=59
 Controls        met=13 partial=0 missing=0 waived=0 n/a=0
 Evidence count  13
```

The command exits `0`. Open `output/sample_release/summary.html` in a
browser, or read `report.md`, to see which evidence met which control.

Now drop the `--attestations-dir` line and run it again. The scanner output
alone gives `not_ready` and exit `2`, and the summary names what is missing:

```text
 Release status         not_ready
 Missing critical/high  ORG-CODE-REVIEW:code_review,
                        ORG-RELEASE-APPROVAL:release_approval,
                        ORG-REL-ROLLBACK:rollback_plan,
                        SSDF-PS.2:artifact_signature
```

That is what your first real run will most likely look like too: code review,
release approval, rollback plan and artifact signature are practices no
scanner reports on, so you state them in attestation files.

### Add your own attestations

[`examples/attestations/`](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/tree/main/examples/attestations)
has one template per evidence type. Copy the ones you need into a directory of
your own, replace the placeholder values, and pass that directory with
`--attestations-dir`:

```bash
mkdir -p release-attestations
cp examples/attestations/*.yaml release-attestations/
```

```powershell
New-Item -ItemType Directory -Force release-attestations
Copy-Item examples/attestations/*.yaml release-attestations/
```

As shipped, every template has `status: unknown`, which satisfies no control:
run with the templates unchanged and the verdict stays `not_ready`. Set
`status: passed` in a file only when the practice it describes happened for
this release. The collector checks the shape of these files, not whether what
they say is true, so whoever sets that status is the control. The
[templates README](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/blob/main/examples/attestations/README.md)
lists the fields and the controls each file feeds.

### Next step

Point `--artifacts-dir` at your own scanner output (SARIF, CycloneDX or SPDX,
JUnit XML, Trivy JSON and the other formats in the
[README](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector#readme)),
and choose how strict the gate is with `--fail-on` (see
[Troubleshooting](troubleshooting.md#a-conditional-release-exits-0)).

## GitHub Action

**Prerequisites:** a GitHub repository with Actions enabled, a job that
writes your scanner output into a directory, and a release tag of this
project to pin.

Add the collector as a step after your scanners. Replace `vX.Y.Z` with the tag
used in the [GitHub Action quick start](github_action.md#quick-start), which
is kept on the latest release:

```yaml
      - id: collect
        uses: lucashgrifoni/Secure-SDLC-Evidence-Collector@vX.Y.Z
        with:
          application: my-app
          release-id: ${{ github.ref_name }}
          artifacts-dir: artifacts
          attestations-dir: attestations
          fail-on: none
```

`fail-on: none` is observe mode: the step reports the verdict and passes, and
fails only when the collector could not run at all. Expect the first runs to
be `not_ready` until your attestations exist.

**What you see:** the verdict and the missing critical and high evidence in
the job summary, the `release-status` output for later steps, and the bundle
in `output/sdlc-evidence`, which you keep with `actions/upload-artifact`.

**Next step:** once the job summary shows what you expect, switch to
`fail-on: not_ready` or `fail-on: conditional` on the release trigger. The
full workflow, the inputs and outputs, pull request evidence and waivers are
in [Using the GitHub Action](github_action.md). To run the collector as a job
of its own instead of a step, use the
[reusable workflow](reusable_workflow.md).

## GitLab CI/CD Catalog component

**Prerequisites:** a GitLab project whose earlier jobs save their scanner
reports as job artifacts.

Include the component in a stage after the scanner jobs. Replace `<version>`
with the component release named in the
[component README](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/blob/main/examples/gitlab-component/README.md):

```yaml
include:
  - component: gitlab.com/lucas.henriquegrifoni/secure-sdlc-evidence-component/collect@<version>
    inputs:
      application: my-application
      artifacts-dir: scanner-output
      attestations-dir: release-attestations
```

The component's `fail-on` defaults to `conditional`, stricter than the CLI
and the GitHub surfaces: a release with a high control missing, such as the
SAST scan, fails the job. Set `fail-on: not_ready` while you are getting
started if you want the GitHub behaviour.

**What you see:** the verdict in the job log, a line for each file in
`artifacts-dir` that matched no format, and the bundle under
`release-evidence/` as a job artifact kept for 30 days.

**Next step:** the accepted report formats, every input and the rollback
steps are in the
[component README](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/blob/main/examples/gitlab-component/README.md);
the input names across the GitHub and GitLab surfaces are compared in
[Using the reusable workflow](reusable_workflow.md#inputs-across-the-three-surfaces).

## Docker image

**Prerequisites:** Docker, and a clone of the repository (the image is built
from its `Dockerfile`, and the sample files come from it).

Build the image from the root of the clone:

```bash
docker build -t sdlc-evidence:local .
```

The container reads your files through bind mounts under `/workspace`. In
Git Bash on Windows, prefix the command with `MSYS_NO_PATHCONV=1`; without
it Git Bash rewrites `/workspace/...` into a Windows path and the run exits
`3` (see [Troubleshooting](troubleshooting.md#git-bash-rewrites-container-paths)).
On Linux the output directory must be writable by the container user; the
[Docker image section](github_action.md#docker-image) of the Action page shows
the `--user` form for that.

```bash
mkdir -p output
MSYS_NO_PATHCONV=1 docker run --rm \
  -v "$PWD/examples/sample_release/artifacts:/workspace/artifacts:ro" \
  -v "$PWD/examples/sample_release/attestations:/workspace/attestations:ro" \
  -v "$PWD/output:/workspace/output" \
  sdlc-evidence:local run \
    --application payments-api \
    --repository acme/payments-api \
    --release-id 2026.04.10 \
    --commit-sha abcdef1234567890 \
    --artifacts-dir /workspace/artifacts \
    --attestations-dir /workspace/attestations \
    --output-dir /workspace/output
```

In PowerShell:

```powershell
New-Item -ItemType Directory -Force output
docker run --rm `
  -v "${PWD}/examples/sample_release/artifacts:/workspace/artifacts:ro" `
  -v "${PWD}/examples/sample_release/attestations:/workspace/attestations:ro" `
  -v "${PWD}/output:/workspace/output" `
  sdlc-evidence:local run `
    --application payments-api `
    --repository acme/payments-api `
    --release-id 2026.04.10 `
    --commit-sha abcdef1234567890 `
    --artifacts-dir /workspace/artifacts `
    --attestations-dir /workspace/attestations `
    --output-dir /workspace/output
```

**What you see:** the same summary as the CLI, `ready` with exit `0`, and the
three files in `output/`.

**Next step:** mount your own scanner output and attestation directories in
place of the sample ones. Each release also publishes a signed image; how to
verify it is on the [documentation home page](index.md).

## Before you upgrade

Changes to verdicts, exit codes and outputs between releases are listed in
[Upgrading](upgrading.md). What the verdict does not prove, and the inputs the
collector reads only partly, are in [Limitations](limitations.md).
