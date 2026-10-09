# Secure SDLC Evidence Collector for GitLab

The `collect` component turns existing scanner reports and release attestations
into JSON, Markdown and HTML evidence bundles. It installs the exact collector
package version selected by the pipeline.

## Usage

Include the component in a stage after the jobs that produce scanner artifacts.
GitLab downloads artifacts from earlier stages into the collector job.

```yaml
include:
  - component: gitlab.com/lucas.henriquegrifoni/secure-sdlc-evidence-component/collect@1.0.0
    inputs:
      application: my-application
      artifacts-dir: scanner-output

stages: [scan, test]
```

Use an exact component version or reviewed commit SHA in production.

## Inputs

| Input | Default | Purpose |
| --- | --- | --- |
| stage | test | Stage that runs after scanner jobs |
| job-name | sdlc-evidence | Unique collector job name |
| application | $CI_PROJECT_NAME | Application label |
| repository | $CI_PROJECT_PATH | Repository identity |
| release-id | $CI_COMMIT_REF_NAME | Release identity |
| artifacts-dir | artifacts | Existing scanner reports |
| attestations-dir | empty | Release attestations |
| exceptions-dir | empty | Approved waiver files |
| catalog | empty | Custom control catalog path |
| collector-version | 3.2.0 | Exact package version |
| fail-on | conditional | Failure threshold |

The job records the pipeline commit SHA, the pipeline ID as the pipeline run
and the job ID as the build. On a tag pipeline the tag is recorded as the
release tag. GitLab gives tag pipelines no branch, so the branch field takes
`CI_DEFAULT_BRANCH`; branch and merge request pipelines record their own
branch. The job writes `release-evidence/`
with a 30-day GitLab artifact expiry. Set artifact access restrictions in your
project according to the sensitivity of the supplied evidence. Input values
are passed as quoted arguments, including paths and names with spaces.

## Scope and validation

The component collects local files supplied by earlier jobs. Scanner execution,
credential management and regulatory submissions remain separate workflows.
The release verdict follows the selected catalog and the collector's documented
evidence rules. A presence check alone cannot establish that a security control
is effective.

The component pipeline tests an SBOM, a custom catalog, names and paths with
spaces, the release commit, tag and pipeline identity, bundle verification and
all three outputs. Tag pipelines run those checks before the Catalog release job.

Collector documentation and license:
[Secure SDLC Evidence Collector](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector).
Component source uses Apache-2.0. The installed collector package includes its
own dependency and third-party notices.

## Version updates and rollback

Version 1.0.0 installs collector 3.2.0 and pip 26.2.1. Python and the release
CLI images are pinned by digest. The collector's transitive dependencies are
resolved by PyPI at installation time; an exact collector version alone does
not lock the full dependency tree.

Test component and collector updates in a separate pipeline before changing
the pinned include. To roll back, restore the last reviewed component version
or commit SHA and the previous `collector-version` input. Preserve existing
bundles with their original commit and catalog hashes. Report component issues
in this project's issue tracker, with a sanitized pipeline log and the pinned
version. Do not attach credentials or private evidence bundles.
