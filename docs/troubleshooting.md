# Troubleshooting

What the collector prints when a run does not go as expected, and what to do
about it. The examples come from runs of `sdlc-evidence run` on the sample
release in the repository.

## What the exit code means

`run`, `evaluate` and `bundle` turn the verdict into an exit code:

| Code | Meaning |
|------|---------|
| `0` | `ready`, or `conditional` with the default `--fail-on not_ready` |
| `1` | `conditional`, when `--fail-on conditional` (or `ready`) is set |
| `2` | `not_ready` |
| `3` | the command could not run; nothing was produced, so do not read it as a verdict |

The full matrix, and the codes of the other commands, are in the CLI reference
section [Exit codes](cli-reference.md#exit-codes).

## A conditional release exits 0

With the default `--fail-on not_ready`, only `not_ready` fails. Remove the
Semgrep SARIF from the sample artifacts and the SAST controls go missing:

```text
 Release status         conditional
 Missing critical/high  SSDF-PW.7:sast_scan, SAMM-VERIF-ST-1:sast_scan
```

That run exits `0`. The same files with `--fail-on conditional` exit `1`. Pass
`--fail-on conditional` when a missing high control must stop the pipeline.

The CI surfaces set their own default: `not_ready` for the GitHub Action and
the reusable workflow, `conditional` for the GitLab CI/CD Catalog component.
The Action and the reusable workflow also accept `fail-on: none`, which
reports the verdict without failing; the CLI has no `none` value.

## The release is not_ready because attestations are missing

Scanner output alone does not make a release `ready`. Without an attestations
directory the sample release exits `2` and names four critical controls:

```text
 Release status         not_ready
 Missing critical/high  ORG-CODE-REVIEW:code_review,
                        ORG-RELEASE-APPROVAL:release_approval,
                        ORG-REL-ROLLBACK:rollback_plan,
                        SSDF-PS.2:artifact_signature
```

Code review, release approval, rollback plan and artifact signature come from
attestation files. Start from the templates in
[`examples/attestations/`](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/tree/main/examples/attestations)
and pass their directory with `--attestations-dir`. For code review on GitHub,
`--pull-request <number>` reads the approvals instead.

If you copied the templates and the verdict is still `not_ready`, look at
their `status`. Every template ships with `status: unknown`, which satisfies
no control, and `report.md` says so for each one:

```text
Control ORG-CODE-REVIEW is not satisfied: required evidence att-... (unknown) of type code_review is present but did not satisfy it.
```

Set `status: passed` only for the practices that happened for this release.

## Collection warnings

A file the collector recognised but could not read does not stop the run. It
is listed under "Collection warnings", recorded in the bundle's
`collection_errors`, and the verdict covers whatever evidence was read. Two
examples from one run:

- a JSON file cut short:

  ```text
  Collection warnings:
    - .../artifacts/broken.json: Invalid JSON in .../artifacts/broken.json: Expecting value: line 2 column 1 (char 12)
  ```

- an attestation with a misspelled key (`stauts:` instead of `status:`). The
  file is refused rather than read with the default status, and the control
  it fed shows as missing:

  ```text
    - .../attestations/rollback_plan.yaml: Attestation .../attestations/rollback_plan.yaml has unknown fields ['stauts']; put custom data under 'metadata'. Allowed fields are [...]
  ```

An input directory that does not exist is a collection warning too
(`directory not found`), as long as another input was found. To stop a
pipeline on any of these, fail the step when `collection_errors` in
`bundle.json` is not empty; the GitHub Action exposes the count as the
`collection-errors` output.

## A file matched no parser

The collector decides what a file is from its content, not its name. A file
in `--artifacts-dir` that matches no supported format is skipped and listed
after the summary:

```text
1 file in --artifacts-dir matched no parser and was not collected:
  - ...\artifacts\notes.txt
```

Check that the scanner wrote one of the formats listed in the
[README](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector#readme),
for example SARIF rather than a tool's own text output. Files in
`--attestations-dir` must end in `.yaml`, `.yml` or `.json`; other files there
are skipped without a message.

## Exit 3: the command could not run

Exit `3` means no verdict was computed. The messages seen most often:

- no input at all:

  ```text
  no evidence source was given (--artifacts-dir, --attestations-dir, --exceptions-dir, --pull-request or --workflow-run); nothing was collected and no bundle was written
  ```

- every input directory missing:

  ```text
  none of the input directories exist (...); nothing was collected and no bundle was written
  ```

- a required option missing, or a value the option does not accept:

  ```text
  Error: Missing option '--repository'.
  Error: Invalid value: --fail-on must be one of ['ready', 'conditional', 'not_ready']; got 'banana'.
  ```

`--verbose` prints the traceback for a failure that is not a usage error.

## Windows shells

### PowerShell line continuation

PowerShell does not read a trailing backslash as a line continuation. A
command copied in the bash form fails before it starts:

```text
ParserError: ...
Line |
   2 |   --application payments-api \
     |     ~
     | Missing expression after unary operator '--'.
```

End each line with a backtick (`` ` ``) instead, as in the PowerShell examples
of [Getting started](getting-started.md), or put the whole command on one line.

### Git Bash rewrites container paths

Git Bash converts arguments that look like absolute Unix paths into Windows
paths before Docker sees them. `--artifacts-dir /workspace/artifacts` reaches
the container as a path under the Git installation, so the run finds no input
and exits `3`:

```text
none of the input directories exist (C:/Program Files/Git/workspace/artifacts); nothing was collected and no bundle was written
```

Prefix the `docker run` command with `MSYS_NO_PATHCONV=1`, or run it from
PowerShell. Relative paths such as `examples/sample_release/artifacts` are
not rewritten, so the pip-installed CLI runs from Git Bash as shown in
[Getting started](getting-started.md).
