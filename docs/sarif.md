# Control gaps as SARIF

`sdlc-evidence sarif` writes the controls a release did not meet as a
SARIF 2.1.0 log, so they show up in a code scanning dashboard next to
the findings of the scanners that fed the bundle.

```sh
sdlc-evidence sarif output/sample_release/bundle.json -o gaps.sarif
```

## What goes in

One result per control the bundle evaluated as `missing` or `partial`.
Controls that are `met`, `waived` or `not_applicable` are left out; a
waiver already records its owner, reason and expiry in the bundle.

| Field | Value |
|---|---|
| `ruleId` | the control id, for example `ORG-CODE-REVIEW` |
| `level` | `error` for critical and high controls, `warning` for medium, `note` for low |
| `message` | the control, its status, and the required evidence types still missing |
| `security-severity` (rule property) | 9.0, 7.0, 5.0 or 3.0 by criticality, which GitHub uses to rank the alert |
| `help` (rule) | the remediation hint from the bundle's gap list, when it has one |
| location | the bundle file name, line 1: a control gap has no line of source code |
| `partialFingerprints` | `controlId/v1` set to the control id, so the same gap keeps one alert across releases |

The log carries no timestamps and every list is sorted, so the same
bundle always produces the same bytes. A release with no unmet controls
produces a log with an empty `results` list, which closes any open
alerts from earlier uploads.

## Uploading is up to you

The collector writes the file and stops there. It does not upload
SARIF and does not fail the build on gaps; the release verdict and its
exit code stay with `run` and `evaluate`. To send the log to GitHub
code scanning, add an upload step after the command, for example:

```yaml
- run: sdlc-evidence sarif output/bundle.json -o gaps.sarif
- uses: github/codeql-action/upload-sarif@<pinned-sha>
  with:
    sarif_file: gaps.sarif
    category: release-evidence
```

The upload step needs `security-events: write`. On a private repository
code scanning also needs GitHub Advanced Security.
