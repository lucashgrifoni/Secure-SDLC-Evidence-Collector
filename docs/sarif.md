# Control gaps as SARIF

`sdlc-evidence sarif` writes the controls a release did not meet as a
SARIF 2.1.0 log, so they show up in a code scanning dashboard next to
the findings of the scanners that fed the bundle. How the collector
reads the SARIF your scanners write is described
[at the end of this page](#how-scanner-sarif-is-read).

```sh
sdlc-evidence sarif output/sample_release/bundle.json -o gaps.sarif
```

Run it from the repository root: code scanning resolves the result
location against the root, so the bundle path is written relative to
the working directory.

## What goes in

One result per control the bundle evaluated as `missing` or `partial`.
Controls that are `met`, `waived` or `not_applicable` are left out; a
waiver already records its owner, reason and expiry in the bundle.

| Field | Value |
|---|---|
| `ruleId` | the control id, for example `ORG-CODE-REVIEW` |
| `level` | `error` for critical and high controls, `warning` for medium, `note` for low |
| `message` | the control, its status, and the evidence types it still lacks: required ones for a `missing` control, recommended ones for a `partial` control |
| `security-severity` (rule property) | 9.0, 7.0, 5.0 or 3.0 by criticality, which GitHub uses to rank the alert |
| `help` (rule) | every distinct remediation hint the bundle's gap list gives for the control |
| location | the bundle path relative to the working directory, line 1, because a control gap has no line of source code; a bundle outside the working directory is named by its file name |
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

## How scanner SARIF is read

Every `runs[]` entry of a scanner's SARIF becomes one evidence record.
The driver name picks the evidence type (see
[limitations §2](limitations.md#2-sarif-classification-heuristic)), and
the results decide its status.

| SARIF content | What the collector does |
|---|---|
| `result.level` | Used as is: `error` is high, `warning` medium, `note` low, `none` info. |
| No `level`, `kind` other than `fail` | Level `none` (info). |
| No `level` | The `defaultConfiguration.level` of the rule the result references through `ruleIndex`, `rule.index`, `ruleId` or `rule.id`, in the driver or in the `tool.extensions` entry `rule.toolComponent` names; `warning` when no rule sets one. |
| Rule property `security-severity` | Raises the bucket to critical (9.0 and up), high (7.0) or medium (4.0) when that is above the level's bucket. It never lowers it. |
| `invocations[].executionSuccessful: false` | The record is `invalid` at low confidence and does not satisfy a control. |
| No `results` array | Zero findings, low confidence, `metadata.results_absent: true`, and a warning. SARIF reserves `results: []` for a run that found nothing. |
| Error-level `toolExecutionNotifications` or `toolConfigurationNotifications` | Low confidence, `metadata.tool_error_notifications`, and a warning. The status is unchanged. |
| `suppressions` all `accepted` or without a status | Not an open finding: left out of the counts, recorded in `metadata.suppressed_count` and named in the summary. |
| A suppression `underReview` or `rejected` | Still an open finding. |

A scan fails when it has a critical or high open finding. A
`secrets_scan` fails on any open finding, because every result of a
secret scanner is a detected secret; its counts keep the level the
scanner reported. Metadata keys appear only when their condition
occurs, so a plain run produces the same record as before.

The parser does not apply `ruleConfigurationOverrides`, does not fetch
external property files, and does not open the URIs a result points to.

Tests run these rules against output captured from real tools: Semgrep,
Gitleaks, KICS and Checkov SARIF, Trivy JSON and pytest JUnit. Each
capture sits in `tests/fixtures/real/<tool>/` with a README that records
the tool version and the command. CodeQL, Grype, OSV-Scanner and ZAP
output have no capture there yet.
