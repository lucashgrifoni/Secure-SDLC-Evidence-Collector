# Upgrading

Changes that can move a verdict, an exit code or an output between
releases, newest first. The changelog lists every change; this page lists
the ones you may need to act on.

## Unreleased

### Scanner results are read as the scanner reported them

Verdicts can get stricter on unchanged scanner files. The sample release
is unaffected: its bundle digest and its `ready` verdict stay the same.

- SARIF results with no `level` take the level of the rule they reference
  (`defaultConfiguration.level`), then `warning`, as SARIF 2.1.0 §3.27.10
  says. Real Semgrep, Gitleaks and KICS output is written this way, so an
  `ERROR` rule hit that used to count as medium now counts as high and
  fails `sast_scan`. A rule's `security-severity` can raise a bucket.
  Results whose `kind` is not `fail` now count as info.
- A SARIF run whose invocation reports `executionSuccessful: false` is
  `invalid` and no longer satisfies its control.
- Any open result in a `secrets_scan` fails it, whatever its level. This
  covers secret scanner SARIF (Gitleaks and others) and the secret class of
  a native Trivy JSON report. The finding counts keep the scanner's level.
- Checkov, KICS, tfsec and Terrascan SARIF is `iac_scan` instead of
  `sast_scan`. A release that relied on Checkov alone for SSDF-PW.7 now
  shows that control as missing; add a SAST scanner. Their evidence ids
  start with `iac-` instead of `sast-` (Checkov) or `scan-`.
- SARIF results with only `accepted` (or status-less) suppressions, such
  as `# nosemgrep` lines, are no longer counted as findings. The number
  is recorded in `metadata.suppressed_count` and named in the summary.
- A SARIF run with no `results` array, or with error-level tool
  notifications, is recorded at `low` confidence with a warning on the
  console and in NDJSON logs; its status does not change.
- JUnit counts are the larger of each suite attribute and the matching
  `<testcase>` elements, and negative attributes read as 0. A report
  whose suite omits `failures` but holds a failing test case now fails
  `test_result`.
- OSV-Scanner `groups` are honoured: aliases of one issue count as one
  finding, so `total_findings` can go down. CVE ids are unchanged.
- A clean native Trivy report, which has no `Results` key, is recognised
  instead of being listed as matching no parser. It still produces no
  evidence.
