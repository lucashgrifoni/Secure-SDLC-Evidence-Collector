# Known limitations

This document spells out what the Secure SDLC Evidence Collector **does
not** do, where heuristics can produce false positives or false negatives,
and which scenarios require human interpretation on top of the bundle.
Publishing these limits up-front is part of the project's public
contract: the tool aims at traceable honesty, not marketing.

## 1 · Not a scanner

- The collector **does not scan source code, containers, or
  infrastructure**. It ingests the output of third-party tools.
- Rule selection, severity thresholds, and exploitability labels are
  decided by the upstream scanner. We never override them.
- If a scanner misses a vulnerability, the collector cannot synthesize
  it. Reference evidence is the signal, not the ground truth.

## 2 · SARIF classification heuristic

SARIF is a format, not a taxonomy. A single SARIF file may contain
multiple `runs` from different tools with overlapping intent (Trivy
exports vuln + secret + misconfig in one file; Snyk exports SAST + SCA
separately; Sonar exports a mix). The collector classifies each `run`
into exactly one `evidence_type` based on the driver name.

- **False-positive risk**: a Trivy SARIF with a vuln run and a secret
  run in the same file is classified as `sca_scan`; the secret run is
  counted under SCA rather than under `secrets_scan`. Mitigation:
  export Trivy's secret scan into a separate file (`trivy fs --scanners
  secret --format sarif --output trivy-secrets.sarif`) or provide the
  output of a dedicated secrets tool (Gitleaks/TruffleHog).
- **False-negative risk**: an unknown driver defaults to `sast_scan`.
  If the driver was actually a DAST tool, the `sast_scan` control is
  credited while `dast_scan` remains missing.
- Mitigation: the classification heuristic and the fallback label are
  both documented in the bundle's `evidence[*].rationale` field, so
  reviewers can see why the collector chose a label.

## 3 · Evidence quality is shallow

The collector checks **presence**, not correctness.

- A SAST SARIF with **zero findings** still satisfies the `sast_scan`
  control — the control asks "was a scan run?", not "was the scan
  effective?".
- Attestations are validated against a Pydantic schema (shape,
  required fields, `extra='forbid'`) but the **content** of those
  fields is not audited. A `release_approval.yaml` naming `Approver:
  joe@example.com` is accepted at face value.
- Suppressions (e.g. `.semgrepignore`, CodeQL `# lgtm[...]`) are
  visible only if the underlying scanner reports them in its SARIF.
  The collector does not flag "scan ran but everything was
  suppressed".

## 4 · Control catalog is small on purpose

- The default catalog has **13 controls** focused on widely supported
  SSDF + OWASP SAMM practices plus four org-internal controls.
- It is **not** a full SSDF implementation (PS.1, PS.3-partial, PW.2,
  PW.5, PW.6, RV.* are out of scope). Custom catalogs via `--catalog`
  are the supported extension point.
- Criticality values are advisory. The release-status rule only cares
  about `critical` and `high`; `medium` and `low` controls drop the
  verdict to `conditional` at worst.

## 5 · SCM coverage

- Only GitHub and GitLab are first-class. Azure DevOps and Bitbucket
  are on the roadmap but not implemented.
- "Last approval after last commit" for GitHub looks at REST
  `/pulls/:n/reviews`. Dismissed reviews and draft reviews are ignored.
  Required-reviewer policies on protected branches are not checked.
- Code-review evidence from providers without reviewer metadata (e.g.
  signed-off-by on plain git) is not parsed; supply a
  `code_review.yaml` attestation instead.

## 6 · DAST coverage

- The ZAP parser reads ZAP's JSON baseline/full-scan reports. Nuclei,
  Burp XML, Wapiti, and ZAP's automation framework output are not
  parsed.
- If a release's DAST evidence is a screenshot or a PDF, it must be
  attested via `dast_scan` in `generic_attestation.yaml` with a link.

## 7 · Signing verification

- The collector records `artifact_signature` **presence** (a file
  exists and declares the signed digest). It does **not** verify the
  signature against a key or an identity.
- Verification of cosign keyless signatures is expected upstream (for
  example in the `release.yml` workflow or on the consumer side). The
  project's own release workflow signs its artifacts; downstream
  consumers still need to run `cosign verify-blob` themselves.

## 8 · Determinism boundaries

- Bundle JSON is deterministic for a fixed set of inputs **after
  stripping** four per-run timestamp fields: `generated_at`,
  `evaluated_at`, `collected_at`, and the release-unique `bundle_id`.
  Those four fields intentionally change per run; everything else
  (including `evidence_id`, which is derived from a SHA-256 of the
  input artifact and context, not from a random UUID) is stable.
- File iteration order depends on the filesystem. The collector sorts
  paths before ingestion, so Linux and Windows should produce the same
  bundle — the `test_sample_release_bundle_is_stable_across_artifact_reorder`
  regression test catches drift if this ever changes.

## 9 · Performance envelope

- Individual artifact hard cap: **25 MB**.
- No concurrency inside a single `run`; a 100-artifact bundle is
  processed serially. Benchmarks on the sample and lab fixtures finish
  under 2 s; releases with hundreds of SARIF files will take longer.
- No streaming mode: every artifact is parsed into memory and held
  until export. Very large bundles may need a catalog split.

## 10 · Scope out of bug-bounty

These are explicitly out of scope for security reports (see
`SECURITY.md`):

- issues in third-party SARIF / SBOM parsers we call,
- DoS that requires privileged filesystem access,
- missing security headers in the `summary.html` artifact when served
  outside the tool's default invocation.

## 11 · Things the verdict does **not** imply

- `ready` does **not** mean "legally compliant with SSDF / PCI-DSS /
  SOC 2 / ISO 27001". It means "every required critical and high
  control in the active catalog has evidence attached".
- `conditional` does **not** mean "ship at your own risk". It means
  "medium-criticality gaps or only recommended-evidence gaps remain —
  review them before promotion".
- `not_ready` does **not** automatically mean "the release is
  broken". A critical control without evidence may also reflect an
  immature evidence pipeline rather than an unsafe release.

## 12 · When results need human interpretation

- SARIF from a scanner run with `--severity=low` — the collector
  records it, but the release manager has to decide whether a
  low-severity-only run counts as a meaningful SAST check.
- Waivers (`exceptions/*.yaml`) that are expired vs. valid — the
  collector flags expiry but never decides whether the waiver should
  have existed.
- DAST coverage on an API release where only UI was scanned — the
  collector sees a `dast_scan`, not its coverage.
