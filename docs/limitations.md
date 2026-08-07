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
- Since `v1.1.1` the bundle also surfaces a first-class
  `evidence[*].classification` field with `confidence` (`high` / `medium`
  / `low`), `reason` (`driver_match` / `manual_override` /
  `fallback_sast`) and the original `driver_name`. Downstream consumers
  can filter or weight evidence by classification confidence without
  parsing the `rationale` prose, and a `fallback_sast` reason is a
  reliable signal that the underlying tool was unknown to the heuristic.

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
- SBOM evidence carries a `metadata.cisa_2025_minimum_elements`
  presence map and a `metadata.cisa_2025_conformant` flag, checked
  against CISA's 2025 Minimum Elements for an SBOM (author, timestamp,
  supplier, component name, version, unique identifier, dependency
  relationships, hash, license, tool name, generation context). A
  component-level element is reported present only when **every**
  component carries it. This checks the SBOM's *shape*, not the
  correctness of the values — a component with a bogus license string
  still counts the `license` element as present.
- For CycloneDX 1.6/1.7, SBOM evidence also surfaces counts of ML-BOM
  components (`metadata.ml_bom`), CBOM cryptographic assets
  (`metadata.cbom`), and `declarations.attestations`
  (`metadata.cyclonedx_attestation_count`) — added only when present, so
  a classic dependency SBOM stays byte-identical to pre-1.7 bundles.
  These are presence/count signals, not a validation of the ML, crypto,
  or attestation content.
- SPDX 3.0.x JSON-LD documents (a `@context` + `@graph` of typed
  elements, rather than the 2.x `packages[]` shape) are detected and
  ingested; their AI / Dataset / Security profile element counts surface
  as `metadata.spdx_profiles`. The CISA presence check above is shaped for
  SPDX 2.x / CycloneDX and is **not** applied to SPDX 3.0 documents.

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
  example in the `publish-pypi.yml` workflow or on the consumer side). The
  project's own release workflow signs its artifacts; downstream
  consumers still need to run `cosign verify-blob` themselves.
- The same boundary applies to every in-toto attestation the collector
  ingests — SLSA provenance, VSA, and release attestations. A DSSE
  envelope or Sigstore bundle is *decoded*, never *verified*: the
  signature and the verification material are read past, not checked.
- In particular, an in-toto **release attestation** states no issuer of
  its own. The only identity in the file lives in the Sigstore
  verification material, and treating that as authoritative would be
  signature verification. The normalized evidence therefore records
  `producer = "in-toto-release-attestation"` — the format that was read —
  rather than naming an organization the collector did not authenticate.

## 7b · in-toto predicates the collector does not model

- An in-toto Statement whose `predicateType` has no dedicated parser is
  ingested as a `generic_attestation` with status `unknown`, and the
  collector logs a warning naming the predicate. It is **recorded, not
  interpreted**: no verdict is derived from it, and it satisfies no
  control on its own. This is deliberate — before it existed, such a
  Statement was dropped with no trace at all.
- Predicates that *are* modelled: SLSA provenance, SLSA VSA, the release
  predicate, `svr/v0.2`, `test-result/v0.1`, and `vulns/v0.2`.
- **`spdx3/v0.1` is a known gap.** Its predicate is an SPDX 3 document
  that should route to the SBOM parser, but `parse_sbom` reads from a
  path rather than an in-memory document. Until that is reshaped, an
  SPDX 3 Statement is ingested as a generic attestation: preserved, but
  not parsed as an SBOM and not counted toward SBOM controls.
- A DSSE-wrapped or Sigstore-bundled **VSA** also lands here rather than
  in the dedicated VSA parser, which reads raw Statements only. The
  evidence survives, but with less detail than an unwrapped VSA.

## 7c · Package-registry attestations

- PyPI (PEP 740) and npm attestations are read **from a file you saved**.
  The collector never calls a registry: no network access, no tokens, and
  the same workflow you already use for `gh attestation download`.
- What is recorded is the *envelope of publication* — which registry,
  which `publisher.kind`, and the predicate types the bundle carries. The
  embedded predicates are **not** each turned into separate evidence, so
  a SLSA provenance inside a PyPI provenance object does not currently
  satisfy build-provenance controls on its own. Save the provenance
  attestation separately if you need that.
- `publisher.kind` is recorded as the open string PEP 740 defines it to
  be, never mapped to a closed set.
- Only the *names* of `publisher.claims` are kept, not their values:
  claim values are publisher-specific and can carry repository, ref and
  workflow detail that should not land in a shareable bundle by default.
- When npm's declared `predicateType` disagrees with the Statement inside
  the signed DSSE payload, the **payload wins**. The declared field sits
  outside the signature, so trusting it would let unsigned registry
  metadata relabel an attestation.

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

## 13 · Enriched bundles are not byte-stable across EPSS / KEV feed refreshes

- `sdlc-evidence enrich` and `sdlc-evidence run --enrich` write
  EPSS / KEV signal into evidence. The structural-hash gate
  deliberately captures `epss_feed_date`, `epss_model_version`, and
  `kev_feed_date` so a feed bump (or an EPSS model-version change)
  surfaces as drift.
- This means **the same source artifacts produce different bundle
  hashes on different days when enrichment is on**. That is the
  intent: drift in the EPSS feed is meaningful, not noise.
- If a downstream signer needs a single durable hash, sign the
  **base bundle** (built without `--enrich`) and ship the enriched
  view as a separate, time-bound delta. The base bundle is
  byte-stable across runs on identical inputs.

## 14 · Risk-weighted verdict only downgrades (T6.6)

- `sdlc-evidence run --risk-mode epss-weighted` re-derives
  `release_status` using EPSS + KEV signal already in the bundle.
- The mode can only make the verdict **worse** (`ready` →
  `conditional` → `not_ready`). It will **never** promote a
  `not_ready` base verdict to `ready` just because the present CVEs
  happen not to be exploitable. Missing required evidence is its own
  gap and must be addressed at the evidence layer, not waved away.
- A CVE on evidence marked `reachability.status == "not_reachable"`
  is removed from the exploitable count. The collector trusts the
  upstream reachability tool; it does not second-guess the verdict.

## 15 · Reachability is not re-derived by the collector (§3.2)

- The `Reachability` field is populated by external tools
  (CodeQL reachability, Endor Labs, Semgrep Pro, manual review).
- The collector records `status` (`reachable` / `not_reachable` /
  `unknown`), `source`, and `method`. It does NOT compute
  reachability and will NOT contradict an upstream verdict, even
  when the data looks wrong.
- `unknown` is treated as "could be exploitable" in risk weighting
  so a missing reachability tool cannot silently suppress a real
  signal.

## 17 · Watch daemon postponed to v2.1 (T6.9)

- The roadmap pairs the GUAC adapter with a ``sdlc-evidence watch``
  daemon (webhook receiver, durable cursor, delta bundles for
  continuous ATO). That subcommand is deferred from v2.0 to v2.1
  because it requires an optional ``[watch]`` extra (FastAPI +
  uvicorn + watchdog) and durable cursor persistence the
  file-first collector deliberately avoids.
- The GUAC adapter and the CRA / FedRAMP profiles cover the
  immediate regulator-driven use cases for set/2026. The watch
  daemon is a continuous-ATO accelerator, not a v2.0 blocker.

## 16 · Multi-VEX consumer trusts the upstream verdict (T6.7)

- `sdlc-evidence vex --consume <file>` merges external VEX
  (OpenVEX, CycloneDX VEX, CSAF) into the bundle-derived statements.
- The merger **does not validate** that the consumed VEX file was
  signed or that the source is authentic. Pipelines that need that
  guarantee must verify signatures before piping the file into
  `--consume`.
- Conflict policy (`first-wins`, `last-wins`, `fail`) decides what
  happens when sources disagree. `fail` is the right choice when an
  unexpected disagreement is itself a finding.
- SPDX VEX is deferred (low industry adoption). Tracked in the v2.1
  backlog.
