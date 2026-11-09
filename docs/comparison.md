# How the Secure SDLC Evidence Collector compares to adjacent tools

This page is a crosswalk: where the collector overlaps with existing tools,
where it differs, and where another tool is the better choice. Items marked
"honesty check" call out a job that another tool does better. Facts about
other projects were checked against their own repositories and docs on
**2026-11-09** and are re-checked at each minor release; the sources are
linked in the tables. Release numbers are the latest seen on that date.

## Positioning in one sentence

The Secure SDLC Evidence Collector is a **release-readiness evidence layer**:
it reads the output of scanners, test runners and attestation tools,
normalises it into one canonical `EvidenceBundle`, evaluates it against a
control catalog (NIST SSDF 1.1 by default; SSDF 1.2 preview, AI Profile,
FedRAMP 20x CR26 and OSPS Baseline as opt-ins), and writes a deterministic
JSON bundle plus Markdown and HTML reports. It does not scan, sign or store
anything, and it gates only through its exit code.

## Closest open-source peers

These tools answer a similar question ("did this build meet our bar?") and
are open source. Each makes different trade-offs.

| Project | License, latest release | What it does | Overlap with the collector | Where it differs |
|---|---|---|---|---|
| **Chainloop** ([repo](https://github.com/chainloop-dev/chainloop), [material types](https://docs.chainloop.dev/concepts/material-types)) | Apache-2.0, v1.134.0 (2026-11-09) | A CI CLI sends build outputs to content-addressable storage and references them in signed in-toto attestations. Workflow contracts declare the required materials; Rego policies attached to the contract are evaluated and the result goes into the attestation. Its material types include SBOM, SARIF, OpenVEX, CSAF, JUnit, GitLab security reports and a generic `EVIDENCE` type. | High: per-build collection in CI, SBOM/SARIF/VEX/JUnit ingestion, a contract that plays the role of a control catalog, a policy verdict | Chainloop has a control plane (hosted by default, self-hostable with Helm) that stores and signs evidence. The collector is stateless: no server, no storage, no signing. It writes a deterministic bundle with a catalog-mapped verdict, time-bound waivers, EPSS/KEV/CVSS 4.0 enrichment and OSCAL, OpenVEX and SARIF exports. |
| **in-toto Witness + Archivista** ([witness](https://github.com/in-toto/witness), [archivista](https://github.com/in-toto/archivista), [policy docs](https://witness.dev/docs/docs/concepts/policy/)) | Apache-2.0; witness v0.12.0 (2026-07-10), archivista v0.11.1 (2025-10-30) | Attestors capture build context and sign attestation collections. `witness verify` checks signatures, trusted functionaries, step chaining and embedded Rego; Archivista stores and indexes the attestations. | Medium: in-toto predicates and policy over evidence | Witness produces and verifies signed attestations at build time. The collector reads many scanner formats and evaluates them against catalogs; it neither signs nor verifies signatures. `statement --predicate-type witness` only uses a `witness.dev`-namespaced predicate URI; it has not been tested with `witness verify`. |
| **AMPEL** ([repo](https://github.com/policylabs/ampel), [SLSA blog](https://slsa.dev/blog/2025/10/slsa-e2e-with-ampel)) | Apache-2.0, v1.5.0 (2026-11-01) | A CEL policy engine over in-toto attestations and Sigstore bundles. Transformers normalise scanner output, policies link to OSCAL catalog controls, and results come out as a ResultSet, a SLSA VSA or an in-toto SVR, optionally signed. | High on the verdict side: a release gate over SBOM, test, OSV and VEX evidence, framework mapping, SVR output (the collector also writes SVR) | AMPEL verifies signatures and evaluates policy per subject. The collector normalises raw tool output into one bundle with human-readable reports. AMPEL emits a VSA; the collector does not. |
| **Conforma**, formerly Enterprise Contract ([repo](https://github.com/conforma/cli)) | Apache-2.0 | `ec validate image` verifies image signatures and attestations (SLSA provenance) and evaluates Rego policies, reporting successes and violations. | Medium: a policy verdict over a release artifact's supply-chain attestations | Conforma is built around OCI images and signed attestations in a registry. The collector is file-based and also covers scanner, test, approval and AI evidence. |
| **GUAC** and **Trustify** ([guac](https://github.com/guacsec/guac), [trustify](https://github.com/guacsec/trustify), [OpenSSF](https://openssf.org/blog/2025/08/27/trustify-joins-guac/)) | Apache-2.0; GUAC v1.1.0 (2026-03-13), OpenSSF Incubating. Trustify was developed by Red Hat and contributed to the GUAC community. | A graph database and query layer over an organisation's SBOMs, attestations and vulnerability data. | Low to medium: `sdlc-evidence guac` writes an index that routes a release's SBOMs and in-toto attestations to `guacone collect files` | GUAC answers graph queries across an organisation; the collector answers whether one release is ready. GUAC does not read the collector's container itself, only the documents it points to (see [GUAC](guac.md)). |
| **OpenSSF Scorecard** ([repo](https://github.com/ossf/scorecard)) | Apache-2.0 | Heuristic security-posture checks on a repository. | Both reference secure-development practices | Scorecard scores repository settings and history. The collector does not use Scorecard results as evidence: a Scorecard SARIF run is recognised and skipped (a Scorecard-only file is listed as an ignored artifact), so it never counts as SAST. |

## Commercial and SaaS alternatives

| Product | Primary focus | Overlap with the collector | Where it differs |
|---|---|---|---|
| **Kosli** ([attestations](https://docs.kosli.com/getting_started/attestations.md), [CLI, MIT](https://github.com/kosli-dev/cli)) | Flows and trails with templates of required attestations; built-in types (pull request, JUnit, Snyk, SBOM, Jira, SonarQube) and custom types validated with a JSON Schema and jq rules; `kosli assert artifact` gates a deployment | High: templates of required evidence, compliance by attestation, a CI gate | Evaluation and storage happen in the Kosli service, which also tracks runtime environments. The collector runs locally or air-gapped on open formats; it has no per-type content rules and no evidence vault. |
| **JFrog Evidence Collection / AppTrust** ([blog](https://jfrog.com/blog/evidence-collection-with-jfrog/)) | `jf evd create` attaches signed evidence to artifacts, builds, packages and release bundles, with promotion gated on evidence | Medium: per-release evidence with a promotion gate | Tied to Artifactory and its paid plans. The collector is vendor-neutral and works offline. |
| **Scribe Security (Valint)** ([sample policies](https://github.com/scribe-public/sample-policies)) | Generates and signs SBOMs and provenance and checks policy rules over them | Medium: SBOM and provenance evidence with policy as code | Scribe generates, signs and hosts the evidence. Company status unverified: `scribesecurity.com` redirected to a page that returned 404 on 2026-11-09. |
| **Snyk / Mend / Sonatype** | Commercial SCA and SBOM platforms | SCA findings through SARIF or OSV | Curated vulnerability intelligence, fixes and dashboards; the collector consumes their SARIF. |
| **CodeQL reachability / Endor Labs / Semgrep Pro** | Reachability-aware vulnerability triage | The collector records their verdict in the `Reachability` field | They derive reachability; the collector never does. |

## Where the collector is the right answer

- You want one JSON document per release, with a deterministic structural
  hash, that you can sign yourself (`cosign sign-blob`, or `statement` for an
  in-toto Statement with an optional unsigned DSSE envelope) and hand to a
  policy engine or an auditor.
- You want SBOM, SARIF, attestations, waivers, AI evaluations, EPSS and KEV
  travelling together under the same `release_id` and `commit_sha`, without
  running a server.
- You want a verdict that names the specific missing required evidence
  instead of a score.
- You need a machine-readable evidence pack next to a regulatory process.
  The `cra-2026` and `fedramp-20x` profiles add reference metadata; they do
  not establish compliance.

## Where the collector is the wrong answer

- **Honesty check.** If you need evidence stored, signed and queried across
  many builds with a server and UI, **Chainloop** or **Kosli** are built for
  that. The collector is CLI-first and stateless by design.
- **Honesty check.** If you need signed attestations produced and verified
  at build time with trusted functionaries, use **Witness**, or **AMPEL** for
  policy over signed attestations. The collector does not verify signatures.
- **Honesty check.** If you need admission control at deploy time, use
  **Sigstore policy-controller**, **Kyverno** or **Conforma**. The collector's
  gate is the exit code of a CI step.
- **Honesty check.** If you need a query language over an organisation-wide
  supply-chain graph, **GUAC** is the right place. The collector can route a
  release's SBOMs and attestations to it; continuous ingestion (a `watch`
  mode) is deferred and not scheduled ([limitations §17](limitations.md)).
- **Honesty check.** If you need to *generate* findings, you need a scanner.
  The collector does not scan; it consumes scanner output.

## What "OSS canonical" means here

- Licensed `Apache-2.0 AND BSD-2-Clause` (the BSD-2-Clause part is a port of
  the FIRST CVSS reference implementation, see
  [third-party notices](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/blob/main/THIRD_PARTY_LICENSES.md)),
  with no telemetry.
- Signed distributions: the wheel, sdist, release bundle and collector SBOM
  on each GitHub Release are signed with cosign keyless, with their SHA-256
  sums in `checksums.txt`; the wheel and sdist on PyPI have the same digests
  (checked for 4.2.0), and the multi-arch container image on GHCR is signed.
  See [verifying signatures](index.md#verifying-signatures).
- Formats the collector's commands write: the evidence bundle JSON (with its
  JSON Schema), Markdown and HTML reports, SARIF 2.1.0 (`sarif`), OpenVEX
  0.2.0 (`vex`), OSCAL 1.1.2 Catalog and Assessment Results (`oscal`), and an
  in-toto Statement v1 with an optional unsigned DSSE envelope (`statement`;
  the `slsa-provenance` variant only advertises the SLSA Provenance v1
  predicate type, its body is the bundle). `guac` writes a project-defined
  container for GUAC ingestion, not a standard format. CycloneDX, SPDX and
  OSV are formats the collector reads, not ones it writes.
- The control catalog is YAML; teams override or extend it without forking
  the project. Six catalogs ship: NIST SSDF 1.1 (`catalog.yaml`, the
  default), SSDF 1.2 preview (`catalog-ssdf-1.2.yaml`), the AI Profile
  (`catalog-ai.yaml`), FedRAMP 20x CR26 (`catalog-fedramp-cr26.yaml`), OSPS
  Baseline (`catalog-osps-baseline.yaml`), and the deprecated
  `catalog-fedramp-20x-ksi.yaml`, whose IDs are not official FedRAMP KSIs.
  Use CR26 for FedRAMP; its six controls are all `high`, so it returns
  `conditional` at worst and never `not_ready`.

## When to combine

| Goal | Stack |
|---|---|
| Public OSS release with audit trail | Collector + Sigstore (cosign keyless) + SLSA build provenance |
| Evidence stored and governed across builds | Collector `bundle.json` attached to a Chainloop workflow as an `EVIDENCE` material, or to a Kosli trail with `kosli attest custom --attestation-data` (Kosli caps the data at 1 MB), checked with a custom attestation type that has a JSON Schema or jq rules over `summary` |
| Policy over signed attestations | `sdlc-evidence statement --predicate-type svr` (or the full bundle), signed by you, evaluated by a policy engine that reads in-toto attestations, such as AMPEL. Not tested end to end here. |
| Organisation-wide supply-chain graph | `sdlc-evidence guac` in the CI job that builds the bundle, then `guacone collect files` on the documents it lists ([GUAC](guac.md)) |
| AI / LLM product with the SSDF AI Profile | Collector + garak + lm-eval + Hugging Face model cards |
| EU CRA disclosure pipeline | Collector with `--profile cra-2026` + ENISA intake |
| FedRAMP 20x evidence pack | Collector with `--profile fedramp-20x --catalog catalog-fedramp-cr26.yaml` (partial supporting evidence; gate with `--fail-on conditional`, since CR26 never returns `not_ready`) + OSCAL export |

## Asking the inverse question

The collector does not aim to replace the tools above, and some of them can
replace it for teams that accept their trade-offs: Chainloop and Kosli
collect and gate evidence per build, and AMPEL evaluates release policy over
attestations. What sets the collector apart is a narrower combination: it
runs with no server, produces a deterministic bundle from raw tool output in
many formats, maps it to a control catalog, and turns the verdict into an
exit code. Where its job overlaps another tool's, the right move is to
interoperate (GUAC routing, OpenVEX, OSCAL, SARIF and in-toto output), not to
compete.

If you find this page misrepresents your project, **please open a Discussion
or PR**. Keeping this page accurate is part of the project's public contract.
