# How the Secure SDLC Evidence Collector compares to adjacent tools

This page is an honest crosswalk: where the collector overlaps with
existing tools, where it differs, and where it is the wrong choice.
Items marked "honesty check" call out where another tool is better
at a specific job. Every claim here can be verified against the
linked project's docs.

## Positioning in one sentence

The Secure SDLC Evidence Collector is the **release-readiness
evidence layer**: it ingests the output of every scanner and
attestation tool, normalises it into a single canonical
`EvidenceBundle`, evaluates it against a control catalog (NIST SSDF
1.1 / 1.2 / AI Profile / FedRAMP 20x KSI / OSPS Baseline), and emits
an audit-ready JSON + report. It does **not** scan, sign, or enforce; it makes the
"did this release meet our Secure SDLC bar?" question answerable
from one document.

## Side-by-side matrix

| Product | Primary focus | Overlap with the collector | What's clearly better elsewhere |
|---|---|---|---|
| **Chainguard Enforce** ([docs](https://edu.chainguard.dev/chainguard/enforce/overview/)) | Image hardening + admission control for Kubernetes | Cosign + attestation consumption | Image-level hardening, OCI ecosystem, admission policy at deploy time |
| **Scribe Security (Trust Hub)** ([docs](https://scribesecurity.com/)) | End-to-end SBOM + provenance + policy-as-code SaaS | SBOM ingest, attestation, evidence model | Hosted UI, customer support, signed analytics; collector ships OSS only |
| **GUAC** (OpenSSF Incubating, [docs](https://docs.guac.sh)) | Graph of supply-chain metadata | The collector emits a GUAC-ingest container (T6.9) | Graph queries, blast-radius analysis, cross-org search |
| **Kusari Trustify** ([docs](https://github.com/trustification/trustify)) | Backend search for supply-chain metadata (contributed into GUAC) | None — collector is upstream of Trustify | Hosted backend for SBOM search; collector produces input documents |
| **Lineaje** ([site](https://lineaje.com/)) | SaaS supply-chain integrity + remediation | SBOM ingest, dependency risk | Vendor-driven remediation, commercial support |
| **OpenSSF Scorecard** ([docs](https://github.com/ossf/scorecard)) | Health score for OSS repos | Both reference SSDF practices | Heuristic scoring on git history; the collector consumes Scorecard as evidence |
| **Snyk / Mend / Sonatype** | Commercial SCA + SBOM platforms | SCA findings via SARIF / OSV | Curated vuln intelligence, fixes, dashboard; collector consumes their SARIF |
| **CodeQL reachability / Endor Labs / Semgrep Pro** | Reachability-aware vuln triage | Collector records their verdict via `Reachability` field (§3.2) | Re-deriving reachability — collector never does this itself |

## Where the collector is the right answer

- You need a **single signed JSON** that proves a release followed
  Secure SDLC, ingestible by GUAC, Kyverno, OPA, Sigstore
  policy-controller, or a custom verifier.
- You ship to a regulator (CRA 2026, FedRAMP 20x) that wants a
  machine-readable evidence pack instead of a PDF.
- You want SBOM + SARIF + attestation + waiver + AI evals + EPSS +
  KEV traveling together with the same `release_id` /
  `commit_sha`, with a deterministic structural hash.
- You distrust scoring theater and want a verdict that calls out
  the specific missing required evidence (not "92 %").

## Where the collector is the wrong answer

- **Honesty check.** If you need a hosted UI with trend analysis
  across thousands of releases, **Scribe Trust Hub** is built for
  that. The collector is CLI-first and stateless by design.
- **Honesty check.** If you need image-runtime enforcement,
  **Chainguard Enforce** has the admission-controller side covered;
  the collector emits the attestation, not the gate at the runtime
  edge.
- **Honesty check.** If you need a query language over an
  organisation-wide supply-chain graph, **GUAC** is the right
  place — the collector is one of GUAC's many sources (T6.9 closes
  this with the GUAC adapter).
- **Honesty check.** If you need to *generate* findings, you need a
  scanner. The collector intentionally does not scan; it consumes
  scanner output.

## What "OSS canonical" means here

- Apache-2.0, no telemetry, no signed binary download outside
  GitHub Releases.
- Every format the collector emits is an open standard: SARIF,
  CycloneDX (1.5–1.7), SPDX, OpenVEX 0.2.0, OSCAL 1.1.2, in-toto
  Statement v1 + DSSE, SLSA Provenance v1, OSV Schema, GUAC
  collector container.
- The control catalog is YAML; teams override or extend it without
  forking the project. Five catalogs ship today: NIST SSDF 1.1
  (default), SSDF 1.2 preview, FedRAMP 20x KSI, OSPS Baseline, and
  the AI Profile.

## When to combine

| Goal | Stack |
|---|---|
| Public OSS release with audit trail | Collector + Sigstore (cosign keyless) + SLSA generic generator |
| Continuous ATO with continuous evidence | Collector + GUAC (via T6.9 adapter) |
| AI / LLM product with SDLC AI Profile | Collector + garak + lm-eval + Hugging Face model cards |
| EU CRA disclosure pipeline | Collector with `--profile cra-2026` + ENISA intake |
| FedRAMP 20x evidence pack | Collector with `--catalog catalog-fedramp-20x-ksi.yaml` + OSCAL export |

## Asking the inverse question

The collector does not aim to replace any of the tools above. The
inverse question — "could any of them replace the collector?" — has
a single-line answer today: **none of them are OSS, format-neutral,
and exclusively focused on release-readiness evidence**. That niche
is where this project lives. Where the niche overlaps with another
tool's roadmap, the right move is to interop (GUAC ingest, OpenVEX
emission, OSCAL export), not to compete.

If you find this comparison page misrepresents your project,
**please open a Discussion or PR**. The project commits to keeping
this page honest — it is part of the public contract.
