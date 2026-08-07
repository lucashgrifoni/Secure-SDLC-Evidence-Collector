# ADR 0007 — in-toto Statement predicate type variants

- Status: accepted
- Date: 2026-05-19
- Deciders: Lucas Henrique Grifoni
- Supersedes: none
- Superseded by: none

## Context

Tier 5.5 added the `sdlc-evidence statement` command, which wraps an
`EvidenceBundle` as an in-toto Statement v1 with a single
predicateType:

```
https://github.com/lucashgrifoni/secure-sdlc-evidence-collector/predicate/sdlc-evidence/v1
```

That URI is project-native and unique, which is correct for declaring
"this attestation carries Secure SDLC evidence." It is also the wrong
URI to advertise when the downstream verifier gates on a specific
predicateType from the Witness or SLSA ecosystems. Two concrete cases
surfaced during Tier 6 / v2.0 planning:

1. **Witness-based verification.** Witness
   (https://witness.dev) emits and consumes in-toto Statement v1
   envelopes with predicate types under the `witness.dev` namespace
   (`https://witness.dev/attestations/<attestor>/v0.1`). A Witness
   verifier configured to gate on Witness predicates ignores our
   project-native URI by design.
2. **SLSA provenance interop.** Tooling such as `slsa-verifier`,
   Kyverno verifyImages, and Sigstore policy-controller often gate on
   `predicateType == "https://slsa.dev/provenance/v1"`. Without that
   exact URI on the wire, the bundle cannot stand in for a SLSA
   provenance attestation even if the bundle carries equivalent build
   metadata.

## Decision

Add a `--predicate-type` CLI flag on `sdlc-evidence statement` with
three accepted values:

| Name | predicateType URI | Use case |
|---|---|---|
| `evidence-bundle` (default) | `https://github.com/lucashgrifoni/secure-sdlc-evidence-collector/predicate/sdlc-evidence/v1` | Project-native; current behaviour preserved as the default. |
| `witness` | `https://witness.dev/attestations/custom/sdlc-evidence/v0.1` | Witness-compatible custom attestation. Verifiers gating on `witness.dev/*` accept it without bespoke parsers. |
| `slsa-provenance` | `https://slsa.dev/provenance/v1` | SLSA Provenance v1 URI. Use when the bundle should travel where a SLSA predicate is expected. |
| `svr` (added 2026-08-07) | `https://in-toto.io/attestation/svr/v0.2` | in-toto Simple Verification Result. Use where a policy engine gates on *verified properties* rather than on raw evidence. |

For the first three variants the wire format of the in-toto Statement
and the predicate payload do **not** change: the bundle is still
embedded as `predicate` in full, the `subject` still carries the
structural SHA-256 of the bundle, and the Statement type is still
`https://in-toto.io/Statement/v1`. Only the advertised `predicateType`
differs.

### Amendment 2026-08-07 — `svr` breaks that invariant, deliberately

The `svr` variant is the first whose **predicate is not the bundle**.

in-toto vetted the SVR predicate for precisely what this project
produces: "evidence that an artifact has been evaluated against one or
more policies". Unlike `witness` and `slsa-provenance`, SVR has a
mandatory shape of its own — `verifier` (with `id` and `policies`),
`timeCreated`, and `properties` — and it is small enough that a
consumer really will validate it. Embedding a bundle there, as the
other variants do, would advertise `svr/v0.2` while shipping a body
that fails the SVR schema. Handing a verifier a predicate that lies
about its own type is the exact failure this project exists to expose,
so the variant emits a real SVR predicate instead.

Three decisions inside that predicate are worth recording:

- **`properties` lists only what passed.** One entry per control
  evaluated as MET, plus `SDLC_EVIDENCE_RELEASE_READY` when the
  bundle's own verdict is `ready`. Partial, missing, waived and
  not-applicable controls are absent. SVR states *verified* properties,
  so "not listed" must read as "not asserted", never as "asserted to be
  failing".
- **`timeCreated` reuses the bundle's `generated_at`**, not the wall
  clock, so the export stays a pure function of its input and re-running
  it on the same bundle is byte-identical. Reading the clock here would
  have made the one determinism guarantee the project sells untrue for
  this output.
- **`policies` is an empty array.** The spec permits it, and a
  ResourceDescriptor requires at least one of `uri`, `digest` or
  `content`. The bundle records no resolvable identifier for the control
  catalogue it was evaluated against, so anything non-empty here would
  be invented provenance. **Follow-up:** recording the catalogue
  identity in the bundle would let this be populated honestly, and is
  worth a future change.

Because the bundle is not carried, a consumer who needs the underlying
evidence should take one of the other three variants (or the bundle
itself) alongside the SVR.

## Consequences

- Backward-compatible: default behaviour is unchanged. Pipelines that
  do not pass `--predicate-type` keep emitting the project-native URI.
- Extensible: future verifiers that need a different URI can be added
  to the literal type and the dispatch table in
  `evidence_collector.exporters.intoto` without changing call sites.
- Honest about semantics: the `slsa-provenance` variant **does not**
  rewrite the bundle into the canonical SLSA provenance shape. It only
  changes the advertised URI so the bundle can sit where a SLSA
  predicate is expected. Consumers that need the strict SLSA build
  definition / run details fields should treat the bundle as a richer
  envelope around what would otherwise be SLSA-shaped metadata.
- DSSE envelope round-trip preserves the chosen `predicateType` (test
  pinned in `tests/unit/test_intoto_export.py`).

## Alternatives considered

- **One predicate per attestor (Witness-style).** Witness models
  attestations per attestor (git, material, product, policy, …). We
  could emit several predicates per bundle. Rejected for v2.0: the
  bundle is the unit of evidence we ship, not a collection of
  per-attestor sub-attestations. The custom Witness predicateType
  carries the whole bundle and lets Witness verifiers gate on it.
- **Embed the SLSA build definition / run details in the predicate.**
  Tempting for the `slsa-provenance` mode, but the bundle already
  contains the source release context (`release_id`, `commit_sha`,
  `pipeline_run_id`, `build_id`, `tag`), so re-shaping would duplicate
  data and create a second source of truth. Deferred to a future ADR
  if downstream SLSA tooling proves too strict in practice.
- **Negotiate the predicateType via a config file.** Possible but
  premature: three options are enough today, and a CLI flag keeps the
  decision visible in pipeline definitions.

## Verification

Run `python -m pytest tests/unit/test_intoto_export.py -k predicate`
to exercise the variants. Each variant emits the advertised
predicateType, preserves the subject digest, and survives the DSSE
base64 round-trip.
