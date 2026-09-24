# Sample exceptions

This directory exists **only** to demonstrate the `sdlc-evidence
exceptions` CLI surface against a real, schema-valid file. It is
intentionally separate from `examples/sample_release/attestations/`
because attestations and exceptions are different concepts:

- `attestations/` — **positive** evidence the controls require.
  Loaded by default in the sample-release smoke run, which is why
  the sample produces `release_status = ready` with all 13 controls
  met.
- `exceptions/` — **time-bound waivers** that the release manager
  uses to record an explicit decision to ship a release while a
  control's required evidence is missing. They never *replace*
  evidence; they record an approved gap with an expiry and a scope.

The single file in this directory (`EXC-2026-DEMO-001.yaml`) is
deliberately scoped to a release context that the canonical sample
fixture does **not** use:

```yaml
scope:
  application: "exceptions-demo"
  release_id:  "2026.05.05-exceptions-demo"
```

The canonical sample-release run uses `application = payments-api`
and `release_id = 2026.04.10`. Because exception scope is
exact-match on `(application, release_id)` when set, this waiver
**does not** apply to the canonical sample. That keeps the
sample-release `ready` 13/13 fixture intact while still giving the
CLI something to validate.

## Reproduce locally

Validate a single file:

```bash
python -m evidence_collector.cli.main exceptions validate \
  examples/sample_release/exceptions/EXC-2026-DEMO-001.yaml
```

List every valid exception in this directory:

```bash
python -m evidence_collector.cli.main exceptions list \
  examples/sample_release/exceptions
```

You should see one row per valid exception with the columns
`exception_id`, `control_id`, `approver`, `approved_at`, `expires_at`
and `scope`.

## Try the waiver against a release that **does** match its scope

Run the sample release with the demo `application` /
`release_id` so the waiver actually applies:

```bash
python -m evidence_collector.cli.main run \
  --application exceptions-demo \
  --repository local/exceptions-demo \
  --release-id 2026.05.05-exceptions-demo \
  --commit-sha abcdef1234567890 \
  --artifacts-dir examples/sample_release/artifacts \
  --exceptions-dir examples/sample_release/exceptions \
  --output-dir output/exceptions-demo
```

Observed output (verbatim, 2026-05-05):

```
Controls        met=5 partial=2 missing=5 waived=1 n/a=0
Release status  not_ready
Missing critical  ORG-CODE-REVIEW:code_review,
                  ORG-RELEASE-APPROVAL:release_approval,
                  ORG-REL-ROLLBACK:rollback_plan,
                  SSDF-PS.2:artifact_signature
```

The CLI records `waived=1` because the waiver scope matches and
`SSDF-PW.1` (medium) is covered by the demo exception. The release
status nevertheless stays `not_ready` because four **critical**
controls still lack required evidence (this run intentionally omits
`--attestations-dir`). That is the contract: a waiver narrows the
specific gap it covers but never flips a verdict over a missing
critical control. To turn this scenario green, add
`--attestations-dir examples/sample_release/attestations` — the
waiver still applies, but it now coexists with attestations that
already cover `SSDF-PW.1`, so the column would simply read `met=13
waived=0` (the engine prefers a real attestation over a waiver when
both are present).

## Schema (do not extend in this fixture)

The canonical schema is documented in
`src/evidence_collector/parsers/exception.py` and
`src/evidence_collector/domain/models.py::EvidenceException`. Six
fields are required (`exception_id`, `control_id`, `approver`,
`approved_at`, `expires_at`, `justification`); two optional
(`reference`, `scope`). `expires_at` must be strictly after
`approved_at`; `justification` must be ≥ 10 characters. Both
timestamps must carry a timezone — bare `2026-12-31` parses to a
naive datetime, which has no defined instant to compare a waiver
window against, and is rejected. The window is half-open:
`approved_at <= now < expires_at`, so a waiver dated in the future
does not waive anything yet. This fixture
must not introduce new fields — extending the schema is explicitly
out of scope of the maturity rounds.
