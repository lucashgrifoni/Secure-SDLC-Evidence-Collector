# Attestation templates

Starting points for the evidence that no scanner produces: a review, an
approval, a rollback plan, a signature. Copy the files you need into the
directory you pass to `--attestations-dir`, then fill them in.

| File | Evidence type | Controls in the default catalog |
|------|---------------|---------------------------------|
| `code_review.yaml` | `code_review` | `ORG-CODE-REVIEW` (critical) |
| `pr_metadata.yaml` | `pr_metadata` | `ORG-CODE-REVIEW` (recommended) |
| `release_approval.yaml` | `release_approval` | `ORG-RELEASE-APPROVAL` (critical) |
| `rollback_plan.yaml` | `rollback_plan` | `ORG-REL-ROLLBACK` (critical) |
| `artifact_signature.yaml` | `artifact_signature` | `SSDF-PS.2` (critical); recommended by `SSDF-PS.3`, `SAMM-IMPL-SB-2` |
| `artifact_attestation.yaml` | `artifact_attestation` | recommended by `SSDF-PS.2`, `SSDF-PS.3`, `SAMM-IMPL-SB-2` |
| `threat_model.yaml` | `threat_model` | `SSDF-PW.1`, `SAMM-DESIGN-TA-1` (medium) |

## They do not pass as shipped

Every template has `status: unknown`, which satisfies no control. A copy that
nobody filled in shows up in the report as present but not satisfying, for
example:

```text
Control ORG-CODE-REVIEW is not satisfied: required evidence att-1f4b9acd377e (unknown) of type code_review is present but did not satisfy it.
```

Set `status` to `passed` (or `completed`) only when the practice the file
describes happened for this release, and `failed` when it did not pass. The
collector checks the shape of these files, not whether what they say is true
([limitations §3](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/blob/main/docs/limitations.md)),
so the person who sets the status is the control.

With the sample scanner output, the templates as shipped give `not_ready`
(exit `2`), and the same files with `status: passed` give `ready` (exit `0`):

```bash
sdlc-evidence run \
  --application example-app \
  --repository example-org/example-app \
  --release-id 1.0.0 \
  --commit-sha abcdef1234567890 \
  --artifacts-dir examples/sample_release/artifacts \
  --attestations-dir examples/attestations \
  --output-dir output/templates
```

## Fields

| Field | Required | Values |
|-------|----------|--------|
| `evidence_type` | yes | an evidence type such as the ones in the table above |
| `producer` | yes | who or what made the statement |
| `subject_ref` | yes | what it is about: a pull request, a release, an artifact |
| `subject_type` | no | `release` (default), `pull_request`, `artifact`, `application`, `repository`, `commit`, `build`, `workflow_run` |
| `status` | no | `completed` (default), `passed`, `generated` satisfy a control; `failed`, `invalid`, `missing`, `unknown` do not |
| `confidence` | no | `medium` (default), `high`, `low`. A control whose supporting evidence includes an attestation is reported one level lower |
| `generated_at` | no | ISO 8601 date and time |
| `summary` | no | one line for the report |
| `approver`, `ticket`, `change_ticket`, `link` | no | stored under `metadata` |
| `metadata` | no | free-form; recorded in the bundle, not evaluated |

Any other top-level key is refused, and the file becomes a collection error
instead of evidence, so a typo such as `stauts:` cannot leave the default
status in place. Put custom data under `metadata`. Files must end in `.yaml`,
`.yml` or `.json`; other files in `--attestations-dir` are skipped without a
message.

The release id and commit come from the `run` options, not from the file, so
the same file is read as evidence of whichever release you run it for. Keep
one directory per release, or regenerate the files in the pipeline.

Every name, address and URL in these templates is a placeholder on
`example.com` or similar. Do not put tokens or credentials in an attestation:
it is copied into `bundle.json`.
