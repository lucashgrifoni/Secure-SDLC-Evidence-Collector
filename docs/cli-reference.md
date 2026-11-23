# CLI reference

Every command, option group, exit code and verdict rule of `sdlc-evidence`.
For a guided first run, start with [Getting started](getting-started.md).

## Commands

```
sdlc-evidence run                    # full pipeline: collect + evaluate + export
sdlc-evidence collect                # walk directories, write evidence and collection errors as JSON
sdlc-evidence evaluate               # evaluate an existing evidence list, export bundle
sdlc-evidence bundle                 # partial alias of evaluate (no waivers, risk mode or --fail-on)
sdlc-evidence controls               # print the active control catalog
sdlc-evidence compare BEFORE AFTER   # diff two bundles (coverage, status, per-control)
sdlc-evidence oscal [--output PATH]  # render the control catalog as OSCAL Catalog JSON
sdlc-evidence oscal --kind assessment-results --bundle BUNDLE  # OSCAL Assessment Results (limits: limitations.md §22-23)
sdlc-evidence plugins                # list parser and collector entry-point plugins
sdlc-evidence schema [--output PATH] # emit JSON Schema for EvidenceBundle
sdlc-evidence doctor [--json]        # run local environment health checks
sdlc-evidence verify BUNDLE_PATH     # recompute (and optionally verify) a bundle's structural SHA-256
sdlc-evidence enrich BUNDLE_PATH     # attach EPSS + CISA KEV intelligence; re-applies a recorded --risk-mode
sdlc-evidence vex BUNDLE_PATH        # emit an OpenVEX document from a bundle
sdlc-evidence statement BUNDLE_PATH  # wrap a bundle as an in-toto Statement v1
sdlc-evidence guac BUNDLE_PATH [-o PATH]   # emit a GUAC-collector container from a bundle
sdlc-evidence sarif BUNDLE_PATH [-o PATH]  # write unmet controls as SARIF 2.1.0 for code scanning
sdlc-evidence exceptions validate PATHS... # validate one or more waiver files
sdlc-evidence exceptions list DIRECTORY    # list every valid waiver in a directory
sdlc-evidence --version
```

To merge a supplier's VEX into `vex` output, pass the file and the identifier of
your release; a consumed statement that names no product of this release is
skipped with a warning (see [limitations §16](limitations.md)):

```bash
sdlc-evidence vex output/bundle.json --consume supplier.vex.json \
  --product pkg:pypi/your-package@1.2.3
```

`--risk-mode epss-weighted` (on `run` and `evaluate`) only weighs EPSS / CISA
KEV data that is already on the evidence, and collection never attaches any.
The working flow is `run --risk-mode epss-weighted`, then
`enrich bundle.json --epss-feed ... --kev-feed ...`: `enrich` re-derives
`release_status` under the mode recorded in the bundle (a bundle built with the
default `off` keeps its verdict). `enrich` exits `0` either way, so gate on the
enriched bundle's `summary.release_status`, or pass its evidence to
`evaluate --risk-mode epss-weighted`. Details in
[limitations §14](limitations.md).

## Release context (required on `run`)

- `--application` · `--repository` · `--release-id` · `--commit-sha`
- optional: `--branch`, `--environment`, `--owner-team`, `--pipeline-run-id`,
  `--build-id`, `--artifact-digest`, `--tag`

`--environment` defaults to `production` and is recorded in the bundle as
stated fact. Set it explicitly when the run is not a production release, so the
evidence does not claim an environment nobody asserted.

### Ingestion options

- `--artifacts-dir PATH` — folder with SARIF, SBOM, JUnit files
  (repeatable). Directory links (symlinks, junctions) inside it are not
  followed; each one is reported as a collection error.
- `--attestations-dir PATH` — folder with YAML/JSON attestations
  (repeatable).
- `--catalog FILE.yaml` — override the default control catalog: a path, or
  the name of a bundled catalog with or without `.yaml` (`catalog-ssdf-1.2`
  and `catalog-ssdf-1.2.yaml` both work).
- `--artifact-root PATH` — base directory that absolute artifact paths
  are rewritten against, so the bundle records repo-relative paths
  instead of leaking local filesystem locations. Recommended in CI.
- `--exceptions-dir PATH` — folder with YAML/JSON waiver files
  (repeatable).
- `--fail-on ready|conditional|not_ready` — severity at which the exit
  status turns non-zero. Default `not_ready`; `ready` is accepted and behaves
  like `conditional`. See [Exit codes](#exit-codes).

### GitHub integration (opt-in)

```bash
export GITHUB_TOKEN=ghp_...
sdlc-evidence run \
  --application payments-api \
  --repository acme/payments-api \
  --release-id 2026.04.10 \
  --commit-sha abcdef1234567890 \
  --pull-request 184 \
  --workflow-run 1001 \
  --artifacts-dir artifacts \
  --output-dir output
```

The GitHub collector never logs tokens and reads them from environment only.

`--workflow-run` evidence passes only when that run concluded with
`success`. A run that is queued, in progress, skipped, neutral, waiting on
an approval (`action_required`) or `stale` is recorded as `unknown` and
satisfies no control. The run executing the collector is still in progress
when it is read, so passing its own id (for example `${{ github.run_id }}`
from the same job) cannot satisfy a control such as OSPS-QA-03.01. Pass the
id of a run that has already finished.

## Exit codes

`run`, `evaluate` and `bundle` turn the release status into an exit code, which
is what makes the CLI a drop-in gate in a pipeline. `--fail-on` sets how severe
the status must be before the exit is non-zero — it **raises** the bar, it never
lowers it. The full matrix:

| `release_status` ↓ / `--fail-on` → | `ready` | `conditional` | `not_ready` *(default)* |
|---|---|---|---|
| `ready`       | 0 | 0 | 0 |
| `conditional` | 1 | 1 | **0** |
| `not_ready`   | 2 | 2 | 2 |

Read the bold cell before wiring a gate: **with the default `--fail-on=not_ready`,
a `conditional` release exits `0`.** Pass `--fail-on conditional` if a conditional
verdict must stop the pipeline.

The CI surfaces set their own threshold, and they do not all match the CLI
default:

- GitHub Action (`action.yml`): `fail-on` defaults to `not_ready`, so a
  `conditional` release passes the step.
- Reusable workflow (`reusable-evidence-collection.yml`): gates at `not_ready`
  by default, like the Action.
- GitLab CI/CD Catalog component (`examples/gitlab-component`): `fail-on`
  defaults to `conditional`, so a `conditional` release fails the job.
- Legacy GitLab template (`examples/gitlab-ci`, deprecated in favour of the
  component): `FAIL_ON` defaults to `not_ready`.

`bundle` is a partial alias of `evaluate`: it always runs with `--fail-on
not_ready` and does not accept `--owner-team`, `--exceptions-dir`,
`--artifact-root`, `--risk-mode` or `--epss-percentile-threshold`, so waivers
and the risk-weighted verdict cannot be applied through it. Passing any of
those options exits `3`. Use `evaluate` when you need any of them.

Every other command reports a verdict but never encodes it in the exit status —
`compare`, `controls`, `plugins`, `schema`, `oscal` and `doctor` exit `0` on
success regardless of the release status, and `compare` in particular does
**not** fail a build on regression.

`doctor` is the one exception to the taxonomy below: it exits `0` when every
required check passes and `1` when any required check fails (optional checks,
such as a missing token or `cosign`, never fail). That `1` is not a
`conditional` verdict. It is kept for compatibility in the 4.x line and will
move to `3` in the next major release, in line with every other failure.
`doctor` also runs on a broken install: if a required dependency such as
`defusedxml` is missing, its `Import:` row fails and it exits `1`, while every
other command prints one line naming the missing package and exits `3`.

**Every failure that is not a release verdict exits `3`.** A missing or
malformed bundle, an unreadable catalog, an invalid `--commit-sha`, an
`--epss-feed` that could not be read, a rejected `--predicate-type` — all of
them, on every command, with a single-line explanation (`--verbose` for the
traceback). The full taxonomy:

| Code | Meaning | Where |
|---|---|---|
| `0` | `ready`, or a command that does not gate | everywhere |
| `1` | `conditional`; for `doctor`, a failed required check (see above) | `run`, `evaluate`, `bundle` (subject to `--fail-on`), `doctor` |
| `2` | `not_ready`; for `verify --expected`, a digest that does not match | `run`, `evaluate`, `bundle`, `verify --expected` |
| `3` | the command could not run: bad input, unreadable file, failed validation | every command |

A wrapper can therefore branch on the code alone. Outside `doctor`, `1` means
`conditional` and nothing else; `3` means "nothing was produced, do not read
this as a verdict".

One input is deliberately not fatal: an input directory passed to `run`,
`collect` or `evaluate` (`--artifacts-dir`, `--attestations-dir`,
`--exceptions-dir`) that does not exist, or is a file. The command records it
in the bundle's `collection_errors`, prints it under "Collection warnings" (a
`collection_error` event with `--json-logs`), writes the bundle, and exits with
the verdict for whatever evidence it did find. That is usually `2`
(`not_ready`) when the missing directory held the evidence, but a missing
`--exceptions-dir` next to complete evidence can still exit `0`. The GitHub
Action passes a configured `exceptions-dir` through even when it is missing,
and the reusable workflow and the
[GitLab CI/CD Catalog component](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/blob/main/examples/gitlab-component/README.md) always
pass `--artifacts-dir`; all three expect a bundle back. To stop a pipeline
on a missing directory, fail the step when `collection_errors` is not empty.

The exception is `run` with nothing readable at all: when no input directory
is passed, or none of the directories passed exists, and no `--pull-request`
or `--workflow-run` is requested, there is no evidence to evaluate, so it
exits `3` and writes no bundle. The wrappers hit this case too. The GitHub
Action skips an `artifacts-dir` or `attestations-dir` that does not exist, so
when both are missing and no pull request or workflow run is set, the step
exits `3` with no bundle and empty outputs, unless the configured
`exceptions-dir` exists.

> Before `3.0.0` this was inconsistent: `vex`, `guac`, `statement`, `enrich`
> and `oscal` returned `2` for a malformed input — the same code as a
> `not_ready` release — while `verify`, `compare` and `evaluate` returned `3`.
> See [the 3.0.0 upgrade notes](upgrading.md#300).

Usage errors exit `3` as well: an unknown flag, a missing required option, or a
rejected value such as `--fail-on banana`. The CLI replaces Click's default of
`2` for them, because `2` is the `not_ready` verdict.

## JSON logs (`--json-logs`)

`--json-logs`, or `SDLC_JSON_LOGS=1` in the environment, turns stdout into
NDJSON: one JSON object per line, each with an `event` field, failures and
usage errors included. `--version` prints a `version` event; `--help` stays
plain text, and so does the help printed by `sdlc-evidence` or
`sdlc-evidence exceptions` run without a subcommand, which exit `0`. Without
JSON logs, human-readable errors go to stderr.

Commands whose output is a document wrap it in an event under JSON logs:
`schema` prints `schema_emitted` with the schema under `.schema`, and `oscal`
prints `oscal_emitted` with the document under `.document`. Use `--output` to
write the bare document to a file, or leave JSON logs off for that step.
`compare --format json` and `doctor --json` print the raw document only when
JSON logs are off. Every event, the command that emits it and its payload
keys are listed in the [JSON logs event reference](json-logs.md); the
gate result of `run`, `evaluate` and `bundle` is the `bundle_built` event.

## Release status rules

| Rule | Verdict |
|------|---------|
| Every control is met, waived or not applicable: no required or recommended evidence is missing | `ready` |
| A high control lacks required evidence | `conditional` |
| Only recommended evidence is missing, or medium-criticality controls lack evidence | `conditional` |
| A critical control lacks required evidence | `not_ready` |

The "missing critical/high evidence" line in the report and the console lists
the gaps from both critical and high controls; only the critical ones make the
release `not_ready`.

In the default catalog the five critical controls are SBOM, code review,
release approval, rollback plan and artifact signature. The SAST, SCA, secrets
and test controls are high, so a release that meets the critical controls but
has no scanner or test evidence at all is `conditional`, and under the default
`--fail-on not_ready` it exits `0`.
The bundled `catalog-fedramp-cr26` has no critical control, so it can return
`conditional` but never `not_ready`. Pass `--fail-on conditional` when those
gaps must stop the pipeline.

Evidence anchored to another release or commit (an `evaluate --evidence` file
collected for an older build, for example) is recorded in `collection_errors`
and lowers a `ready` verdict to `conditional`; it is not refused. Under the
default `--fail-on not_ready` that run still exits `0`, so a pipeline that
reuses evidence across commits should pass `--fail-on conditional`.

Release status is **derived from the criticality of gaps**, never from the
numeric score, so a cosmetic "high score" cannot override a missing
critical control. Scores exist only to signal coverage direction over time.

## Control catalog

The default catalog ships with **13 controls** covering SAST, SCA, secrets
scanning, SBOM, tests, code review, threat model, release approval, rollback
plan, artifact signing, and three OWASP SAMM practices (Threat Assessment,
Secure Build, Security Testing). They are mapped to NIST SSDF practices when
applicable (PS.2/PS.3/PW.1/PW.4/PW.7/PW.8), to OWASP SAMM practice IDs
(DESIGN-TA-1, IMPL-SB-2, VERIF-ST-1), and to org-internal IDs for everything
else.

Inspect it with `sdlc-evidence controls`, or replace it with your own via
`--catalog path/to/your_catalog.yaml`. Schema:

```yaml
controls:
  - control_id: "MY-ORG-1"
    framework: "ORG_INTERNAL"
    name: "..."
    description: "..."
    criticality: "critical|high|medium|low"
    required_evidence_types: ["sast_scan", "sca_scan", ...]
    recommended_evidence_types: ["pr_metadata", ...]
```

### Evidence types

Core: `sast_scan`, `sca_scan`, `secrets_scan`, `dast_scan`, `iac_scan`,
`sbom`, `test_result`, `code_review`, `pr_metadata`, `workflow_run`,
`threat_model`, `release_approval`, `rollback_plan`, `artifact_signature`,
`artifact_attestation`, `generic_attestation`.

AI evidence: `model_card`, `prompt_injection_test_result`, `ai_safety_eval`,
`mcp_tool_inventory`, `ai_training_data_lineage`.

The authoritative list is `EvidenceType` in
`src/evidence_collector/domain/enums.py`, mirrored in the published
[`evidence-bundle.schema.json`](evidence-bundle.schema.json).

## Comparing bundles

`sdlc-evidence compare before.json after.json` reports what changed but never
fails a build, and no workflow in this repository runs it. What CI does enforce
is the structural-determinism gate: it rebuilds the sample bundle and compares
the normalized SHA-256 across runs and operating systems. When the two bundles
were evaluated against different control catalogs (different SHA-256),
`compare` names both catalogs and marks each control change `(catalog)`, since
the movement may come from the catalog rather than the evidence. The JSON
output carries the same facts under `catalog` and `controls.catalog_drift`. If
either bundle records no catalog (bundles made before catalog provenance was
recorded), `catalog.changed` is `null` and the table warns that control changes
cannot be attributed.
