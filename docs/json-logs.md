# JSON logs event reference

`--json-logs`, or `SDLC_JSON_LOGS=1`, turns stdout into NDJSON: one JSON object
per line, each with an `event` field. This page lists every event the CLI
emits, the command that emits it and its payload keys. A unit test reads this
table and fails when the code emits an event that is missing here, or when the
table lists an event the code no longer emits.

The exit code stays the primary gate signal (see
[Exit codes](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector#exit-codes)).
Use the events for the detail behind it: the verdict and counts of a run, the
path of every collection error, the file a command wrote. Changes to event
names or keys are recorded in [upgrading](upgrading.md).

Keys are sorted alphabetically in each line. A key listed below may be absent
or `null` where the text says so.

## Every command

| Event | Emitted by | When | Payload keys |
|---|---|---|---|
| `version` | `--version` | Version requested | `version` |
| `command_failed` | any command | Usage error (unknown option, missing required option, rejected value), a missing required dependency, or any failure without a command-specific event below. Exits `3`. | `reason`, `error_type` (the exception class, for example `NoSuchOption`, `MissingParameter` or `ModuleNotFoundError`) |
| `log` | any command | A log record. Written to **stderr**, not stdout, so stdout keeps only the events below. | `level`, `logger`, `message` |

## Building a bundle: `run`, `collect`, `evaluate`, `bundle`

| Event | Emitted by | When | Payload keys |
|---|---|---|---|
| `bundle_built` | `run`, `evaluate`, `bundle` | The bundle was written. This is the gate result. | `bundle_id`, `release_status`, `coverage`, `confidence`, `controls_met`, `controls_partial`, `controls_missing`, `controls_waived`, `controls_not_applicable`, `evidence_count`, `collection_error_count`, `missing_critical_evidence`, `risk_rationale`, `bundle_json`, `report_md`, `summary_html` |
| `collection_error` | `run`, `evaluate`, `bundle`, `collect` | One line per entry in the bundle's `collection_errors` (or, for `collect`, in the evidence file): a missing directory, an unreadable or refused file | `path`, `reason` |
| `artifact_ignored` | `run`, `collect` | A file in an artifacts directory matched no parser | `path` |
| `artifact_root_mismatch` | `run`, `collect`, `evaluate` | `--artifact-root` does not exist or does not contain an input directory, so absolute paths stay in the output | `artifact_root`, `root_exists`, `outside` |
| `evidence_collected` | `collect` | The evidence file was written | `evidence_count`, `output` |
| `run_failed` | `run` | `run` could not produce a bundle, for example no evidence source or no input directory that exists. Exits `3`. | `reason` |
| `evaluate_failed` | `evaluate`, `bundle` | The evidence file is a directory, or could not be read or validated. Exits `3`. | `reason` |

## Exports from a bundle

| Event | Emitted by | When | Payload keys |
|---|---|---|---|
| `vex_emitted` | `vex` | The OpenVEX document was written | `bundle`, `output`, `statements`, `consumed`, `skipped`, `policy` |
| `vex_failed` | `vex` | Exits `3`. The bundle could not be read (`bundle`, `reason`), it is JSON that does not match the bundle schema (`reason` only), or a `--consume` source disagrees with the bundle under `--policy fail` (`bundle`, `policy`, `reason`, and no file is written). | `reason`; `bundle` except for a schema mismatch; `policy` only for a merge conflict |
| `statement_emitted` | `statement` | The in-toto Statement was written | `bundle`, `statement`, `envelope`, `predicate_type`, `predicate_type_name` |
| `statement_failed` | `statement` | Unknown `--predicate-type`, or the bundle could not be read or does not match the bundle schema. Exits `3`. | `reason`; `bundle` except for a schema mismatch |
| `sarif_emitted` | `sarif` | The SARIF file was written | `bundle`, `output`, `results` |
| `sarif_failed` | `sarif` | The bundle could not be read or does not match the bundle schema. Exits `3`. | `reason`; `bundle` except for a schema mismatch |
| `guac_emitted` | `guac` | The GUAC collector container was written | `bundle`, `output`, `documents` |
| `guac_failed` | `guac` | The bundle could not be read or does not match the bundle schema. Exits `3`. | `reason`; `bundle` except for a schema mismatch |
| `oscal_emitted` | `oscal` | The OSCAL document was produced | `kind`; `document` when printed to stdout, `output` when written with `--output` |
| `oscal_failed` | `oscal` | `--kind assessment-results` without an existing `--bundle`, an unreadable or invalid bundle, or control ids that collide once rendered as OSCAL. Exits `3`. | `reason` |
| `enrich_completed` | `enrich` | The bundle was enriched | `bundle`, `evidence_enriched`, `evidence_with_cves`, `distinct_cves`, `cves_in_kev`, `epss_feed_date`, `kev_feed_date`, `risk_mode`, `release_status`, `reports_regenerated`, `reports_left_alone` |
| `enrich_skipped` | `enrich` | Neither `--epss-feed` nor `--kev-feed` was given; the bundle is left unchanged | `reason`, `bundle` |
| `enrich_reports_left_alone` | `enrich` | `report.md` or `summary.html` in the output directory belong to the input bundle and were not regenerated; write `--output` to another directory to get new ones | `reason` |
| `enrich_failed` | `enrich` | A feed or the bundle could not be read or written. Exits `3`. | `reason`, `bundle`; `feed` and `feed_kind` for a feed |

## Inspection and comparison

| Event | Emitted by | When | Payload keys |
|---|---|---|---|
| `verify_computed` | `verify` | Digest computed, no `--expected` | `bundle`, `sha256` |
| `verify_result` | `verify --expected` | Digest compared with the pin. Exits `2` when `match` is false. | `bundle`, `sha256`, `expected`, `match` |
| `verify_failed` | `verify` | The bundle could not be read or validated, or `--expected` is not a 64-character SHA-256. Exits `3`. | `reason`, `bundle` |
| `bundles_compared` | `compare` | Comparison done. Never fails the build. | `before_bundle_id`, `after_bundle_id`, `before_release_status`, `after_release_status`, `coverage_delta`, `confidence_delta`, `controls`, `catalog`, `epss` |
| `compare_failed` | `compare` | A bundle could not be read. Exits `3`. | `reason` |
| `controls_listed` | `controls` | Catalog printed | `controls` |
| `schema_emitted` | `schema` | Schema produced | `schema` when printed to stdout, `output` when written with `--output` |
| `plugins_listed` | `plugins` | Plugin list printed | `plugins` |
| `doctor_checked` | `doctor` | Health checks ran. `failed` counts the checks that did not pass; the command exits `1` when a required one failed. | `checks`, `failed` |

## Exceptions (waivers)

| Event | Emitted by | When | Payload keys |
|---|---|---|---|
| `exception_validated` | `exceptions validate` | One line per valid file | `path`, `exception`, `in_force`, `scope_evaluated` |
| `exception_invalid` | `exceptions validate`, `exceptions list` | A file could not be parsed or failed validation. The command exits `3`. | `reason`, `path` |
| `exception_listed` | `exceptions list` | One line per valid exception | `path`, `exception`, `in_force`, `scope_evaluated` |
| `exception_duplicate` | `exceptions list` | An exception id is defined in more than one file. Exits `3`. | `reason`, `path` |
| `exceptions_summary` | `exceptions list` | Totals for the directory | `active`, `not_in_force`, `unparseable`, `duplicate_ids`, `scope_evaluated` |
| `exceptions_failed` | `exceptions list` | The path is not a directory. Exits `3`. | `reason` |

## Telling failures apart

Every failure exits `3`, so read the event when the reason matters. For
example, `vex --policy fail` and an unreadable bundle both exit `3` with
`vex_failed`. The conflict carries a `policy` key and a reason that starts with
`VEX merge conflict:`; the unreadable bundle has neither.
