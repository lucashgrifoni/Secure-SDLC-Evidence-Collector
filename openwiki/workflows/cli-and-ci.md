---
type: "workflow"
title: "CLI outcomes and CI"
description: "Use the command entrypoint and distinguish release-verdict exits from input failures and CI validation."
tags: ["cli","ci","testing"]
verified:
  - by: openwiki/0.7.2
    at: 2026-10-14T18:37:45.397Z
sources:
  - id: openwiki-source-e4347ec9a24d3f6fdf562920
    resource: repo://.github/workflows/github-ci-cd.yml
  - id: openwiki-source-1c816d27f524a8dee9dbd353
    resource: repo://src/evidence_collector/cli/_exit_codes.py
  - id: openwiki-source-37d0514b75cc4e55978e01c9
    resource: repo://src/evidence_collector/cli/commands/run.py
  - id: openwiki-source-e32594edae565ad2a6cca101
    resource: repo://src/evidence_collector/cli/main.py
  - id: openwiki-source-2d15416690365c71f93b8c3b
    resource: repo://tests/integration/test_exit_code_taxonomy.py
generated: { by: "codex", at: "2026-10-14T18:37:45.397Z" }
---

# CLI outcomes and CI

## CLI ownership

The console entrypoint builds a root Typer application, registers command modules and handles global `--verbose`, `--json-logs` and `--version` options ([entrypoint](../../src/evidence_collector/cli/main.py#L17-L82)). Use the existing user guides for command-specific inputs.

The default verdict exits are 0 for ready, 1 for conditional and 2 for not_ready. Input/IO failures reserve exit 3; `--fail-on` can change whether a softer verdict returns zero ([exit-code rules](../../src/evidence_collector/cli/_exit_codes.py#L18-L42), [threshold handling](../../src/evidence_collector/cli/_exit_codes.py#L86-L104)). Interpret the selected threshold with the status in the bundle.

## Missing directories are context-dependent

The `run` command has an explicit no-input guard. When the supplied directories are all absent and no alternate source is available, it exits 3 before writing a bundle. With usable inputs alongside a missing directory, evaluation can continue and the missing input remains a collection error. Tests assert both outcomes ([run guard](../../src/evidence_collector/cli/commands/run.py#L216-L233), [regression tests](../../tests/integration/test_exit_code_taxonomy.py#L137-L208)). Do not translate every missing-directory warning into a release verdict or every warning into a fatal process error.

## Repository validation

The GitHub CI/CD quality job runs Python 3.12 and 3.13, installs hash-locked dependencies, then runs Ruff lint/format, Mypy and pytest with coverage. These are configured checks, not a statement that a particular run passed ([workflow](../../.github/workflows/github-ci-cd.yml#L54-L122)). The [contribution guide](../../CONTRIBUTING.md) records the local quality bar.

Use [quickstart](../quickstart.md) to route implementation questions and [the release pipeline](../architecture/release-pipeline.md) to trace persisted results.
