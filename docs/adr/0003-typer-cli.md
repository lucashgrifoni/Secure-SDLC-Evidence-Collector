# ADR-0003 — Typer for the CLI

- **Status:** accepted
- **Date:** 2026-04-23

## Context

The project is CLI-first. The CLI is the primary surface for both
humans (running locally during incident response) and pipelines
(consuming `bundle.json` and exit codes). It needs:

- type-safe parameter binding,
- automatic `--help` generation,
- a clean way to compose subcommands and shared options,
- a testing surface that does not require subprocesses.

Candidates: stdlib `argparse`, `click`, `typer`, `cyclopts`.

## Decision

Use **Typer**. It is a thin layer over `click` that derives the
parser directly from Python type hints, which keeps the CLI signature
in lockstep with the underlying functions and removes the manual
parser-building boilerplate. Typer's `CliRunner` (re-exported from
click) lets unit and integration tests invoke commands without
spawning subprocesses.

## Consequences

**Positive**
- Adding a flag is a one-line type annotation, not a separate
  `add_argument` call.
- `mypy --strict` understands the command signatures end to end.
- Tests can call `runner.invoke(app, [...])` and assert on
  `result.exit_code` and `result.output` synchronously.

**Negative / accepted**
- Typer hides some click features behind helper functions. We accept
  that the bottom 5 % of advanced cases will require dropping into
  click directly.
- Typer's options can collide with global Typer flags (e.g. `--help`).
  Mitigation: every command has a unit/integration test that invokes
  it with the documented flags so hidden conflicts surface immediately.
