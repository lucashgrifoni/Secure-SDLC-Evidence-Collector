# ADR 0006 — CLI command modularization

- Status: accepted
- Date: 2026-05-10
- Deciders: Lucas Henrique Grifoni
- Supersedes: none
- Superseded by: none

## Context

Until 2026-05-10 the CLI lived in a single file: `src/evidence_collector/cli/main.py`.
That file grew to 811 lines and 11 Typer commands plus shared helpers,
the `--json-logs` flag callback, the doctor health-check logic, the
exceptions sub-app, the exit-code policy, and the UTF-8 stream
reconfiguration. Three problems followed from that layout:

1. **Review locality.** Any PR touching one command rebuilt the whole
   file in reviewers' heads. The diff also crossed unrelated code
   blocks, so reviewers had to scroll past commands they were not
   reviewing.
2. **Testability.** Helpers like `_render_summary`, `_doctor_checks`,
   `_emit_event` and the exit-code policy were coplanar with Typer
   command definitions, so mocking was harder than it should have been.
3. **Onboarding.** A new command always meant editing the same crowded
   file, increasing the risk of accidental interference with unrelated
   commands (global `_LOG_JSON`, sub-Typer registration, etc.).

The rest of the project already followed a clean-architecture layout
(`application/`, `controls/`, `domain/`, `exporters/`,
`normalizers/`, `parsers/`). The CLI was the last hot single-file
boundary.

## Decision

Split `cli/main.py` into a thin entrypoint and one module per command:

```
src/evidence_collector/cli/
├── main.py             # root Typer app, callback, main(), reexports
├── _state.py           # JSON-logs flag, shared Console, EVIDENCE_ADAPTER
├── _logging.py         # configure_logging, emit_event
├── _render.py          # render_summary, render_collection_errors
├── _exit_codes.py      # exit_code_for_status, fail_on_exit_code
├── _builders.py        # build_application, build_release
└── commands/
    ├── __init__.py     # register_all(app); ordered COMMAND_MODULES
    ├── run.py
    ├── collect.py
    ├── evaluate.py
    ├── bundle_cmd.py
    ├── controls.py
    ├── compare.py
    ├── oscal.py
    ├── plugins.py
    ├── schema.py
    ├── doctor.py
    ├── exceptions.py
    └── verify.py
```

Each command module exposes a single `register(app: typer.Typer)`
function that defines the command(s) and attaches them to the root
app. `commands/__init__.py` lists the registration order, so `--help`
output stays predictable.

External contracts are preserved:

- `from evidence_collector.cli.main import app` keeps working.
- `from evidence_collector.cli.main import _doctor_checks` keeps
  working — the symbol is re-exported from `commands/doctor.py`.
- All flag names, argument names, exit codes and NDJSON event names
  remain identical.

## Alternatives considered

| Option | Why not |
|---|---|
| Keep `cli/main.py` as one file | Costs of the status quo were already paid in PR review time and onboarding friction. No upside. |
| Split by user-facing pipeline only (run / collect / evaluate / bundle) and leave the rest in `main.py` | Half-measure; the file still housed `compare`, `oscal`, `plugins`, `schema`, `doctor`, `exceptions`. |
| Generate command modules from a config file | Over-engineering for 12 commands. Hand-written modules read better and let each command document its own contract in a docstring. |
| Use a Typer plugin system (entry-points) | The project already has an entry-point group for third-party parsers and collectors (`evidence_collector.plugins`). Internal commands do not need that level of indirection. |

## Consequences

### Positive

- One file per command keeps PR diffs focused and reviewer-friendly.
- Each command's docstring is the canonical contract for that command.
- Helpers (`_render`, `_exit_codes`, `_builders`) are now testable in
  isolation without instantiating a Typer app.
- Adding a new command is a three-step recipe: write the module, add
  the `register` to `COMMAND_MODULES`, write the test.
- The `verify` command (and a future `doctor --strict` variant) can be
  added without touching any existing command's code.

### Negative

- More files in the repository. We accept this; clean-architecture
  layouts already trained the team to navigate by module.
- A small amount of import indirection: `evaluate` is imported by
  `bundle_cmd` to keep the alias one-line. This is explicit and
  documented.
- The shared JSON-logs flag is now a module-level mutable state in
  `_state.py`. We accept this because the same was true in the
  pre-refactor `main.py`; the only difference is that `set_json_logs`
  is the single public mutator.

### Neutral

- The `_doctor_checks` symbol is re-exported from `main.py` to keep
  the test imports stable. When tests are updated to import from
  `cli.commands.doctor`, this re-export can be dropped in a future
  release.

## Validation

After the split, all of the following pass locally:

- `ruff check src tests scripts`
- `ruff format --check src tests scripts`
- `mypy --strict src tests`
- `pytest -q` (existing CLI suites: `test_cli.py`,
  `test_cli_more_commands.py`, `test_doctor.py`, `test_json_logs.py`)

Re-validation is mandatory before tagging `v1.1.1`. See
`docs/release-readiness.md` "Re-validation required before tagging
`v1.1.1`".
