"""CLI command modules.

Each module declares its command(s) and exposes a :func:`register`
function that attaches them to the root Typer app. ``main.py`` walks
this list during import so a new command is added by:

1. dropping a module under ``cli/commands/``,
2. exposing a ``register(app: typer.Typer)`` entrypoint, and
3. adding it to :data:`COMMAND_MODULES` below.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Final

import typer

from . import (
    bundle_cmd,
    collect,
    compare,
    controls,
    doctor,
    enrich,
    evaluate,
    exceptions,
    oscal,
    plugins,
    run,
    schema,
    statement,
    verify,
    vex,
)

CommandRegister = Callable[[typer.Typer], None]

# Order is preserved in `--help` output, so keep the user-facing
# pipeline commands first (run → collect → evaluate → bundle) and the
# auxiliary tools after them.
COMMAND_MODULES: Final[tuple[CommandRegister, ...]] = (
    run.register,
    collect.register,
    evaluate.register,
    bundle_cmd.register,
    controls.register,
    compare.register,
    oscal.register,
    plugins.register,
    schema.register,
    doctor.register,
    verify.register,
    enrich.register,
    vex.register,
    statement.register,
    exceptions.register,
)


def register_all(app: typer.Typer) -> None:
    """Attach every command in :data:`COMMAND_MODULES` to ``app``."""
    for register in COMMAND_MODULES:
        register(app)
