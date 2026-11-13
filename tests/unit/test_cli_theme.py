"""The CLI theme changes colours only where a terminal shows colour.

Call sites write semantic names (`[status.warn]`) instead of colours. These
tests pin what that may and may not change:

- with `NO_COLOR` the bytes are the ones the old colour markup produced;
- written to a pipe (no TTY) there is no escape sequence at all;
- a 16-colour terminal keeps the named ANSI colours the CLI always used;
- every semantic name a command uses exists in every theme.
"""

from __future__ import annotations

import io
import re
from pathlib import Path

import pytest
from rich.console import Console
from rich.table import Table

from evidence_collector.cli import _errors, _state
from evidence_collector.cli._theme import install, theme_for

CLI_SOURCE = Path(__file__).resolve().parents[2] / "src/evidence_collector/cli"
VERDICTS = ("ready", "conditional", "not_ready")

# Each semantic name and the markup its call sites used before the theme.
REPLACED = {
    "status.ok": "green",
    "status.warn": "yellow",
    "status.bad": "red",
    "output": "green",
    "muted": "dim",
    "brand": "bold",
    "count": "bold",
    **{f"verdict.{verdict}": "bold" for verdict in VERDICTS},
}

# Free text the default highlighter used to colour: numbers, paths, key=value.
HIGHLIGHTED = "3 files under C:/w/out/bundle.json · coverage=93 confidence=59 · id=abc-123"


def _console(*, themed: bool, color_system: str | None, no_color: bool = False) -> Console:
    terminal = color_system is not None
    console = Console(
        file=io.StringIO(),
        force_terminal=terminal,
        color_system=color_system,  # type: ignore[arg-type]
        no_color=no_color,
        width=120,
        legacy_windows=False,
    )
    return install(console) if themed else console


def _output(console: Console) -> str:
    stream = console.file
    assert isinstance(stream, io.StringIO)
    return stream.getvalue()


def _table(title: str) -> Table:
    table = Table(title=title)
    table.add_column("Status")
    table.add_row("ok")
    return table


@pytest.mark.parametrize(("name", "before"), REPLACED.items())
@pytest.mark.parametrize("color_system", ["truecolor", "256", "standard"])
def test_no_color_output_is_byte_identical_to_the_old_markup(
    name: str, before: str, color_system: str
) -> None:
    themed = _console(themed=True, color_system=color_system, no_color=True)
    plain = _console(themed=False, color_system=color_system, no_color=True)
    themed.print(f"[{name}]word 42[/{name}] {HIGHLIGHTED}")
    plain.print(f"[{before}]word 42[/{before}] {HIGHLIGHTED}")
    themed.print(_table("Release readiness summary"))
    plain.print(_table("Release readiness summary"))
    assert _output(themed) == _output(plain)


@pytest.mark.parametrize("name", REPLACED)
def test_a_pipe_gets_no_escape_sequence(name: str) -> None:
    themed = _console(themed=True, color_system=None)
    plain = _console(themed=False, color_system=None)
    themed.print(f"[{name}]word[/{name}] {HIGHLIGHTED}")
    plain.print(f"[{REPLACED[name]}]word[/{REPLACED[name]}] {HIGHLIGHTED}")
    assert "\x1b" not in _output(themed)
    assert _output(themed) == _output(plain)


@pytest.mark.parametrize(
    ("name", "before"),
    [
        ("status.ok", "green"),
        ("status.warn", "yellow"),
        ("status.bad", "red"),
        ("output", "green"),
        ("muted", "dim"),
        ("verdict.ready", "bold green"),
        ("verdict.conditional", "bold yellow"),
        ("verdict.not_ready", "bold red"),
    ],
)
def test_sixteen_colours_keep_the_named_ansi_colours(name: str, before: str) -> None:
    themed = _console(themed=True, color_system="standard")
    plain = _console(themed=False, color_system="standard")
    themed.print(f"[{name}]word[/{name}]", highlight=False)
    plain.print(f"[{before}]word[/{before}]", highlight=False)
    assert _output(themed) == _output(plain)


@pytest.mark.parametrize("color_system", ["truecolor", "256"])
def test_rich_terminals_get_the_brand_badge_and_no_digit_highlighting(color_system: str) -> None:
    console = _console(themed=True, color_system=color_system)
    console.print("[verdict.not_ready]not_ready[/]")
    console.print(HIGHLIGHTED)
    lines = _output(console).splitlines()
    assert re.search(r"\x1b\[[0-9;]*48;", lines[0]), "the verdict is a badge with its own fill"
    assert "\x1b" not in lines[1], "plain text is not painted by the highlighter"


def test_theme_for_picks_a_palette_by_colour_depth() -> None:
    def style(color_system: str | None, *, no_color: bool = False) -> str:
        return str(theme_for(color_system, no_color=no_color).styles["status.warn"])

    assert style("truecolor") == style("256") == "#af8700"
    assert style("standard") == style("windows") == style(None) == "yellow"
    assert style("truecolor", no_color=True) == "none"


def _semantic_names_used_by_commands() -> set[str]:
    names: set[str] = set()
    for path in CLI_SOURCE.rglob("*.py"):
        if path.name == "_theme.py":
            continue
        source = path.read_text(encoding="utf-8")
        names |= set(
            re.findall(r"\[((?:status|verdict)\.[a-z_]+|output|muted|brand|count)\]", source)
        )
        if "[verdict.{status}]" in source:
            names |= {f"verdict.{verdict}" for verdict in VERDICTS}
    return names


@pytest.mark.parametrize(
    ("color_system", "no_color"), [("truecolor", False), ("standard", False), (None, True)]
)
def test_every_name_a_command_uses_exists_in_every_theme(
    color_system: str | None, no_color: bool
) -> None:
    used = _semantic_names_used_by_commands()
    assert used >= {"status.ok", "status.warn", "status.bad", "output", "verdict.ready"}
    assert used <= set(theme_for(color_system, no_color=no_color).styles)


def test_the_shared_consoles_carry_the_theme() -> None:
    for console in (_state.console, _errors.error_console):
        assert console.get_style("status.warn") is not None
        assert console.get_style("verdict.not_ready") is not None
