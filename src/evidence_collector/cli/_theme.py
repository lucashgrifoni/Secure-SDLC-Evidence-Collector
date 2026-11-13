"""Rich theme for the CLI: semantic style names over a palette per colour depth.

Command modules write `[status.warn]...[/]` instead of `[yellow]...[/]`, so the
meaning is named once and the colour is decided here. Colour only reinforces:
every status is a printed word, and a verdict is bold as well, so `NO_COLOR`,
a pipe and a monochrome terminal all keep the meaning.

A CLI cannot know the terminal background, and no single foreground colour
reaches 4.5:1 on both a dark and a light one. Two consequences:

* the verdict is a badge, dark ink on its own fill, so its contrast is the
  same on every terminal (6.9:1, 9.3:1 and 5.3:1);
* the other status words use the landing page hues at a mid lightness, snapped
  to the xterm-256 cube so a 256-colour terminal shows what a truecolor one
  does. They stay near 3:1 on any background and are never the only signal.

A 16-colour terminal (a CI log with `FORCE_COLOR`, the legacy Windows console)
keeps the named ANSI colours the CLI has always used. Rich would otherwise
downgrade the brand green to cyan there.

With `NO_COLOR` set the theme maps every semantic name back to the attribute
the call site had before (bold, dim or nothing) and leaves Rich's defaults
alone, so that output is byte for byte what it was.
"""

from __future__ import annotations

from typing import Final

from rich.console import Console
from rich.theme import Theme

# Checked against the design tokens (`cli` in tokens.json) by the drift test.
BRAND: Final[dict[str, str]] = {
    "badge-ink": "#0c124c",
    "ready-fill": "#08b98b",
    "conditional-fill": "#f0b429",
    "not-ready-fill": "#ef5c5c",
    "ok": "#00875f",
    "warn": "#af8700",
    "bad": "#d75f5f",
    "muted": "#808080",
}

# Rich's default highlighter colours numbers, paths and `key=value` pairs in
# free text. In this CLI that paints digits cyan and half an identifier
# magenta, which reads as a status. Only a URL keeps a mark.
_PLAIN_HIGHLIGHTS: Final[dict[str, str]] = dict.fromkeys(
    (
        "repr.number",
        "repr.number_complex",
        "repr.str",
        "repr.path",
        "repr.filename",
        "repr.attrib_name",
        "repr.attrib_value",
        "repr.attrib_equal",
        "repr.bool_true",
        "repr.bool_false",
        "repr.none",
        "repr.brace",
        "repr.comma",
        "repr.ellipsis",
        "repr.tag_start",
        "repr.tag_name",
        "repr.tag_contents",
        "repr.tag_end",
        "repr.call",
        "repr.uuid",
        "repr.ipv4",
        "repr.ipv6",
        "repr.eui48",
        "repr.eui64",
    ),
    "none",
) | {"repr.url": "underline"}

_SHARED: Final[dict[str, str]] = {
    "brand": "bold",
    "count": "bold",
    "table.title": "bold",
    "table.header": "bold",
    **_PLAIN_HIGHLIGHTS,
}


def _badge(fill: str) -> str:
    return f"bold {BRAND['badge-ink']} on {BRAND[fill]}"


_BRAND_STYLES: Final[dict[str, str]] = {
    "verdict.ready": _badge("ready-fill"),
    "verdict.conditional": _badge("conditional-fill"),
    "verdict.not_ready": _badge("not-ready-fill"),
    "status.ok": BRAND["ok"],
    "status.warn": BRAND["warn"],
    "status.bad": BRAND["bad"],
    "output": BRAND["ok"],
    "muted": BRAND["muted"],
    **_SHARED,
}

_ANSI_STYLES: Final[dict[str, str]] = {
    "verdict.ready": "bold green",
    "verdict.conditional": "bold yellow",
    "verdict.not_ready": "bold red",
    "status.ok": "green",
    "status.warn": "yellow",
    "status.bad": "red",
    "output": "green",
    "muted": "dim",
    **_SHARED,
}

# What each semantic name replaced at its call site, colour removed.
_MONO_STYLES: Final[dict[str, str]] = {
    "verdict.ready": "bold",
    "verdict.conditional": "bold",
    "verdict.not_ready": "bold",
    "status.ok": "none",
    "status.warn": "none",
    "status.bad": "none",
    "output": "none",
    "muted": "dim",
    "brand": "bold",
    "count": "bold",
}

_RICH_COLOUR_DEPTHS: Final[frozenset[str]] = frozenset({"truecolor", "256"})


def theme_for(color_system: str | None, *, no_color: bool = False) -> Theme:
    """Brand hues where the terminal can show them, named ANSI colours elsewhere."""
    if no_color:
        return Theme(_MONO_STYLES)
    if color_system in _RICH_COLOUR_DEPTHS:
        return Theme(_BRAND_STYLES)
    return Theme(_ANSI_STYLES)


def install(console: Console) -> Console:
    """Give a console the theme that fits the colour depth it detected."""
    console.push_theme(theme_for(console.color_system, no_color=console.no_color))
    return console
