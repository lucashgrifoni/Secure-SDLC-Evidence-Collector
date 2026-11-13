"""WCAG 2.2 AA contrast of the colour tokens, read from the shipped CSS.

The ratios are computed from the custom properties exactly as summary.html and
the docs stylesheet declare them, theme by theme, so a token edited in place
is measured before it ships. Translucent layers (tints, glows, lines) are
composited over what really sits behind them before the ratio is taken.
Minimums: 4.5:1 for text (SC 1.4.3), 3:1 for large text and for a graphic that
carries meaning (SC 1.4.3, SC 1.4.11).

The CLI verdict badge is checked as ink on its own fill, in truecolor and in
the 256-colour value a terminal really shows, because a CLI cannot know the
terminal background. The other CLI hues only reinforce a printed word.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest
from rich.color import Color, ColorSystem

from evidence_collector.cli._theme import BRAND
from evidence_collector.domain.enums import ReleaseStatus
from evidence_collector.domain.models import Application, EvidenceBundle, ReleaseContext, Summary
from evidence_collector.exporters.html import bundle_to_html

REPO = Path(__file__).resolve().parents[2]
TEXT, LARGE, GRAPHIC = 4.5, 3.0, 3.0

RGB = tuple[float, float, float]
Pair = tuple[str, str, list[str], float]

_HEX = re.compile(r"^#([0-9a-fA-F]{6})$")
_RGBA = re.compile(r"^rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*(?:,\s*([\d.]+)\s*)?\)$")
_DECLARATION = re.compile(r"--([a-z0-9-]+):\s*([^;]+);")


def _parse(colour: str) -> tuple[float, float, float, float]:
    if match := _HEX.match(colour):
        value = match.group(1)
        return (int(value[0:2], 16), int(value[2:4], 16), int(value[4:6], 16), 1.0)
    if match := _RGBA.match(colour):
        alpha = float(match.group(4)) if match.group(4) is not None else 1.0
        return (float(match.group(1)), float(match.group(2)), float(match.group(3)), alpha)
    raise ValueError(f"unsupported colour: {colour!r}")


def _over(top: tuple[float, float, float, float], bottom: RGB) -> RGB:
    alpha = top[3]
    return (
        top[0] * alpha + bottom[0] * (1 - alpha),
        top[1] * alpha + bottom[1] * (1 - alpha),
        top[2] * alpha + bottom[2] * (1 - alpha),
    )


def _flatten(stack: list[str]) -> RGB:
    base = _parse(stack[0])
    assert base[3] == 1.0, f"the bottom of a paint stack must be opaque: {stack[0]}"
    result: RGB = (base[0], base[1], base[2])
    for layer in stack[1:]:
        result = _over(_parse(layer), result)
    return result


def _luminance(rgb: RGB) -> float:
    def linear(channel: float) -> float:
        value = channel / 255
        return value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4

    return 0.2126 * linear(rgb[0]) + 0.7152 * linear(rgb[1]) + 0.0722 * linear(rgb[2])


def _ratio(first: RGB, second: RGB) -> float:
    lighter, darker = sorted((_luminance(first), _luminance(second)), reverse=True)
    return (lighter + 0.05) / (darker + 0.05)


def _contrast(foreground: str, stack: list[str]) -> float:
    background = _flatten(stack)
    return _ratio(_over(_parse(foreground), background), background)


def _declarations(css: str) -> dict[str, str]:
    return {name: value.strip() for name, value in _DECLARATION.findall(css)}


def _summary_themes() -> dict[str, dict[str, str]]:
    """The token values of summary.html per theme, as the rendered page declares them."""
    bundle = EvidenceBundle(
        bundle_id="contrast",
        application=Application(name="app", repository="acme/app"),
        release=ReleaseContext(release_id="1", commit_sha="abcdef1"),
        evidence=[],
        control_evaluations=[],
        summary=Summary(
            evidence_coverage_score=0,
            confidence_score=0,
            release_status=ReleaseStatus.READY,
            total_controls=0,
            controls_met=0,
            controls_partial=0,
            controls_missing=0,
            controls_waived=0,
            controls_not_applicable=0,
        ),
    )
    html = bundle_to_html(bundle)
    block = html[html.index("/* tokens:begin") : html.index("/* tokens:end */")]
    base, rest = block.split("@media screen and (prefers-color-scheme: dark)")
    dark, printed = rest.split("@media print")
    light = _declarations(base)
    return {
        "light": light,
        "dark": light | _declarations(dark),
        "print": light | _declarations(printed),
    }


def _docs_themes() -> dict[str, dict[str, str]]:
    css = (REPO / "docs/stylesheets/extra.css").read_text(encoding="utf-8")
    block = css[css.index("/* tokens:begin") : css.index("/* tokens:end */")]
    light_start = block.index('[data-md-color-scheme="default"]')
    dark_start = block.index('[data-md-color-scheme="slate"]')
    print_start = block.index("@media print")

    def unprefixed(css_block: str) -> dict[str, str]:
        return {name.removeprefix("ds-"): value for name, value in _declarations(css_block).items()}

    return {
        "light": unprefixed(block[light_start:dark_start]),
        "dark": unprefixed(block[dark_start:print_start]),
    }


# The lightest (dark theme) or darkest (light theme) the page ground gets.
_GROUND = {"dark": ["ground", "glow-b", "glow-a"], "light": ["ground-top"], "print": ["ground"]}


def _summary_pairs(theme: str) -> list[Pair]:
    ground, sheet, target, head = _GROUND[theme], ["sheet"], ["sheet", "target"], ["sheet-head"]
    pairs: list[Pair] = [
        ("page heading", "text-hi", ground, TEXT),
        ("page secondary text", "text-lo", ground, TEXT),
        ("page code chip", "text-hi", [*ground, "code-bg"], TEXT),
        ("page focus ring", "focus", ground, GRAPHIC),
        ("callout text", "text-hi", [*ground, "warn-tint"], TEXT),
        ("callout icon", "warn-ink", [*ground, "warn-tint"], GRAPHIC),
        ("cell text", "text", sheet, TEXT),
        ("cell value", "text-hi", sheet, TEXT),
        ("cell secondary text", "text-lo", sheet, TEXT),
        ("cell code chip", "text-hi", [*sheet, "code-bg"], TEXT),
        ("cell link", "accent-ink", sheet, TEXT),
        ("cell link in a code chip", "accent-ink", [*sheet, "code-bg"], TEXT),
        ("column label", "text-lo", head, TEXT),
        ("group row label", "text-hi", head, TEXT),
        ("link in a code chip on a header row", "accent-ink", [*head, "code-bg"], TEXT),
        ("criticality bars", "text", sheet, GRAPHIC),
        ("sheet focus ring", "focus", sheet, GRAPHIC),
        ("custom catalog flag", "warn-ink", [*sheet, "warn-tint"], TEXT),
        ("target row text", "text", target, TEXT),
        ("target row secondary text", "text-lo", target, TEXT),
        ("target row link in a code chip", "accent-ink", [*target, "code-bg"], TEXT),
        ("coverage meter", "meter-a", [*sheet, "track"], GRAPHIC),
        ("confidence meter", "meter-alt-a", [*sheet, "track"], GRAPHIC),
        ("next step text", "text-hi", ["panel-b", "code-bg"], TEXT),
        ("next step code chip", "text-hi", ["panel-b", "code-bg", "code-bg"], TEXT),
    ]
    for tone in ("ok", "warn", "bad", "muted"):
        pairs += [
            (f"{tone} pill", f"{tone}-ink", [*sheet, f"{tone}-tint"], TEXT),
            (f"{tone} pill on a target row", f"{tone}-ink", [*target, f"{tone}-tint"], TEXT),
            (f"{tone} controls bar segment", f"{tone}-fill", sheet, GRAPHIC),
        ]
    for tone in ("ok", "warn", "bad"):
        glow = ["panel-a", f"{tone}-glow"]
        pairs += [
            (f"{tone} verdict word", f"{tone}-strong", glow, LARGE),
            (f"{tone} verdict word, lower panel", f"{tone}-strong", ["panel-b"], LARGE),
            (f"{tone} verdict literal chip", f"{tone}-ink", [*glow, f"{tone}-tint"], TEXT),
            (f"{tone} verdict tag", f"{tone}-ink", glow, TEXT),
            (f"{tone} verdict status bar", f"{tone}-fill", ["panel-a"], GRAPHIC),
            (f"{tone} verdict labels", "text-lo", glow, TEXT),
            (f"{tone} verdict reasons", "text", glow, TEXT),
            (f"{tone} verdict code chip", "text-hi", [*glow, "code-bg"], TEXT),
            (f"{tone} verdict link in a code chip", "accent-ink", [*glow, "code-bg"], TEXT),
            (f"{tone} verdict 'more' marker", "accent-ink", glow, TEXT),
            (f"{tone} verdict caution icon", "warn-ink", glow, GRAPHIC),
        ]
    return pairs


def _docs_pairs(theme: str) -> list[Pair]:
    header_bg, header_fg = (
        (["text-hi"], "ground") if theme == "light" else (["ground-deep"], "text-hi")
    )
    header_focus = "accent" if theme == "light" else "accent-ink"
    return [
        ("body text", "text", ["ground"], TEXT),
        ("headings", "text-hi", ["ground"], TEXT),
        ("secondary text and navigation", "text-lo", ["ground"], TEXT),
        ("link and active navigation item", "accent-ink", ["ground"], TEXT),
        ("inline code", "text-hi", ["ground", "code-bg"], TEXT),
        ("code block text", "text-hi", ["sheet"], TEXT),
        ("code keyword", "accent-ink", ["sheet"], TEXT),
        ("code string", "ok-ink", ["sheet"], TEXT),
        ("code number", "warn-ink", ["sheet"], TEXT),
        ("code special", "bad-ink", ["sheet"], TEXT),
        ("code comment", "text-lo", ["sheet"], TEXT),
        ("table cell", "text", ["sheet"], TEXT),
        ("table column label", "text-lo", ["sheet-head"], TEXT),
        ("header and footer text", header_fg, header_bg, TEXT),
        ("header focus ring", header_focus, header_bg, GRAPHIC),
        ("page focus ring", "focus", ["ground"], GRAPHIC),
    ]


def _failures(tokens: dict[str, str], pairs: list[Pair]) -> list[str]:
    failures = []
    for label, foreground, stack, minimum in pairs:
        value = _contrast(tokens[foreground], [tokens[layer] for layer in stack])
        if value < minimum:
            failures.append(f"{label}: {value:.2f} < {minimum}")
    return failures


@pytest.mark.parametrize("theme", ["dark", "light", "print"])
def test_summary_html_meets_aa_contrast(theme: str) -> None:
    assert _failures(_summary_themes()[theme], _summary_pairs(theme)) == []


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_docs_theme_meets_aa_contrast(theme: str) -> None:
    assert _failures(_docs_themes()[theme], _docs_pairs(theme)) == []


def test_print_never_paints_a_translucent_layer_over_paper() -> None:
    printed = _summary_themes()["print"]
    colours = {name: value for name, value in printed.items() if value.startswith(("#", "rgb"))}
    assert "ground" in colours
    translucent = {name: value for name, value in colours.items() if 0 < _parse(value)[3] < 1}
    assert translucent == {}


@pytest.mark.parametrize("fill", ["ready-fill", "conditional-fill", "not-ready-fill"])
@pytest.mark.parametrize("system", [ColorSystem.TRUECOLOR, ColorSystem.EIGHT_BIT])
def test_cli_verdict_badge_meets_aa_on_any_terminal(fill: str, system: ColorSystem) -> None:
    def shown(hex_value: str) -> str:
        triplet = Color.parse(hex_value).downgrade(system).get_truecolor()
        return f"#{triplet.red:02x}{triplet.green:02x}{triplet.blue:02x}"

    assert _contrast(shown(BRAND["badge-ink"]), [shown(BRAND[fill])]) >= TEXT


def test_tokens_json_and_every_surface_are_in_sync() -> None:
    result = subprocess.run(
        [sys.executable, str(REPO / "scripts/design_tokens/build.py"), "--check"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
