"""Behaviour tests for `exporters/_jinja.py`.

Targets the small filter and environment surface; avoids snapshot
testing the rendered Markdown/HTML (those are exercised by the
end-to-end integration suite).
"""

from __future__ import annotations

from jinja2 import Environment, StrictUndefined

from evidence_collector.exporters._jinja import (
    _upper_or_dash,
    get_environment,
    template_root_exists,
)


def test_upper_or_dash_handles_none_and_empty_string() -> None:
    assert _upper_or_dash(None) == "-"
    assert _upper_or_dash("") == "-"


def test_upper_or_dash_uppercases_strings() -> None:
    assert _upper_or_dash("hello") == "HELLO"
    assert _upper_or_dash("MixedCase") == "MIXEDCASE"


def test_upper_or_dash_stringifies_non_string_inputs() -> None:
    # Filter must be defensive: integers, enums, paths all valid in jinja.
    assert _upper_or_dash(42) == "42"
    assert _upper_or_dash(True) == "TRUE"


def test_get_environment_returns_strict_jinja_environment() -> None:
    env = get_environment()
    assert isinstance(env, Environment)
    # StrictUndefined makes typos in templates fail loudly instead of
    # rendering empty strings — the reason the project uses it.
    assert env.undefined is StrictUndefined
    # The custom filter is registered.
    assert "upper_or_dash" in env.filters


def test_get_environment_is_cached_across_calls() -> None:
    # `@cache` means two calls return the same instance; relevant
    # because Jinja builds an internal AST cache lazily and we want
    # one shared environment per process.
    assert get_environment() is get_environment()


def test_template_root_exists_in_installed_package() -> None:
    # When the package is installed (editable or wheel), the templates
    # directory must be discoverable. If this returns False, exporters
    # will silently fail downstream.
    assert template_root_exists() is True


def test_environment_can_render_inline_template_with_custom_filter() -> None:
    env = get_environment()
    template = env.from_string("[{{ value | upper_or_dash }}]")
    assert template.render(value="ready") == "[READY]"
    assert template.render(value="") == "[-]"
    assert template.render(value=None) == "[-]"
