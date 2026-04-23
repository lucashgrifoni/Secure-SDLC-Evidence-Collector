"""Shared Jinja2 environment for Markdown and HTML exporters."""

from __future__ import annotations

from functools import cache
from importlib.resources import files

from jinja2 import Environment, PackageLoader, StrictUndefined, select_autoescape


@cache
def get_environment() -> Environment:
    # `PackageLoader` reads templates packaged with the installed module, so
    # it works both in development (editable install) and in wheels.
    loader = PackageLoader(
        package_name="evidence_collector",
        package_path="exporters/templates",
    )
    env = Environment(
        loader=loader,
        autoescape=select_autoescape(["html", "xml"]),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters["upper_or_dash"] = _upper_or_dash
    return env


def _upper_or_dash(value: object) -> str:
    if value is None or value == "":
        return "-"
    return str(value).upper()


def template_root_exists() -> bool:
    try:
        return files("evidence_collector.exporters.templates").is_dir()
    except (ModuleNotFoundError, FileNotFoundError):
        return False
