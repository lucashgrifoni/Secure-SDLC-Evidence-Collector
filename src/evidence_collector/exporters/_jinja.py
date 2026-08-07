"""Shared Jinja2 environment for Markdown and HTML exporters."""

from __future__ import annotations

from functools import cache
from importlib.resources import files

from jinja2 import Environment, PackageLoader, StrictUndefined, select_autoescape

# `select_autoescape` matches on the *suffix* of the template name, and every
# template here ends in `.j2`. `select_autoescape(["html", "xml"])` therefore
# matched nothing at all and fell through to its `default=False`: summary.html
# was rendered with escaping OFF.
#
# That is a real injection sink, not a theoretical one. Almost every string in
# the summary originates in an artifact the tool did not write — SARIF rule
# names, package names and versions from an SBOM, waiver justifications, file
# paths. A dependency named `<img src=x onerror=...>`, or a scanner message
# carrying a `<script>` tag, lands verbatim in an HTML file that a release
# manager opens in a browser and that CI publishes as a build artifact.
#
# `.md.j2` stays unescaped on purpose: HTML-escaping Markdown would render
# `&amp;` and `&#39;` as literal text. Markdown injection is handled where it
# belongs, by the `md_cell` filter, which neutralises the characters that
# break table structure.
AUTOESCAPED_EXTENSIONS = ("html", "htm", "xml", "html.j2", "htm.j2", "xml.j2")


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
        autoescape=select_autoescape(AUTOESCAPED_EXTENSIONS),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters["upper_or_dash"] = _upper_or_dash
    env.filters["md"] = md_escape
    return env


def _upper_or_dash(value: object) -> str:
    if value is None or value == "":
        return "-"
    return str(value).upper()


_MD_CONTROL_CHARS = {ord(c): " " for c in "\n\r\t\x0b\x0c"}


def md_escape(value: object) -> str:
    """Neutralise the two characters that let a value forge Markdown structure.

    Markdown has no equivalent of HTML escaping, so untrusted strings written
    into `report.md` can rewrite the document instead of appearing in it. Two
    characters do all the damage:

    - `|` closes the current table cell. One pipe in a package name shifts
      every following column left, so a row can be made to read
      `met` under Status while the evaluation actually says `missing`.
    - a newline ends the row (or the bullet) entirely, and everything after it
      is parsed as fresh Markdown at the top level — a forged `## Verdict`
      section, a second table, or raw HTML in renderers that allow it.

    Almost none of these strings are written by this tool: package names and
    versions come from an SBOM, rule ids and messages from SARIF, paths from
    the filesystem, justifications from waiver files. Newlines collapse to a
    space and pipes are backslash-escaped, which CommonMark renders as a
    literal `|` in both table cells and prose, so the value is still readable.
    """
    if value is None:
        return ""
    return str(value).translate(_MD_CONTROL_CHARS).replace("|", "\\|")


def template_root_exists() -> bool:
    try:
        return files("evidence_collector.exporters.templates").is_dir()
    except (ModuleNotFoundError, FileNotFoundError):
        return False
