"""Shared Jinja2 environment for Markdown and HTML exporters."""

from __future__ import annotations

import re
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
# `.md.j2` stays out of autoescape on purpose: most identifiers in report.md
# sit inside backtick code spans, where CommonMark does not decode entities, so
# autoescaping would render `&amp;` and `&#39;` there as literal text. Markdown
# injection is handled where it belongs, by the `md` filter for prose and table
# cells (structure characters and raw HTML) and `md_code` for code spans.
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
    env.filters["md_code"] = md_code
    return env


def _upper_or_dash(value: object) -> str:
    if value is None or value == "":
        return "-"
    return str(value).upper()


# Every character `str.splitlines()` treats as a line boundary. That is the set
# that matters, because every line-wise reader of report.md uses `splitlines()`
# — including this project's own structural assertions. Collapsing only the
# ASCII vertical whitespace left U+2028, U+2029, U+0085 and the C0 information
# separators free to forge a new line.
_MD_LINE_BREAKS = "\n\r\v\f\x1c\x1d\x1e\x85"
_MD_CONTROL_CHARS: dict[int, str] = {ord(c): " " for c in _MD_LINE_BREAKS + "\t"}
# U+2028 LINE SEPARATOR and U+2029 PARAGRAPH SEPARATOR, by code point: as
# literals they are invisible in source and ruff flags them as ambiguous.
_MD_CONTROL_CHARS[0x2028] = " "
_MD_CONTROL_CHARS[0x2029] = " "
# An `&` that could open a named, decimal or hex character reference. This is a
# superset of what CommonMark and Python-Markdown decode, so nothing the value
# carried is decoded into a different character. A bare `&` is left alone.
_MD_ENTITY_START = re.compile(r"&(?=#?[A-Za-z0-9]+;)")


def md_escape(value: object) -> str:
    """Neutralise the characters that let a value forge Markdown structure.

    Markdown has no equivalent of HTML escaping, so untrusted strings written
    into `report.md` can rewrite the document instead of appearing in it. Two
    things do all the damage:

    - `|` closes the current table cell. One pipe in a package name shifts
      every following column left, so a row can be made to read `met` under
      Status while the evaluation actually says `missing`.
    - a line break ends the row (or the bullet) entirely, and everything after
      it is parsed as fresh Markdown at the top level — a forged `## Verdict`
      section, a second table, or raw HTML in renderers that allow it.

    Almost none of these strings are written by this tool: package names and
    versions come from an SBOM, rule ids and messages from SARIF, paths from
    the filesystem, justifications from waiver files. Line breaks collapse to a
    space and pipes are backslash-escaped, which CommonMark renders as a
    literal `|` in both table cells and prose, so the value stays readable.

    The backslash is escaped *first*, and that ordering is the whole
    correctness argument. Escaping only the pipe turned a value that already
    contained a backslash-pipe into backslash-backslash-pipe — an escaped
    backslash followed by a *live* pipe — and Python-Markdown splits the row
    there. On the waiver table that was enough to push the real `expires_at`
    into another column and promote an attacker-chosen date into "Expires at",
    so an expired waiver read as valid for decades, out of a string the tool
    merely copied from a waiver file.

    Raw HTML is the third problem. CommonMark passes inline HTML through in
    prose and table cells, so a dataset or tool named
    `<img src=x onerror=alert(1)>` became a live element in any renderer that
    allows HTML. `<` and `>` become `&lt;` and `&gt;`, and an `&` that would
    open an entity reference becomes `&amp;`, so a value that already reads
    `&lt;` is shown as written. CommonMark decodes those references back to
    the same visible text. The `&` is handled before the angle brackets so the
    references this filter writes are not escaped a second time.

    Square brackets are backslash-escaped too. Without that, a value such as
    `[x](javascript:alert(1))` became a live link in Python-Markdown (the
    engine behind mkdocs), and `![p](https://example.test/p.png)` a remote
    image in every renderer. An escaped bracket renders as a literal bracket.
    """
    if value is None:
        return ""
    text = str(value).translate(_MD_CONTROL_CHARS)
    text = text.replace("\\", "\\\\").replace("|", "\\|")
    for character in "*_`~":
        text = text.replace(character, "\\" + character)
    text = text.replace("[", "\\[").replace("]", "\\]")
    text = _MD_ENTITY_START.sub("&amp;", text)
    return text.replace("<", "&lt;").replace(">", "&gt;")


def md_code(value: object) -> str:
    """Neutralise a value that will be rendered inside a backtick code span.

    A code span is a different escaping context and needs a different filter.
    CommonMark does *not* process backslash escapes inside one, so `md_escape`'s
    doubling — correct and necessary in prose and plain table cells — is
    rendered literally here. `report.md.j2` backticks nearly every identifier
    and path, so on Windows every artifact path in the human-facing audit
    deliverable read `C:\\\\Users\\\\...` instead of `C:\\Users\\...`. Applying
    an escape where it is not processed does not make the value safer, only
    wrong.

    Three things still need handling:

    - a backtick would close the span and let the rest of the value out into
      Markdown, so runs of backticks are replaced with a visible marker;
    - a pipe still splits a GFM table cell even inside a code span, because
      the table is divided before inline code is parsed. It has to be
      escaped, and CommonMark renders that as a literal `\\|` here — ugly,
      unavoidable, and vastly better than a shifted row;
    - line breaks end the row, exactly as in prose.
    """
    if value is None:
        return ""
    text = str(value).translate(_MD_CONTROL_CHARS)
    return text.replace("`", "'").replace("|", "\\|")


def template_root_exists() -> bool:
    try:
        return files("evidence_collector.exporters.templates").is_dir()
    except (ModuleNotFoundError, FileNotFoundError):
        return False
