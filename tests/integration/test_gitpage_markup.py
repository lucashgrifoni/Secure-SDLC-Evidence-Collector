"""Static checks on the landing page markup (gitpage/index.html).

These hold the parts of the page that need no browser to verify: a heading
outline without skipped levels, numbers that are already final in the HTML,
a brand link named by its visible text, and third-party scripts pinned by
Subresource Integrity. The browser-only checks (contrast, focus, print) are
recorded in the pull request that changes the page.
"""

from __future__ import annotations

from html.parser import HTMLParser
from itertools import pairwise
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[2] / "gitpage" / "index.html"
HEADINGS = {"h1", "h2", "h3", "h4", "h5", "h6"}

Attributes = dict[str, str | None]


class _Page(HTMLParser):
    """Collect the few facts these tests read from the page."""

    def __init__(self) -> None:
        super().__init__()
        self.heading_levels: list[int] = []
        self.scripts: list[Attributes] = []
        self.inline_script_chars = 0
        self.counters: list[tuple[Attributes, str]] = []
        self.brand: Attributes | None = None
        self.brand_text = ""
        self._in_inline_script = False
        self._in_brand = False
        self._counter: Attributes | None = None
        self._counter_text = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if tag in HEADINGS:
            self.heading_levels.append(int(tag[1]))
        if tag == "script":
            self.scripts.append(attributes)
            self._in_inline_script = "src" not in attributes
        if "data-counter" in attributes:
            self._counter, self._counter_text = attributes, ""
        if tag == "a" and "nav__brand" in (attributes.get("class") or "").split():
            self.brand, self._in_brand = attributes, True

    def handle_endtag(self, tag: str) -> None:
        if tag == "script":
            self._in_inline_script = False
        if tag == "a":
            self._in_brand = False
        if self._counter is not None:
            # Counter elements hold text only, so the first end tag is their own.
            self.counters.append((self._counter, self._counter_text.strip()))
            self._counter = None

    def handle_data(self, data: str) -> None:
        if self._in_inline_script:
            self.inline_script_chars += len(data.strip())
        if self._counter is not None:
            self._counter_text += data
        if self._in_brand:
            self.brand_text += data


@pytest.fixture(scope="module")
def page() -> _Page:
    parser = _Page()
    parser.feed(PAGE.read_text(encoding="utf-8"))
    return parser


@pytest.mark.integration
def test_headings_never_skip_a_level(page: _Page) -> None:
    levels = page.heading_levels
    assert levels[0] == 1
    assert levels.count(1) == 1
    assert [pair for pair in pairwise(levels) if pair[1] - pair[0] > 1] == []


@pytest.mark.integration
def test_counters_ship_their_final_value(page: _Page) -> None:
    """Without JavaScript and in print the numbers must not read as zero."""
    assert page.counters
    for attributes, text in page.counters:
        assert text == f"{attributes['data-counter']}{attributes.get('data-suffix') or ''}"


@pytest.mark.integration
def test_brand_link_is_named_by_its_visible_text(page: _Page) -> None:
    assert page.brand is not None
    assert "aria-label" not in page.brand
    assert page.brand_text.strip() == "Secure SDLC Evidence Collector"


@pytest.mark.integration
def test_third_party_scripts_are_pinned_by_integrity_hash(page: _Page) -> None:
    external = [
        script
        for script in page.scripts
        if (script.get("src") or "").startswith(("http:", "https:", "//"))
    ]
    assert [script["src"] for script in external] == [
        "https://unpkg.com/three@0.158.0/build/three.min.js"
    ]
    for script in external:
        assert (script.get("integrity") or "").startswith("sha384-")
        assert script.get("crossorigin") == "anonymous"


@pytest.mark.integration
def test_page_has_no_inline_script(page: _Page) -> None:
    """main.js alone sets the class that hides content for the scroll reveal.

    An inline script that set it would leave every section invisible whenever
    main.js failed to load.
    """
    assert page.inline_script_chars == 0
    assert all("src" in script for script in page.scripts)
