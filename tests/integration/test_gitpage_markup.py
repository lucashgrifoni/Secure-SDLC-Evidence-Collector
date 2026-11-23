"""Static checks on the landing page markup (gitpage/index.html).

These hold the parts of the page that need no browser to verify: a heading
outline without skipped levels, numbers that are already final in the HTML,
a brand link named by its visible text, third-party scripts pinned by
Subresource Integrity, and the hero layout that keeps the 3D scene out from
behind the text. The browser-only checks (contrast, focus, print) are
recorded in the pull request that changes the page.
"""

from __future__ import annotations

from html.parser import HTMLParser
from itertools import pairwise
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
PAGE = REPO_ROOT / "gitpage" / "index.html"
# The Pages workflow builds the mkdocs site under this path of the published site.
DOCS_PREFIX = "docs/"
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
        self.links: list[tuple[Attributes, str]] = []
        self.ids: dict[str, str] = {}
        self.canvas_ancestors: list[str] = []
        self._open_classes: list[str] = []
        self._link: Attributes | None = None
        self._link_text = ""
        self._id_tag: tuple[str, str] | None = None
        self._id_text = ""
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
        if tag == "a":
            self._link, self._link_text = attributes, ""
        if tag == "canvas":
            self.canvas_ancestors = list(self._open_classes)
        if tag == "div":
            self._open_classes.append(attributes.get("class") or "")
        if attributes.get("id") and tag in {"code", "button"}:
            self._id_tag, self._id_text = (str(attributes["id"]), tag), ""

    def handle_endtag(self, tag: str) -> None:
        if tag == "script":
            self._in_inline_script = False
        if tag == "a":
            self._in_brand = False
            if self._link is not None:
                self.links.append((self._link, " ".join(self._link_text.split())))
                self._link = None
        if tag == "div" and self._open_classes:
            self._open_classes.pop()
        if self._id_tag is not None and tag == self._id_tag[1]:
            self.ids[self._id_tag[0]] = self._id_text.strip()
            self._id_tag = None
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
        if self._link is not None:
            self._link_text += data
        if self._id_tag is not None:
            self._id_text += data


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


@pytest.mark.integration
def test_get_started_leads_to_the_docs_guide(page: _Page) -> None:
    targets = [attrs.get("href") for attrs, text in page.links if text == "Get started"]
    assert targets == ["docs/getting-started/"]


def _nav_files(node: object) -> list[str]:
    """Every Markdown file named in a mkdocs nav tree."""
    if isinstance(node, str):
        return [node] if node.endswith(".md") else []
    if isinstance(node, dict):
        return [path for value in node.values() for path in _nav_files(value)]
    if isinstance(node, list):
        return [path for item in node for path in _nav_files(item)]
    return []


def _docs_url(markdown_file: str) -> str:
    """The directory URL mkdocs gives a page, relative to the docs site root."""
    stem = markdown_file.removesuffix(".md")
    parent, _, name = stem.rpartition("/")
    if name in {"index", "README"}:
        return f"{parent}/" if parent else ""
    return f"{stem}/"


@pytest.mark.integration
def test_docs_links_point_to_pages_in_the_docs_nav(page: _Page) -> None:
    """A link into the docs site, Get started included, must not lead to a 404."""
    config = yaml.safe_load((REPO_ROOT / "mkdocs.yml").read_text(encoding="utf-8"))
    published = {_docs_url(path) for path in _nav_files(config["nav"])}
    docs_links = [
        str(attrs["href"])[len(DOCS_PREFIX) :]
        for attrs, _ in page.links
        if str(attrs.get("href") or "").startswith(DOCS_PREFIX)
    ]
    assert "getting-started/" in docs_links
    assert [link for link in docs_links if link not in published] == []


@pytest.mark.integration
def test_install_command_is_plain_text(page: _Page) -> None:
    """Without JavaScript the command must still be there to select and copy."""
    assert page.ids["install-command"] == "pip install secure-sdlc-evidence-collector"


@pytest.mark.integration
def test_scene_has_its_own_box_beside_the_text(page: _Page) -> None:
    """The canvas lives in the hero's visual column, not in the stage behind the text."""
    assert "hero__globe" in page.canvas_ancestors
    assert not any("hero__stage" in classes for classes in page.canvas_ancestors)


@pytest.mark.integration
def test_confidence_score_is_labelled_evidence_strength() -> None:
    text = PAGE.read_text(encoding="utf-8")
    assert "<dt>Evidence strength</dt>" in text
    assert ">Confidence<" not in text
