"""Link-header pagination shared by the SCM collectors.

GitHub and GitLab both page list endpoints and announce the next page in an
RFC 8288 `Link` header. Reading only the first page silently drops data, and
for code review that can flip a verdict, so every list the collectors decide
on goes through `get_all_pages`.

The helper fails closed: it raises `PaginationError` instead of returning a
partial list when the page cap is reached or when a `next` link points away
from the API origin the client was configured with (following it would send
the bearer token to that host).
"""

from __future__ import annotations

from typing import Any

import httpx

# 50 pages x 100 items per page. Far beyond any real pull request.
MAX_PAGES = 50
PER_PAGE = 100


class PaginationError(RuntimeError):
    """A paged list could not be read completely; no partial result is used."""


def get_all_pages(
    client: httpx.Client,
    path: str,
    *,
    params: dict[str, Any] | None = None,
    max_pages: int = MAX_PAGES,
) -> list[Any]:
    """Return every item of a paged JSON list, following `rel="next"` links."""
    origin = client.base_url
    items: list[Any] = []
    url: str = path
    query: dict[str, Any] | None = {"per_page": PER_PAGE, **(params or {})}
    for _ in range(max_pages):
        response = client.get(url, params=query)
        response.raise_for_status()
        page = response.json()
        if not isinstance(page, list):
            raise PaginationError(f"expected a JSON list from {path}")
        items.extend(page)
        next_url = response.links.get("next", {}).get("url")
        if not next_url:
            return items
        target = httpx.URL(next_url)
        if target.is_absolute_url and (
            target.scheme != origin.scheme
            or target.host != origin.host
            or target.port != origin.port
        ):
            raise PaginationError(f"next page link for {path} leaves the API origin")
        url = next_url
        query = None
    raise PaginationError(f"{path} has more than {max_pages} pages; refusing a partial list")
