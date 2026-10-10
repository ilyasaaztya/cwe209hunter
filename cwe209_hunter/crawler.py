"""Bounded same-origin HTML crawler."""
from __future__ import annotations

from collections import deque
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from .scope import normalize_url, same_origin


async def crawl(
    client: httpx.AsyncClient,
    target: str,
    max_pages: int = 100,
) -> tuple[list[str], list[dict[str, str]]]:
    """Crawl same-origin links. Redirects are not automatically followed."""
    queue = deque([normalize_url(target)])
    queued = {queue[0]}
    visited: list[str] = []
    errors: list[dict[str, str]] = []
    root = target

    while queue and len(visited) < max_pages:
        url = queue.popleft()
        if url in visited or not same_origin(url, root):
            continue
        visited.append(url)

        try:
            response = await client.get(url)
        except httpx.HTTPError as exc:
            errors.append({"url": url, "error": type(exc).__name__})
            continue

        content_type = response.headers.get("content-type", "").lower()
        if response.status_code >= 300 and response.status_code < 400:
            # Do not follow redirects automatically; record target for visibility.
            continue
        if "text/html" not in content_type:
            continue

        soup = BeautifulSoup(response.text, "html.parser")
        for tag in soup.find_all(["a", "link", "area"]):
            href = tag.get("href")
            if not href:
                continue
            candidate = normalize_url(urljoin(url, href))
            parsed = urlparse(candidate)
            if (
                parsed.scheme in {"http", "https"}
                and same_origin(candidate, root)
                and candidate not in queued
                and len(queued) < max_pages * 10
            ):
                queued.add(candidate)
                queue.append(candidate)

    return visited, errors
