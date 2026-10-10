"""Conservative HTTP method probes."""
from __future__ import annotations

import httpx

DEFAULT_METHODS = ("GET", "HEAD", "OPTIONS")


async def probe_method(
    client: httpx.AsyncClient,
    method: str,
    url: str,
) -> httpx.Response:
    """Perform a permitted low-impact probe.

    GET is used for crawling/baseline. HEAD and OPTIONS are safe defaults.
    Mutating methods and TRACE are intentionally not implemented here.
    """
    normalized = method.upper()
    if normalized not in DEFAULT_METHODS:
        raise ValueError(f"Method not enabled by default: {normalized}")
    if normalized == "GET":
        return await client.get(url)
    return await client.request(normalized, url)
