"""Stable finding deduplication."""
from __future__ import annotations

from typing import Any
from urllib.parse import urlparse, urlunparse


def _key(item: dict[str, Any]) -> tuple[str, str, tuple[str, ...]]:
    parsed = urlparse(item.get("url", ""))
    # Query strings can contain identifiers/secrets; omit them from dedup key.
    normalized = urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path, "", "", "")
    )
    rules = tuple(sorted(
        indicator.get("rule", "")
        for indicator in item.get("indicators", [])
    ))
    return normalized, item.get("method", ""), rules


def deduplicate(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep one representative for each URL path/method/rule combination."""
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    output = []
    for finding in findings:
        key = _key(finding)
        if key not in seen:
            seen.add(key)
            output.append(finding)
    return output
