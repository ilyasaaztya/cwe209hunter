"""Response analysis and candidate classification."""
from __future__ import annotations

from typing import Any

from .fingerprint import fingerprint


def analyze_response(
    url: str,
    method: str,
    status_code: int,
    headers: dict[str, str],
    body: str,
) -> dict[str, Any] | None:
    """Analyze a response and return a candidate only when indicators match."""
    content_type = headers.get("content-type", "").lower()
    if method == "HEAD" or not (
        "text/" in content_type or "json" in content_type or "xml" in content_type
    ):
        return None

    indicators = fingerprint(body)
    if not indicators:
        return None

    # Conservative triage label; human validation remains mandatory.
    confidence = "medium" if len(indicators) >= 2 else "low"
    return {
        "cwe": "CWE-209",
        "title": "Possible verbose error information disclosure",
        "url": url,
        "method": method,
        "status_code": status_code,
        "confidence": confidence,
        "indicators": indicators,
        "validation_status": "needs_manual_validation",
        "rationale": (
            "A technical error indicator was found. Confirm that the response "
            "is unintended, reachable by an unauthorized user, and discloses "
            "useful internal details before reporting CWE-209."
        ),
    }
