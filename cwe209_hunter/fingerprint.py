"""Conservative indicators for possible verbose error disclosures."""
from __future__ import annotations

import re

# Indicators are triage hints, not proof by themselves.
RULES: dict[str, re.Pattern[str]] = {
    "python_traceback": re.compile(r"Traceback \(most recent call last\):", re.I),
    "java_stack_trace": re.compile(
        r"(?m)^\s*at\s+[\w.$<>]+\([^()\n]*\.java:\d+\)", re.I
    ),
    "php_fatal_error": re.compile(
        r"(?:PHP\s+)?Fatal error:\s+.*?\bon line\s+\d+", re.I | re.S
    ),
    "sqlstate_exception": re.compile(r"SQLSTATE\[[0-9A-Z]+\]", re.I),
    "oracle_error": re.compile(r"\bORA-\d{5}\b", re.I),
    "framework_exception": re.compile(
        r"(?:Illuminate\\Database\\QueryException|"
        r"Symfony\\Component\\[^\\\s]+\\Exception|"
        r"NullReferenceException)",
        re.I,
    ),
    "absolute_filesystem_path": re.compile(
        r"(?:/var/www/|/srv/|/opt/[^ \n]*/|/home/[^/\s]+/|"
        r"[A-Z]:\\(?:inetpub|xampp|wamp)\\)",
        re.I,
    ),
}

# Avoid storing full response bodies in reports. Keep only short matching excerpts.
def _excerpt(text: str, start: int, end: int, radius: int = 90) -> str:
    excerpt = text[max(0, start - radius):min(len(text), end + radius)]
    excerpt = re.sub(r"(?i)(authorization\s*:\s*bearer\s+)\S+", r"\1[REDACTED]", excerpt)
    excerpt = re.sub(r"(?i)(password|passwd|token|api[_-]?key)(\s*[=:]\s*)['\"]?[^'\"\s&,;]+",
                     r"\1\2[REDACTED]", excerpt)
    excerpt = re.sub(r"[\r\n\t]+", " ", excerpt)
    return excerpt[:300]


def fingerprint(body: str) -> list[dict[str, str]]:
    """Return rule matches with bounded, sanitized evidence excerpts."""
    matches: list[dict[str, str]] = []
    for name, pattern in RULES.items():
        match = pattern.search(body)
        if match:
            matches.append({
                "rule": name,
                "evidence": _excerpt(body, match.start(), match.end()),
            })
    return matches
