"""URL validation and same-origin scope enforcement."""
from urllib.parse import urlparse, urldefrag


def normalize_url(url: str) -> str:
    """Normalize a URL by trimming whitespace and removing its fragment."""
    return urldefrag(url.strip())[0]


def validate_target(url: str) -> str:
    """Validate and return an absolute HTTP(S) target URL."""
    normalized = normalize_url(url)
    parsed = urlparse(normalized)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Target must use http:// or https://")
    if not parsed.hostname:
        raise ValueError("Target must include a hostname")
    if parsed.username or parsed.password:
        raise ValueError("Credentials in target URLs are not supported")
    return normalized


def origin_of(url: str) -> tuple[str, str, int]:
    """Return normalized scheme, hostname and effective port."""
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower().rstrip(".")
    port = parsed.port or (443 if scheme == "https" else 80)
    return scheme, host, port


def same_origin(url: str, root: str) -> bool:
    """True only when scheme, host and effective port match."""
    try:
        parsed = urlparse(url)
        return parsed.scheme in {"http", "https"} and origin_of(url) == origin_of(root)
    except ValueError:
        return False
