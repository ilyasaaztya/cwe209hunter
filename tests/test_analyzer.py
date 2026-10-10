from cwe209_hunter.analyzer import analyze_response
from cwe209_hunter.dedup import deduplicate


def test_analyzer_requires_text_content():
    assert analyze_response(
        "https://example.test/", "GET", 500,
        {"content-type": "application/octet-stream"},
        "Traceback (most recent call last):",
    ) is None


def test_analyzer_returns_candidate_not_confirmation():
    result = analyze_response(
        "https://example.test/", "GET", 500,
        {"content-type": "text/html"},
        "Traceback (most recent call last):",
    )
    assert result is not None
    assert result["cwe"] == "CWE-209"
    assert result["validation_status"] == "needs_manual_validation"


def test_dedup_ignores_query_parameters():
    base = {
        "cwe": "CWE-209", "method": "GET",
        "indicators": [{"rule": "python_traceback"}],
    }
    a = {**base, "url": "https://example.test/error?id=1"}
    b = {**base, "url": "https://example.test/error?id=2"}
    assert len(deduplicate([a, b])) == 1
