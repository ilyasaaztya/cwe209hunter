import pytest

from cwe209_hunter.scope import normalize_url, same_origin, validate_target


def test_normalize_removes_fragment():
    assert normalize_url("https://example.test/a#section") == "https://example.test/a"


def test_validate_target_requires_http_scheme():
    with pytest.raises(ValueError):
        validate_target("file:///etc/passwd")


def test_validate_target_rejects_credentials():
    with pytest.raises(ValueError):
        validate_target("https://user:pass@example.test/")


def test_same_origin_checks_port_and_scheme():
    assert same_origin("https://example.test/a", "https://example.test/")
    assert not same_origin("http://example.test/a", "https://example.test/")
    assert not same_origin("https://example.test:8443/a", "https://example.test/")
    assert not same_origin("https://other.test/", "https://example.test/")
