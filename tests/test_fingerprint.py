from cwe209_hunter.fingerprint import fingerprint


def test_detects_python_traceback():
    matches = fingerprint("Traceback (most recent call last):\n  File \"/app/main.py\"")
    assert any(item["rule"] == "python_traceback" for item in matches)


def test_detects_sqlstate():
    matches = fingerprint("Database exception SQLSTATE[42000]: syntax error")
    assert any(item["rule"] == "sqlstate_exception" for item in matches)


def test_generic_error_word_is_not_enough():
    assert fingerprint("<h1>Error</h1><p>Please try again later.</p>") == []


def test_redacts_token_in_excerpt():
    matches = fingerprint("Traceback (most recent call last): token=secret-value")
    assert matches
    assert all("secret-value" not in item["evidence"] for item in matches)
