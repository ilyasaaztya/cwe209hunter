# Detection rules

Current fingerprints are intentionally narrow:

- Python traceback marker
- Java stack trace source-line pattern
- PHP fatal error pattern
- SQLSTATE and Oracle error markers
- Selected framework exception names
- Selected absolute filesystem path prefixes

## Limitations

A match can be benign, stale, intentionally documented, or unrelated to sensitive information. A lack of matches does not imply safety. CWE-209 requires context: an error message must expose sensitive information that should not be available to the recipient. Validate authorization context, reproducibility, and actual disclosure before filing a report.

Add rules with a fixture and tests for both positive and negative cases. Avoid generic rules that match words such as `error`, `exception`, or HTTP 500 by themselves.
