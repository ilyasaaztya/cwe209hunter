# CWE-209 Hunter

A modular, scope-limited discovery and triage tool for possible **CWE-209: Generation of Error Message Containing Sensitive Information** findings.

> **Important:** this tool produces candidates, not confirmed vulnerabilities. A pattern match does not establish that information is sensitive, unintended, or exposed to an unauthorized user. Validate findings manually and test only systems you own or are explicitly authorized to assess.

## Features

- Same-origin HTML crawling with a configurable page limit.
- Conservative `GET`, `HEAD`, and `OPTIONS` probes.
- No automatic redirect following; no `TRACE`, `PUT`, `PATCH`, or `DELETE` probes.
- Fingerprints for selected stack traces, SQL exceptions, framework exceptions, and internal paths.
- Query-string-aware report deduplication (query strings are omitted from the deduplication key).
- JSON, CSV, and Markdown reports.
- Bounded response-body analysis and short, partially redacted evidence excerpts.
- Unit tests and GitHub Actions CI.

## Requirements

- Python 3.10 or later
- Network access to the authorized test environment

## Install from source

```bash
git clone https://github.com/ilyasaaztya/cwe209-hunter.git
cd cwe209-hunter

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

## Usage

Use only on an authorized target. Begin with a staging system or a local test application.

```bash
cwe209-hunter --help
cwe209-hunter version

cwe209-hunter scan https://staging.example.test \
  --max-pages 50 \
  --delay 0.5 \
  --output-dir reports
```

Output files:

- `reports/findings.json`
- `reports/findings.csv`
- `reports/findings.md`

The default scanner uses `GET`, `HEAD`, and `OPTIONS`. It does not submit forms, guess credentials, bypass access controls, or execute mutating HTTP methods. Crawling is restricted to the initial origin. Redirects are not automatically followed.

## Development

```bash
python -m pip install -e ".[dev]"
pytest -q
ruff check .
```

## Detection methodology and limitations

Rules are conservative indicators and may produce false positives. For example, a stack trace shown only in a deliberately public documentation example is not automatically a vulnerability. Conversely, some real disclosures will not match the current patterns.

Before reporting, verify:

1. The response is reproducible.
2. The technical details are not intended for public display.
3. The content reveals meaningful internal implementation or diagnostic information.
4. An unauthorized user can access the response under the tested conditions.
5. Evidence is minimal and does not expose credentials, tokens, personal data, or unrelated records.

The current release does not implement JavaScript endpoint extraction, authenticated crawling, form submission, differential baseline scoring, or a validated CVSS calculator. Do not interpret its confidence labels as severity ratings.

## Responsible use

You are responsible for complying with applicable laws, program rules, and written authorization. Set conservative rate limits. Stop if testing affects service availability or data integrity. Do not use this tool to access or retain information beyond the approved scope.

## Contributing

Contributions are welcome. Please include regression tests for new fingerprints, document false-positive considerations, and never include live secrets or real personal data in fixtures.

## License

MIT. See [LICENSE](LICENSE).
