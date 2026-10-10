# Architecture

1. `scope.py`: validates target URLs and enforces same-origin boundaries.
2. `crawler.py`: bounded HTML crawler; redirects are not followed automatically.
3. `methods.py`: exposes only conservative GET/HEAD/OPTIONS probes.
4. `fingerprint.py`: matches technical error indicators and emits short sanitized excerpts.
5. `analyzer.py`: creates candidate findings requiring manual validation.
6. `dedup.py`: collapses repeated candidates by path, method, and matched rules.
7. `reporter.py`: writes JSON, CSV, and Markdown reports.
8. `cli.py`: orchestrates the scan.

## Safety assumptions

- The operator has explicit authorization.
- No mutating methods are sent.
- Only URLs on the original scheme/host/port are crawled.
- Redirects are not automatically followed.
- Response bodies are bounded before analysis.
- Candidate classification is not a severity rating or proof of vulnerability.
