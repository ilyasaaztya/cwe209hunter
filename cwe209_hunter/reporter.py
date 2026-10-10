"""JSON, CSV and Markdown report exporters."""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any


def write_reports(
    output_dir: str,
    target: str,
    pages: list[str],
    crawl_errors: list[dict[str, str]],
    findings: list[dict[str, Any]],
) -> list[str]:
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)

    payload = {
        "tool": "CWE-209 Hunter",
        "version": "0.1.0",
        "target": target,
        "pages_crawled": len(pages),
        "crawl_errors": crawl_errors,
        "findings_count": len(findings),
        "findings": findings,
        "disclaimer": (
            "Candidates are not confirmed vulnerabilities. Manually validate "
            "scope, exposure, sensitivity, and reproducibility."
        ),
    }

    json_path = directory / "findings.json"
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    csv_path = directory / "findings.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["cwe", "title", "url", "method", "status_code",
                        "confidence", "validation_status", "rules"],
        )
        writer.writeheader()
        for finding in findings:
            row = {key: finding.get(key, "") for key in writer.fieldnames}
            row["rules"] = ", ".join(
                item.get("rule", "") for item in finding.get("indicators", [])
            )
            writer.writerow(row)

    md_path = directory / "findings.md"
    lines = [
        "# CWE-209 Hunter Report",
        "",
        f"- Target: `{target}`",
        f"- Pages crawled: {len(pages)}",
        f"- Candidate findings: {len(findings)}",
        "",
        "> Candidates require manual validation; matches alone do not prove CWE-209.",
        "",
    ]
    if not findings:
        lines.append("No matching error-disclosure indicators were found.")
    for index, finding in enumerate(findings, 1):
        lines += [
            f"## {index}. {finding['title']}",
            "",
            f"- CWE: {finding['cwe']}",
            f"- URL: `{finding['url']}`",
            f"- Method: `{finding['method']}`",
            f"- Status: `{finding['status_code']}`",
            f"- Confidence: **{finding['confidence']}**",
            f"- Validation: `{finding['validation_status']}`",
            "- Indicators:",
        ]
        for indicator in finding.get("indicators", []):
            lines.append(f"  - `{indicator['rule']}` — `{indicator['evidence']}`")
        lines += ["", finding["rationale"], ""]
    md_path.write_text("\n".join(lines), encoding="utf-8")

    return [str(json_path), str(csv_path), str(md_path)]
