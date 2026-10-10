"""Command-line interface."""
from __future__ import annotations

import asyncio
import httpx
import typer

from . import __version__
from .analyzer import analyze_response
from .crawler import crawl
from .dedup import deduplicate
from .methods import DEFAULT_METHODS, probe_method
from .reporter import write_reports
from .scope import validate_target

app = typer.Typer(
    name="cwe209-hunter",
    help="Scoped discovery and triage for possible CWE-209 disclosures.",
    no_args_is_help=True,
)


@app.command()
def version() -> None:
    """Show the installed version."""
    typer.echo(f"CWE-209 Hunter {__version__}")


@app.command()
def scan(
    target: str = typer.Argument(..., help="Authorized HTTP(S) target URL"),
    max_pages: int = typer.Option(50, min=1, max=500, help="Maximum pages to crawl"),
    delay: float = typer.Option(0.5, min=0.2, max=10.0, help="Delay between probes"),
    timeout: float = typer.Option(8.0, min=1.0, max=30.0, help="Request timeout"),
    output_dir: str = typer.Option("reports", "--output-dir", "-o"),
    user_agent: str = typer.Option(
        "CWE209-Hunter/0.1.0 (+authorized security testing)",
        help="User-Agent header",
    ),
) -> None:
    """Crawl one origin and run low-impact GET/HEAD/OPTIONS checks."""
    try:
        normalized = validate_target(target)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc

    typer.echo("Use only against systems you own or are explicitly authorized to test.")
    typer.echo(f"Target: {normalized}")
    results = asyncio.run(
        _run_scan(normalized, max_pages, delay, timeout, output_dir, user_agent)
    )
    typer.echo(f"Pages crawled: {results['pages']}")
    typer.echo(f"Candidate findings: {results['findings']}")
    for report in results["reports"]:
        typer.echo(f"Report: {report}")


async def _run_scan(
    target: str,
    max_pages: int,
    delay: float,
    timeout: float,
    output_dir: str,
    user_agent: str,
) -> dict:
    headers = {"User-Agent": user_agent}
    limits = httpx.Limits(max_connections=2, max_keepalive_connections=2)
    request_timeout = httpx.Timeout(timeout, connect=min(timeout, 5.0))
    async with httpx.AsyncClient(
        headers=headers,
        timeout=request_timeout,
        limits=limits,
        follow_redirects=False,
        verify=True,
    ) as client:
        pages, crawl_errors = await crawl(client, target, max_pages=max_pages)
        findings = []
        for url in pages:
            for method in DEFAULT_METHODS:
                try:
                    response = await probe_method(client, method, url)
                    body = ""
                    if method != "HEAD":
                        content_type = response.headers.get("content-type", "").lower()
                        if (
                            "text/" in content_type
                            or "json" in content_type
                            or "xml" in content_type
                        ):
                            # Bound body size in memory; do not analyze arbitrary binaries.
                            body = response.text[:1_000_000]
                    finding = analyze_response(
                        url=url,
                        method=method,
                        status_code=response.status_code,
                        headers={k.lower(): v for k, v in response.headers.items()},
                        body=body,
                    )
                    if finding:
                        findings.append(finding)
                except (httpx.HTTPError, ValueError) as exc:
                    crawl_errors.append({"url": url, "error": type(exc).__name__})
                await asyncio.sleep(delay)

    findings = deduplicate(findings)
    reports = write_reports(output_dir, target, pages, crawl_errors, findings)
    return {"pages": len(pages), "findings": len(findings), "reports": reports}


if __name__ == "__main__":
    app()
