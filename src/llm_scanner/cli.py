from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

from llm_scanner.judge import OllamaJudge
from llm_scanner.models import ScanReport, Severity
from llm_scanner.payloads.loader import YamlPayloadLoader
from llm_scanner.preflight import (
    check_http_target_reachable,
    check_judge_differs_from_target,
    check_model_available,
    check_ollama_running,
    warm_up_judge,
)
from llm_scanner.reporters import get_file_reporter
from llm_scanner.scanner import LLMScanner
from llm_scanner.targets import TargetFactory

# Payloads live at project_root/payloads/ -- three levels up from this file
# (src/llm_scanner/cli.py -> src/llm_scanner/ -> src/ -> project_root)
_PAYLOAD_DIR = Path(__file__).parent.parent.parent / "payloads"

# LLM01-LLM09 are always safe to test; LLM10 requires explicit opt-in (CLI-08)
_SAFE_CATEGORIES: list[str] = [f"LLM{i:02d}" for i in range(1, 10)]

# Severity level ordering: higher int = more severe (used for minimum-severity filter)
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

_OLLAMA_HOST = "http://localhost:11434"

console = Console()


def _build_parser() -> argparse.ArgumentParser:
    """Build and return the argparse CLI parser."""
    parser = argparse.ArgumentParser(
        prog="llm-scanner",
        description="OWASP Top 10 for LLMs security scanner -- fully offline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Required arguments (CLI-01, CLI-02)
    parser.add_argument(
        "--target",
        required=True,
        help="URL (--target-type url) or Ollama model name (--target-type ollama)",
    )
    parser.add_argument(
        "--target-type",
        required=True,
        choices=["url", "ollama"],
        help="Type of target: 'url' for HTTP endpoints, 'ollama' for local models",
    )
    parser.add_argument(
        "--judge-model",
        required=True,
        help="Ollama model name to use as AI judge (must differ from target model)",
    )

    # Optional filter arguments (CLI-03, CLI-04)
    parser.add_argument(
        "--categories",
        default=None,
        help=(
            "Comma-separated OWASP categories to test (e.g. LLM01,LLM07). "
            "Default: all safe categories (LLM01-LLM09)."
        ),
    )
    parser.add_argument(
        "--severity",
        default=None,
        choices=["critical", "high", "medium", "low", "info"],
        help="Minimum severity level to include (default: all severities)",
    )

    # Authentication (CLI-05)
    parser.add_argument(
        "--api-key",
        default=None,
        help="Bearer token for URL targets (never included in logs or error output)",
    )

    # Output (CLI-06, CLI-07)
    parser.add_argument(
        "--output-dir",
        default=Path("./reports"),
        type=Path,
        help="Directory for saved report files (default: ./reports)",
    )
    parser.add_argument(
        "--format",
        default=None,
        dest="formats",
        help="Comma-separated output formats: md,json,html (terminal output always shown)",
    )

    # DoS opt-in (CLI-08)
    parser.add_argument(
        "--include-dos-tests",
        action="store_true",
        help="Include LLM10 Unbounded Consumption probes (opt-in -- may stress the target)",
    )

    return parser


def _resolve_categories(args: argparse.Namespace) -> list[str]:
    """Return the category list to scan based on --categories and --include-dos-tests.

    CLI-03: --categories filters categories; default is all safe categories.
    CLI-08: LLM10 only included when --include-dos-tests is explicitly set.
    """
    if args.categories is not None:
        categories = [c.strip().upper() for c in args.categories.split(",")]
        # Enforce LLM10 opt-in even when explicitly requested
        if "LLM10" in categories and not args.include_dos_tests:
            print(
                "[WARNING] LLM10 (Unbounded Consumption) removed -- use --include-dos-tests to enable DoS probes.",
                file=sys.stderr,
            )
            categories = [c for c in categories if c != "LLM10"]
        return categories

    # Default: safe set, optionally extended with LLM10
    categories = _SAFE_CATEGORIES.copy()
    if args.include_dos_tests:
        categories.append("LLM10")
    return categories


def _print_results(report: ScanReport) -> None:
    """Render scan results as a Rich table + risk score summary to the terminal."""
    _severity_styles: dict[str, str] = {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }

    table = Table(title=f"LLM Security Scan - {report.target}", show_lines=False)
    table.add_column("ID", style="dim", no_wrap=True)
    table.add_column("Category", no_wrap=True)
    table.add_column("Name")
    table.add_column("Severity", no_wrap=True)
    table.add_column("Result", no_wrap=True)

    for finding in report.findings:
        sev_str = str(finding.severity).lower()
        sev_style = _severity_styles.get(sev_str, "")
        if finding.success:
            result_markup = "[red bold]VULNERABLE[/red bold]"
        else:
            result_markup = "[green]Safe[/green]"
        table.add_row(
            finding.attack_id,
            finding.owasp_category,
            finding.name[:60],
            f"[{sev_style}]{finding.severity}[/{sev_style}]",
            result_markup,
        )

    console.print()
    console.print(table)
    console.print()

    successful = sum(1 for f in report.findings if f.success)
    total = len(report.findings)

    if report.risk_score >= 7.0:
        score_markup = f"[red bold]{report.risk_score:.1f}[/red bold]"
    elif report.risk_score >= 4.0:
        score_markup = f"[yellow]{report.risk_score:.1f}[/yellow]"
    else:
        score_markup = f"[green]{report.risk_score:.1f}[/green]"

    console.print(f"[bold]Attacks:[/bold]    {successful}/{total} succeeded")
    console.print(f"[bold]Risk Score:[/bold] {score_markup}/10.0")
    console.print()


async def _run(args: argparse.Namespace) -> None:
    """Orchestrate the full scan pipeline: preflight -> load -> scan -> report."""
    # 1. Resolve categories (CLI-03, CLI-08)
    categories = _resolve_categories(args)
    if not categories:
        console.print("[red]Error: No categories selected after filtering.[/red]")
        sys.exit(1)

    # 2. Preflight health checks (Phase 2: preflight.py)
    check_ollama_running(_OLLAMA_HOST)
    check_model_available(args.judge_model, _OLLAMA_HOST)
    check_judge_differs_from_target(args.target_type, args.target, args.judge_model)
    if args.target_type == "ollama":
        check_model_available(args.target, _OLLAMA_HOST)
    else:
        check_http_target_reachable(args.target, args.api_key)

    # 3. Load and filter payloads
    loader = YamlPayloadLoader(_PAYLOAD_DIR)
    payloads = loader.load(categories=categories)

    # CLI-04: minimum severity filter (post-load, because loader does exact-match only)
    if args.severity is not None:
        min_rank = _SEVERITY_RANK[Severity(args.severity)]
        payloads = [p for p in payloads if _SEVERITY_RANK[p.severity] >= min_rank]

    if not payloads:
        console.print("[red]Error: No payloads matched the specified filters.[/red]")
        sys.exit(1)

    # 4. Print scan header
    console.print(f"\n[bold]Target:[/bold]   {args.target} ({args.target_type})")
    console.print(f"[bold]Judge:[/bold]    {args.judge_model}")
    console.print(f"[bold]Payloads:[/bold] {len(payloads)} loaded\n")

    # 5. Build target and judge
    target = TargetFactory.from_config(
        target_type=args.target_type,
        target=args.target,
        api_key=args.api_key,
    )
    judge = OllamaJudge(model=args.judge_model)

    # 6. Warm up judge model (load into VRAM before first attack)
    console.print("[dim]Warming up judge model...[/dim]")
    await warm_up_judge(judge)

    # 7. Run scan
    async with target:
        scanner = LLMScanner(
            target=target,
            judge=judge,
            payloads=payloads,
            target_label=args.target,
        )
        report = await scanner.scan()

    # 8. Display results
    _print_results(report)

    # 9. Save file reports if requested (REPORT-02, REPORT-03, REPORT-04)
    if args.formats:
        for fmt in (f.strip() for f in args.formats.split(",")):
            try:
                reporter = get_file_reporter(fmt)
                saved = reporter.save(report, args.output_dir)
                console.print(f"[dim]Saved {fmt.upper()} report:[/dim] {saved}")
            except ValueError as exc:
                print(f"Warning: {exc}", file=sys.stderr)
            except OSError as exc:
                print(f"Warning: Could not save {fmt.upper()} report: {exc}", file=sys.stderr)


def main() -> None:
    """CLI entry point -- declared in pyproject.toml [project.scripts]."""
    parser = _build_parser()
    args = parser.parse_args()
    try:
        asyncio.run(_run(args))
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        sys.exit(130)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Fatal error:[/red] {exc}", file=sys.stderr)
        sys.exit(1)
