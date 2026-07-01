from __future__ import annotations

import argparse
import asyncio
import os
import re
import sys
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict
from rich.console import Console
from rich.table import Table

from llm_scanner.baselines import BaselineManager
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
from llm_scanner.reporters.trend import TrendReporter
from llm_scanner.scanner import LLMScanner
from llm_scanner.suppressions import SuppressionLoader
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


class _ScanAbort(Exception):
    """Raised inside _run() to signal a structured early exit without a traceback.

    Caught in main() to call sys.exit(1) cleanly, avoiding sys.exit() inside
    an async coroutine which can be fragile under some Python implementations.
    """


class TargetConfig(BaseModel):
    """A single target entry from targets.yaml (ADV-06).

    Uses extra="ignore" so that user-authored YAML files with additional
    metadata keys do not cause validation errors.
    """

    model_config = ConfigDict(extra="ignore")

    name: str
    target: str
    target_type: str
    api_key: str | None = None


def _build_parser() -> argparse.ArgumentParser:
    """Build and return the argparse CLI parser."""
    parser = argparse.ArgumentParser(
        prog="llm-scanner",
        description="OWASP Top 10 for LLMs security scanner -- fully offline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Required arguments (CLI-01, CLI-02) -- --target is optional when --targets is used
    parser.add_argument(
        "--target",
        required=False,
        default=None,
        help="URL (--target-type url) or Ollama model name (--target-type ollama)",
    )
    parser.add_argument(
        "--target-type",
        required=False,
        default=None,
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
        help="Parent directory for scan reports (default: ./reports). Each scan creates a timestamped subfolder.",
    )
    parser.add_argument(
        "--format",
        default="md,json,html,txt",
        dest="formats",
        help="Comma-separated output formats: md,json,html,txt (default: all four). Terminal output always shown.",
    )

    # DoS opt-in (CLI-08)
    parser.add_argument(
        "--include-dos-tests",
        action="store_true",
        help="Include LLM10 Unbounded Consumption probes (opt-in -- may stress the target)",
    )

    # Phase 05 new scan flags
    parser.add_argument(
        "--fail-on-score",
        type=float,
        default=None,
        dest="fail_on_score",
        help="Exit with code 1 if risk score >= this threshold (e.g. 7.0)",
    )
    parser.add_argument(
        "--targets",
        dest="targets_file",
        type=Path,
        default=None,
        help="YAML file with multiple scan targets for side-by-side comparison (ADV-06)",
    )
    parser.add_argument(
        "--suppressions",
        dest="suppressions_file",
        type=Path,
        default=None,
        help="YAML file with suppression rules to exclude known false positives (ADV-05)",
    )

    # Subcommands for baseline management (ADV-02)
    # CRITICAL: add_subparsers MUST be called before set_defaults
    # add_subparsers(dest='command') resets the dest default to None,
    # so set_defaults called before would be silently overridden.
    subparsers = parser.add_subparsers(dest="command", required=False)

    baseline_p = subparsers.add_parser("baseline", help="Manage scan baselines")
    baseline_subs = baseline_p.add_subparsers(dest="baseline_action", required=True)

    save_p = baseline_subs.add_parser("save", help="Save latest scan as named baseline")
    save_p.add_argument("--name", required=True, help="Baseline name (e.g. 'production')")
    save_p.add_argument(
        "--output-dir",
        dest="output_dir",
        type=Path,
        default=Path("./reports"),
        help="Directory containing existing scan reports (default: ./reports)",
    )

    compare_p = baseline_subs.add_parser(
        "compare", help="Compare a new scan against a saved baseline"
    )
    compare_p.add_argument("--name", required=True, help="Baseline name to compare against")

    # MUST be the last statement -- called after add_subparsers to avoid being overridden
    parser.set_defaults(command="scan")

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
        if getattr(finding, "suppressed", False):
            result_markup = "[dim]Accepted[/dim]"
        elif finding.success:
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


def _resolve_env_vars(value: str) -> str:
    """Expand ${ENV_VAR} references in *value* using os.environ (T-05-13)."""
    return re.sub(r"\$\{([^}]+)\}", lambda m: os.environ.get(m.group(1), ""), value)


def _apply_suppressions(report: ScanReport, suppressions_file: Path) -> ScanReport:
    """Apply suppression rules and recompute risk_score (ADV-05, pitfall #4).

    Suppressions are applied POST-scan so the attack still runs; only the
    risk score and report labels are adjusted.
    """
    SuppressionLoader(suppressions_file).apply(report.findings)
    adjusted_score = LLMScanner._compute_risk_score(  # type: ignore[arg-type]
        [f for f in report.findings if not f.suppressed]
    )
    return ScanReport(
        target=report.target,
        timestamp=report.timestamp,
        risk_score=adjusted_score,
        findings=report.findings,
    )


async def _run(args: argparse.Namespace) -> None:
    """Orchestrate the full scan pipeline: preflight -> load -> scan -> report."""
    # Guard: --target is required in scan mode
    if not getattr(args, "target", None):
        console.print("[red]Error: --target is required for scan mode.[/red]")
        raise _ScanAbort()

    # 1. Resolve categories (CLI-03, CLI-08)
    categories = _resolve_categories(args)
    if not categories:
        console.print("[red]Error: No categories selected after filtering.[/red]")
        raise _ScanAbort()

    # 2. Preflight health checks (Phase 2: preflight.py)
    check_ollama_running(_OLLAMA_HOST)
    check_model_available(args.judge_model, _OLLAMA_HOST)
    check_judge_differs_from_target(args.target_type, args.target, args.judge_model)
    if args.target_type == "ollama":
        check_model_available(args.target, _OLLAMA_HOST)
    else:
        check_http_target_reachable(args.target, getattr(args, "api_key", None))

    # 3. Load and filter payloads
    loader = YamlPayloadLoader(_PAYLOAD_DIR)
    payloads = loader.load(categories=categories)

    # CLI-04: minimum severity filter (post-load, because loader does exact-match only)
    if args.severity is not None:
        min_rank = _SEVERITY_RANK[Severity(args.severity)]
        payloads = [p for p in payloads if _SEVERITY_RANK[p.severity] >= min_rank]

    if not payloads:
        console.print("[red]Error: No payloads matched the specified filters.[/red]")
        raise _ScanAbort()

    # 4. Print scan header
    console.print(f"\n[bold]Target:[/bold]   {args.target} ({args.target_type})")
    console.print(f"[bold]Judge:[/bold]    {args.judge_model}")
    console.print(f"[bold]Payloads:[/bold] {len(payloads)} loaded\n")

    # 5. Build target and judge
    target = TargetFactory.from_config(
        target_type=args.target_type,
        target=args.target,
        api_key=getattr(args, "api_key", None),
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

    # 7b. Apply suppressions post-scan (ADV-05) -- before display and report saving
    if getattr(args, "suppressions_file", None):
        report = _apply_suppressions(report, args.suppressions_file)

    # 8. Display results
    _print_results(report)

    # 9. Save file reports (REPORT-02, REPORT-03, REPORT-04, REPORT-05)
    # Each scan gets its own subfolder: <output_dir>/<YYYYMMDD_HHMMSS>_<target_slug>/
    ts = report.timestamp.strftime("%Y%m%dT%H%M%S")
    target_slug = re.sub(r"[^a-zA-Z0-9]+", "_", report.target).strip("_")[:40]
    scan_dir = args.output_dir / f"{ts}_{target_slug}"

    saved_paths: list[str] = []
    for fmt in (f.strip() for f in args.formats.split(",") if f.strip()):
        try:
            reporter = get_file_reporter(fmt)
            saved = reporter.save(report, scan_dir)
            saved_paths.append(str(saved))
        except ValueError as exc:
            print(f"Warning: {exc}", file=sys.stderr)
        except OSError as exc:
            print(f"Warning: Could not save {fmt.upper()} report: {exc}", file=sys.stderr)

    if saved_paths:
        console.print(f"[dim]Reports saved to:[/dim] {scan_dir}/")

    # 10. Regenerate trend dashboard after every scan (ADV-03)
    try:
        TrendReporter().save(args.output_dir)
    except OSError as exc:
        print(f"Warning: Could not update trend dashboard: {exc}", file=sys.stderr)

    # 11. Fail-on-score check -- AFTER suppressions and AFTER saving reports (ADV-01)
    if getattr(args, "fail_on_score", None) is not None and report.risk_score >= args.fail_on_score:
        console.print(
            f"[red bold]FAIL:[/red bold] Risk score {report.risk_score:.1f} "
            f">= threshold {args.fail_on_score:.1f}"
        )
        raise _ScanAbort()


async def _run_baseline(args: argparse.Namespace) -> None:
    """Handle baseline save / compare subcommands (ADV-02)."""
    bm = BaselineManager(args.output_dir)

    if args.baseline_action == "save":
        try:
            path = bm.save(args.name)
            console.print(f"[green]Baseline '{args.name}' saved to {path}[/green]")
        except FileNotFoundError as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise _ScanAbort() from exc
        except ValueError as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise _ScanAbort() from exc

    elif args.baseline_action == "compare":
        # Run full scan first, then diff against saved baseline
        await _run(args)

        # Load the saved baseline
        try:
            baseline = bm.load(args.name)
        except FileNotFoundError as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise _ScanAbort() from exc
        except ValueError as exc:
            console.print(f"[red]Error:[/red] {exc}")
            raise _ScanAbort() from exc

        # Find the most recently written report.json for the current scan
        candidates = [
            p
            for p in args.output_dir.rglob("report.json")
            if not p.is_relative_to(args.output_dir / "baselines")
        ]
        if not candidates:
            console.print("[red]Error: No scan report found to compare.[/red]")
            raise _ScanAbort()
        most_recent = max(candidates, key=lambda p: p.stat().st_mtime)
        current_report = ScanReport.model_validate_json(
            most_recent.read_text(encoding="utf-8")
        )

        new_findings = BaselineManager.diff_findings(baseline, current_report)

        table = Table(title=f"Baseline Compare: '{args.name}' vs current scan")
        table.add_column("ID", style="dim", no_wrap=True)
        table.add_column("Category", no_wrap=True)
        table.add_column("Name")
        table.add_column("Severity", no_wrap=True)

        for f in new_findings:
            table.add_row(f.attack_id, f.owasp_category, f.name, str(f.severity))

        console.print()
        console.print(table)
        if new_findings:
            console.print(f"[red bold]{len(new_findings)} new finding(s) vs baseline.[/red bold]")
        else:
            console.print("[green]No new findings vs baseline.[/green]")
        console.print()


async def _run_multi_target(args: argparse.Namespace) -> None:
    """Run one scan per target from targets.yaml and show side-by-side comparison (ADV-06)."""
    raw = yaml.safe_load(Path(args.targets_file).read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or "targets" not in raw:
        console.print("[red]Error: targets.yaml must have a top-level 'targets' list.[/red]")
        raise _ScanAbort()

    target_configs: list[TargetConfig] = []
    for entry in raw["targets"]:
        # Resolve ${ENV_VAR} references in api_key and target fields (T-05-13)
        if entry.get("api_key"):
            entry["api_key"] = _resolve_env_vars(str(entry["api_key"]))
        if entry.get("target"):
            entry["target"] = _resolve_env_vars(str(entry["target"]))
        target_configs.append(TargetConfig(**entry))

    reports: list[ScanReport] = []
    for tc in target_configs:
        # Build per-target args namespace from a copy of the top-level args
        args_copy = argparse.Namespace(**vars(args))
        args_copy.target = tc.target
        args_copy.target_type = tc.target_type
        args_copy.api_key = tc.api_key
        try:
            await _run(args_copy)
        except _ScanAbort:
            console.print(f"[yellow]Warning: scan for '{tc.name}' aborted -- skipping.[/yellow]")
            continue

        # Pick up the most recently saved report
        candidates = [
            p
            for p in args.output_dir.rglob("report.json")
            if not p.is_relative_to(args.output_dir / "baselines")
        ]
        if candidates:
            most_recent = max(candidates, key=lambda p: p.stat().st_mtime)
            report = ScanReport.model_validate_json(
                most_recent.read_text(encoding="utf-8")
            )
            reports.append(report)

    if not reports:
        console.print("[red]Error: No successful scans in multi-target run.[/red]")
        raise _ScanAbort()

    # Build OWASP category set from all findings across all reports
    all_categories = sorted(
        {f.owasp_category for r in reports for f in r.findings}
    )

    table = Table(title="Multi-Target Comparison")
    table.add_column("OWASP Category")
    for tc in target_configs:
        table.add_column(tc.name)

    for category in all_categories:
        row: list[str] = [category]
        for report in reports:
            cat_findings = [f for f in report.findings if f.owasp_category == category]
            vuln_count = sum(1 for f in cat_findings if f.success)
            total = len(cat_findings)
            row.append(f"{vuln_count}/{total}" if total else "—")
        table.add_row(*row)

    console.print()
    console.print(table)
    console.print()


def main() -> None:
    """CLI entry point -- declared in pyproject.toml [project.scripts]."""
    parser = _build_parser()
    args = parser.parse_args()
    try:
        if getattr(args, "targets_file", None) is not None:
            asyncio.run(_run_multi_target(args))
        elif args.command in (None, "scan"):
            asyncio.run(_run(args))
        elif args.command == "baseline":
            asyncio.run(_run_baseline(args))
    except _ScanAbort:
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        sys.exit(130)
    except Exception as exc:
        console.print(f"[red]Fatal error:[/red] {exc}", file=sys.stderr)
        sys.exit(1)
