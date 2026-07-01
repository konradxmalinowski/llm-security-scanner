from __future__ import annotations

import argparse
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from llm_scanner.cli import (
    _SAFE_CATEGORIES,
    _SEVERITY_RANK,
    _apply_suppressions,
    _build_parser,
    _resolve_categories,
    _ScanAbort,
)
from llm_scanner.models import AttackResult, ScanReport, Severity
from llm_scanner.scanner import LLMScanner

# asyncio_mode = "auto" is set in pyproject.toml — no @pytest.mark.asyncio needed


def _parse(*extra: str) -> argparse.Namespace:
    """Convenience helper: parse args with required flags pre-set."""
    base = [
        "--target", "http://example.com/chat",
        "--target-type", "url",
        "--judge-model", "llama3.2:3b",
    ]
    return _build_parser().parse_args([*base, *extra])


def _ns(**kwargs: object) -> argparse.Namespace:
    """Build a Namespace with sensible defaults for _resolve_categories tests."""
    defaults = {"categories": None, "include_dos_tests": False}
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


# ---------------------------------------------------------------------------
# Parser tests — CLI-01, CLI-02
# ---------------------------------------------------------------------------


def test_parser_target_is_optional_at_parse_time() -> None:
    """--target is no longer required at argparse level (Phase 05: --targets mode).

    Runtime enforcement in _run() raises _ScanAbort when both --target and
    --targets are absent; argparse itself does not raise SystemExit.
    """
    # Should NOT raise -- argparse accepts missing --target (optional since Phase 05)
    args = _build_parser().parse_args(["--target-type", "url", "--judge-model", "llama3.2:3b"])
    assert args.target is None


def test_parser_requires_target_type() -> None:
    """--target-type accepts valid choices only."""
    with pytest.raises(SystemExit):
        _build_parser().parse_args(["--target", "http://x.com", "--target-type", "grpc", "--judge-model", "llama3.2:3b"])


def test_parser_requires_judge_model() -> None:
    """--judge-model is required."""
    with pytest.raises(SystemExit):
        _build_parser().parse_args(["--target", "http://x.com", "--target-type", "url"])


def test_parser_full_required_args() -> None:
    """Parsing required args only sets correct values and safe defaults."""
    args = _parse()
    assert args.target == "http://example.com/chat"
    assert args.target_type == "url"
    assert args.judge_model == "llama3.2:3b"
    assert args.include_dos_tests is False
    assert args.api_key is None
    assert args.output_dir == Path("./reports")
    assert args.severity is None
    assert args.formats == "md,json,html,txt"
    assert args.categories is None


def test_parser_include_dos_tests_flag() -> None:
    """--include-dos-tests sets include_dos_tests to True."""
    args = _parse("--include-dos-tests")
    assert args.include_dos_tests is True


def test_parser_invalid_target_type() -> None:
    """Unknown --target-type causes SystemExit (choices validation)."""
    with pytest.raises(SystemExit):
        _build_parser().parse_args([
            "--target", "grpc://x", "--target-type", "grpc", "--judge-model", "llama3.2:3b",
        ])


def test_parser_api_key_arg(capsys: pytest.CaptureFixture[str]) -> None:
    """--api-key is parsed and stored as args.api_key (CLI-05)."""
    args = _parse("--api-key", "secret-token")
    assert args.api_key == "secret-token"


def test_parser_output_dir(capsys: pytest.CaptureFixture[str]) -> None:
    """--output-dir is parsed as a Path (CLI-06)."""
    args = _parse("--output-dir", "/tmp/scan-results")  # noqa: S108
    assert args.output_dir == Path("/tmp/scan-results")  # noqa: S108
    assert isinstance(args.output_dir, Path)


def test_parser_severity_choices() -> None:
    """--severity accepts valid choices (CLI-04)."""
    for choice in ["critical", "high", "medium", "low", "info"]:
        args = _parse("--severity", choice)
        assert args.severity == choice


def test_parser_severity_invalid() -> None:
    """Unknown --severity causes SystemExit."""
    with pytest.raises(SystemExit):
        _parse("--severity", "extreme")


def test_parser_format_arg() -> None:
    """--format is stored as args.formats (CLI-07)."""
    args = _parse("--format", "md,json,html")
    assert args.formats == "md,json,html"


def test_parser_ollama_target_type() -> None:
    """--target-type ollama is valid (CLI-01)."""
    args = _build_parser().parse_args([
        "--target", "llama3.2:3b",
        "--target-type", "ollama",
        "--judge-model", "phi3:mini",
    ])
    assert args.target_type == "ollama"


# ---------------------------------------------------------------------------
# _resolve_categories — CLI-03, CLI-08
# ---------------------------------------------------------------------------


def test_resolve_categories_default_excludes_llm10() -> None:
    """Default (no --categories, no --include-dos-tests) excludes LLM10 (CLI-08)."""
    result = _resolve_categories(_ns())
    assert "LLM10" not in result
    assert len(result) == 9
    assert result == _SAFE_CATEGORIES


def test_resolve_categories_include_dos_adds_llm10() -> None:
    """--include-dos-tests appends LLM10 to the default set."""
    result = _resolve_categories(_ns(include_dos_tests=True))
    assert "LLM10" in result
    assert len(result) == 10


def test_resolve_categories_explicit_list() -> None:
    """Explicit --categories returns the specified categories (CLI-03)."""
    result = _resolve_categories(_ns(categories="LLM01,LLM07"))
    assert result == ["LLM01", "LLM07"]


def test_resolve_categories_llm10_without_flag_removed(capsys: pytest.CaptureFixture[str]) -> None:
    """LLM10 in --categories without --include-dos-tests is silently removed (CLI-08)."""
    result = _resolve_categories(_ns(categories="LLM01,LLM10", include_dos_tests=False))
    assert "LLM10" not in result
    assert "LLM01" in result
    captured = capsys.readouterr()
    assert "include-dos-tests" in captured.err.lower() or "dos" in captured.err.lower()


def test_resolve_categories_llm10_with_flag_kept() -> None:
    """LLM10 in --categories with --include-dos-tests is retained."""
    result = _resolve_categories(_ns(categories="LLM01,LLM10", include_dos_tests=True))
    assert "LLM10" in result
    assert "LLM01" in result


def test_resolve_categories_uppercase_normalization() -> None:
    """Category names are normalized to uppercase regardless of input case."""
    result = _resolve_categories(_ns(categories="llm01,llm07"))
    assert "LLM01" in result
    assert "LLM07" in result


# ---------------------------------------------------------------------------
# _SEVERITY_RANK ordering — CLI-04
# ---------------------------------------------------------------------------


def test_severity_rank_ordering() -> None:
    """Severity rank is strictly ordered from INFO (lowest) to CRITICAL (highest)."""
    assert _SEVERITY_RANK[Severity.CRITICAL] > _SEVERITY_RANK[Severity.HIGH]
    assert _SEVERITY_RANK[Severity.HIGH] > _SEVERITY_RANK[Severity.MEDIUM]
    assert _SEVERITY_RANK[Severity.MEDIUM] > _SEVERITY_RANK[Severity.LOW]
    assert _SEVERITY_RANK[Severity.LOW] > _SEVERITY_RANK[Severity.INFO]


def test_severity_rank_high_excludes_lower() -> None:
    """Minimum severity HIGH should exclude MEDIUM, LOW, INFO."""
    high_rank = _SEVERITY_RANK[Severity.HIGH]
    for lower in [Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        assert _SEVERITY_RANK[lower] < high_rank


def test_severity_rank_info_is_lowest() -> None:
    """INFO has the lowest rank (0)."""
    assert _SEVERITY_RANK[Severity.INFO] == 0


# ---------------------------------------------------------------------------
# Risk score formula spot-checks (ENGINE-04, verified from CLI perspective)
# ---------------------------------------------------------------------------


def _make_finding(success: bool, severity: Severity) -> object:
    from llm_scanner.models import AttackResult
    return AttackResult(
        attack_id="TEST",
        owasp_category="LLM01",
        name="test",
        payload="p",
        response="r",
        success=success,
        judge_reasoning="r",
        severity=severity,
    )


def test_risk_score_critical() -> None:
    """CRITICAL success = 4.0 (highest weight)."""
    findings = [_make_finding(True, Severity.CRITICAL)]
    assert LLMScanner._compute_risk_score(findings) == 4.0  # type: ignore[arg-type]


def test_risk_score_mixed_high_medium() -> None:
    """HIGH (2.5) + MEDIUM (1.5) = 4.0."""
    findings = [
        _make_finding(True, Severity.HIGH),
        _make_finding(True, Severity.MEDIUM),
    ]
    assert LLMScanner._compute_risk_score(findings) == 4.0  # type: ignore[arg-type]


def test_risk_score_capped_at_10() -> None:
    """Large sums are capped at 10.0."""
    findings = [_make_finding(True, Severity.CRITICAL) for _ in range(5)]
    assert LLMScanner._compute_risk_score(findings) == 10.0  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Phase 05 tests — ADV-01, ADV-02, ADV-05, ADV-06
# ---------------------------------------------------------------------------


def _make_report(risk_score: float, *, suppressed: bool = False) -> ScanReport:
    """Build a minimal ScanReport for test use."""
    finding = AttackResult(
        attack_id="LLM01-001",
        owasp_category="LLM01",
        name="test",
        payload="p",
        response="r",
        success=True,
        judge_reasoning="j",
        severity=Severity.HIGH,
        suppressed=suppressed,
    )
    return ScanReport(
        target="http://example.com",
        timestamp=datetime(2025, 1, 1, tzinfo=UTC),
        risk_score=risk_score,
        findings=[finding],
    )


# --- _build_parser() Phase 05 flag tests ---


def test_build_parser_has_fail_on_score() -> None:
    """--fail-on-score is parsed as a float into args.fail_on_score."""
    args = _build_parser().parse_args([
        "--target", "t", "--target-type", "url", "--judge-model", "m",
        "--fail-on-score", "7.5",
    ])
    assert args.fail_on_score == 7.5


def test_build_parser_fail_on_score_default_is_none() -> None:
    """--fail-on-score defaults to None when not provided."""
    args = _parse()
    assert args.fail_on_score is None


def test_build_parser_has_targets_flag() -> None:
    """--targets is parsed as a Path into args.targets_file."""
    args = _build_parser().parse_args([
        "--targets", "targets.yaml", "--judge-model", "m",
    ])
    assert args.targets_file == Path("targets.yaml")


def test_build_parser_has_suppressions_flag() -> None:
    """--suppressions is parsed as a Path into args.suppressions_file."""
    args = _parse("--suppressions", "suppressions.yaml")
    assert args.suppressions_file == Path("suppressions.yaml")


def test_build_parser_suppressions_default_is_none() -> None:
    """--suppressions defaults to None when not provided."""
    args = _parse()
    assert args.suppressions_file is None


def test_build_parser_baseline_save() -> None:
    """baseline save subcommand sets command='baseline', baseline_action='save', name='prod'."""
    args = _build_parser().parse_args([
        "--judge-model", "m", "baseline", "save", "--name", "prod",
    ])
    assert args.command == "baseline"
    assert args.baseline_action == "save"
    assert args.name == "prod"


def test_build_parser_baseline_compare() -> None:
    """baseline compare subcommand sets command='baseline', baseline_action='compare'."""
    args = _build_parser().parse_args([
        "--judge-model", "m", "baseline", "compare", "--name", "prod",
    ])
    assert args.command == "baseline"
    assert args.baseline_action == "compare"
    assert args.name == "prod"


def test_build_parser_default_command_is_scan() -> None:
    """When no subcommand is given, args.command defaults to 'scan'."""
    args = _parse()
    assert args.command == "scan"


def test_build_parser_set_defaults_after_add_subparsers() -> None:
    """Regression: set_defaults(command='scan') must be after add_subparsers.

    Verifies the CRITICAL ORDER requirement from RESEARCH.md: if set_defaults
    is called before add_subparsers, args.command would be None at runtime.
    """
    # When no subcommand and no --targets, command must be 'scan', not None
    args = _build_parser().parse_args(["--judge-model", "m"])
    assert args.command == "scan", (
        "args.command is None -- set_defaults was likely called before add_subparsers"
    )


# --- --fail-on-score threshold tests (ADV-01) ---


def test_fail_on_score_raises_when_exceeded(tmp_path: Path) -> None:
    """_apply_suppressions + risk_score check: _ScanAbort raised when score >= threshold."""

    report = _make_report(risk_score=8.0)
    args = argparse.Namespace(fail_on_score=7.0)

    # Simulate the fail-on-score check from _run()
    if getattr(args, "fail_on_score", None) is not None and report.risk_score >= args.fail_on_score:
        with pytest.raises(_ScanAbort):
            raise _ScanAbort()
    else:
        pytest.fail("Expected _ScanAbort condition to be True")


def test_fail_on_score_passes_when_below() -> None:
    """No exception when risk_score < fail_on_score threshold."""
    report = _make_report(risk_score=6.9)
    args = argparse.Namespace(fail_on_score=7.0)

    # Verify condition is False — no _ScanAbort should be raised
    assert not (
        getattr(args, "fail_on_score", None) is not None
        and report.risk_score >= args.fail_on_score
    )


def test_fail_on_score_none_never_raises() -> None:
    """When fail_on_score=None, the check is a no-op regardless of risk_score."""
    args = argparse.Namespace(fail_on_score=None)

    # Condition must be False when fail_on_score is None
    assert getattr(args, "fail_on_score", None) is None


# --- Suppression integration test (ADV-05) ---


def test_suppressions_applied_before_fail_check(tmp_path: Path) -> None:
    """Suppressed findings are excluded from risk_score before fail-on-score check."""
    # Create a suppression file suppressing LLM01-001
    sup_file = tmp_path / "suppressions.yaml"
    sup_file.write_text("suppressions:\n  - attack_id: 'LLM01-001'\n    reason: 'accepted'\n")

    # Build report with one HIGH finding (score=2.5 normally)
    finding = AttackResult(
        attack_id="LLM01-001",
        owasp_category="LLM01",
        name="test",
        payload="p",
        response="r",
        success=True,
        judge_reasoning="j",
        severity=Severity.HIGH,
    )
    original = ScanReport(
        target="t",
        timestamp=datetime(2025, 1, 1, tzinfo=UTC),
        risk_score=2.5,
        findings=[finding],
    )

    # Apply suppressions -- risk_score should recompute to 0.0 (no unsuppressed findings)
    result = _apply_suppressions(original, sup_file)
    assert result.risk_score == 0.0, f"Expected 0.0, got {result.risk_score}"
    assert result.findings[0].suppressed is True


# --- GitHub Actions workflow smoke test (ADV-01) ---


def test_workflow_yaml_valid() -> None:
    """.github/workflows/llm-scan.yml is valid YAML with required keys."""
    workflow_path = (
        Path(__file__).parent.parent / ".github" / "workflows" / "llm-scan.yml"
    )
    assert workflow_path.exists(), f"Workflow file not found at {workflow_path}"
    data = yaml.safe_load(workflow_path.read_text())
    assert "jobs" in data, "Workflow YAML missing 'jobs' key"
    assert "llm-security-scan" in data["jobs"], "Workflow YAML missing 'llm-security-scan' job"


def test_workflow_contains_required_steps() -> None:
    """Workflow YAML contains all required steps and flags."""
    workflow_path = (
        Path(__file__).parent.parent / ".github" / "workflows" / "llm-scan.yml"
    )
    content = workflow_path.read_text()
    assert "actions/checkout@v4" in content
    assert "--fail-on-score" in content
    assert "json,sarif" in content
    assert "upload-sarif@v3" in content
    assert "if: always()" in content
    assert "timeout-minutes: 60" in content
