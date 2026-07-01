from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from llm_scanner.baselines import BaselineManager
from llm_scanner.models import AttackResult, ScanReport, Severity

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_scan_report(
    target: str = "http://test",
    risk_score: float = 2.5,
    findings: list[AttackResult] | None = None,
) -> ScanReport:
    """Construct a minimal valid ScanReport for testing."""
    return ScanReport(
        target=target,
        timestamp=datetime(2025, 1, 1, 12, 0, 0, tzinfo=UTC),
        risk_score=risk_score,
        findings=findings if findings is not None else [],
    )


def write_report_json(directory: Path, report: ScanReport) -> None:
    """Create *directory* and write report.json into it."""
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "report.json").write_text(
        report.model_dump_json(indent=2), encoding="utf-8"
    )


# ---------------------------------------------------------------------------
# save() tests
# ---------------------------------------------------------------------------


def test_baseline_save_creates_file(tmp_path: Path) -> None:
    """save() creates baselines/{name}.json and returns its path."""
    report = make_scan_report()
    write_report_json(tmp_path / "scan1", report)

    result = BaselineManager(tmp_path).save("prod")

    assert result == tmp_path / "baselines" / "prod.json"
    assert result.exists()


def test_baseline_save_file_exists(tmp_path: Path) -> None:
    """The saved baseline file contains valid JSON parseable as a ScanReport."""
    report = make_scan_report(target="http://example.com", risk_score=5.0)
    write_report_json(tmp_path / "scan1", report)

    BaselineManager(tmp_path).save("prod")
    dest = tmp_path / "baselines" / "prod.json"

    loaded = ScanReport.model_validate_json(dest.read_text())
    assert loaded.target == "http://example.com"
    assert loaded.risk_score == 5.0


def test_baseline_load_roundtrip(tmp_path: Path) -> None:
    """save() then load() returns a ScanReport matching the original."""
    report = make_scan_report(target="http://roundtrip", risk_score=3.7)
    write_report_json(tmp_path / "scan1", report)

    mgr = BaselineManager(tmp_path)
    mgr.save("test")
    loaded = mgr.load("test")

    assert loaded.target == "http://roundtrip"
    assert loaded.risk_score == 3.7


def test_baseline_load_missing(tmp_path: Path) -> None:
    """load() raises FileNotFoundError for a name that was never saved."""
    with pytest.raises(FileNotFoundError, match="nonexistent"):
        BaselineManager(tmp_path).load("nonexistent")


def test_baseline_save_no_reports(tmp_path: Path) -> None:
    """save() raises FileNotFoundError when no report.json exists under output_dir."""
    with pytest.raises(FileNotFoundError, match=r"No report\.json"):
        BaselineManager(tmp_path).save("x")


# ---------------------------------------------------------------------------
# Name validation tests
# ---------------------------------------------------------------------------


def test_baseline_name_validation_rejects_traversal(tmp_path: Path) -> None:
    """save() raises ValueError for a name containing path traversal characters."""
    with pytest.raises(ValueError, match="Invalid baseline name"):
        BaselineManager(tmp_path).save("../../etc")


def test_baseline_name_validation_rejects_slash(tmp_path: Path) -> None:
    """save() raises ValueError for a name containing a forward slash."""
    with pytest.raises(ValueError, match="Invalid baseline name"):
        BaselineManager(tmp_path).save("prod/v1")


# ---------------------------------------------------------------------------
# diff_findings() tests
# ---------------------------------------------------------------------------


def _make_finding(attack_id: str, success: bool, severity: Severity = Severity.HIGH) -> AttackResult:
    return AttackResult(
        attack_id=attack_id,
        owasp_category="LLM01",
        name=f"Test {attack_id}",
        payload="test payload",
        response="test response",
        success=success,
        judge_reasoning="test reasoning",
        severity=severity,
    )


def test_baseline_diff_new_finding(tmp_path: Path) -> None:
    """diff_findings() returns findings success=True in current not in baseline."""
    baseline = make_scan_report(
        findings=[_make_finding("LLM01-001", success=True)]
    )
    current = make_scan_report(
        findings=[
            _make_finding("LLM01-001", success=True),
            _make_finding("LLM01-002", success=True),  # new vulnerability
        ]
    )

    diff = BaselineManager.diff_findings(baseline, current)

    assert len(diff) == 1
    assert diff[0].attack_id == "LLM01-002"


def test_baseline_diff_no_regression(tmp_path: Path) -> None:
    """diff_findings() returns empty list when all current successes were in baseline."""
    baseline = make_scan_report(
        findings=[
            _make_finding("LLM01-001", success=True),
            _make_finding("LLM01-002", success=True),
        ]
    )
    current = make_scan_report(
        findings=[
            _make_finding("LLM01-001", success=True),
            _make_finding("LLM01-002", success=True),
        ]
    )

    diff = BaselineManager.diff_findings(baseline, current)

    assert diff == []


def test_baseline_diff_fixed_finding(tmp_path: Path) -> None:
    """Findings success=True in baseline but success=False in current do not appear in diff."""
    baseline = make_scan_report(
        findings=[_make_finding("LLM01-001", success=True)]
    )
    current = make_scan_report(
        findings=[
            _make_finding("LLM01-001", success=False),  # was vulnerable, now fixed
            _make_finding("LLM01-002", success=False),  # not vulnerable
        ]
    )

    diff = BaselineManager.diff_findings(baseline, current)

    assert diff == []
