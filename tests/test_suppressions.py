from __future__ import annotations

from pathlib import Path

import yaml

from llm_scanner.models import AttackResult, Severity
from llm_scanner.scanner import LLMScanner
from llm_scanner.suppressions import SuppressionLoader

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    attack_id: str,
    success: bool = True,
    severity: Severity = Severity.HIGH,
) -> AttackResult:
    return AttackResult(
        attack_id=attack_id,
        owasp_category="LLM01",
        name="Test",
        payload="p",
        response="r",
        success=success,
        judge_reasoning="ok",
        severity=severity,
    )


def _write_suppressions(tmp_path: Path, entries: list[dict]) -> Path:
    """Write a suppressions.yaml file and return its path."""
    path = tmp_path / "suppressions.yaml"
    path.write_text(
        yaml.dump({"suppressions": entries}),
        encoding="utf-8",
    )
    return path


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_suppression_file_missing(tmp_path: Path) -> None:
    """load() returns [] without raising when the file does not exist."""
    loader = SuppressionLoader(tmp_path / "nonexistent.yaml")
    assert loader.load() == []


def test_suppression_applied(tmp_path: Path) -> None:
    """apply() marks a finding suppressed when its attack_id matches exactly."""
    path = _write_suppressions(
        tmp_path,
        [{"attack_id": "LLM01-001", "reason": "test reason"}],
    )
    findings = [_make_finding("LLM01-001")]
    loader = SuppressionLoader(path)
    result = loader.apply(findings)
    assert result[0].suppressed is True
    assert result[0].suppression_reason == "test reason"


def test_suppression_not_applied_for_non_match(tmp_path: Path) -> None:
    """apply() leaves findings with non-matching attack_ids untouched."""
    path = _write_suppressions(
        tmp_path,
        [{"attack_id": "LLM01-001", "reason": "irrelevant"}],
    )
    findings = [_make_finding("LLM02-001")]
    loader = SuppressionLoader(path)
    result = loader.apply(findings)
    assert result[0].suppressed is False
    assert result[0].suppression_reason == ""


def test_suppression_glob_pattern(tmp_path: Path) -> None:
    """Glob pattern LLM01-* suppresses all LLM01-xxx findings only."""
    path = _write_suppressions(
        tmp_path,
        [{"attack_id": "LLM01-*", "reason": "glob suppression"}],
    )
    f1 = _make_finding("LLM01-001")
    f2 = _make_finding("LLM01-002")
    f3 = _make_finding("LLM02-001")
    loader = SuppressionLoader(path)
    loader.apply([f1, f2, f3])
    assert f1.suppressed is True
    assert f2.suppressed is True
    assert f3.suppressed is False


def test_risk_score_excludes_suppressed() -> None:
    """_compute_risk_score produces a lower score when suppressed findings are excluded."""
    f1 = _make_finding("LLM01-001", success=True, severity=Severity.HIGH)
    f2 = _make_finding("LLM02-001", success=True, severity=Severity.HIGH)
    f2.suppressed = True

    score_all = LLMScanner._compute_risk_score([f1, f2])
    score_active = LLMScanner._compute_risk_score(
        [f for f in [f1, f2] if not f.suppressed]
    )
    assert score_active < score_all


def test_suppression_extra_yaml_fields_ignored(tmp_path: Path) -> None:
    """Suppression model accepts YAML entries with extra metadata keys."""
    path = _write_suppressions(
        tmp_path,
        [
            {
                "attack_id": "LLM01-001",
                "reason": "accepted",
                "ticket": "SEC-123",
                "owner": "security-team",
            }
        ],
    )
    loader = SuppressionLoader(path)
    suppressions = loader.load()
    assert len(suppressions) == 1
    assert suppressions[0].attack_id == "LLM01-001"


def test_suppression_no_findings(tmp_path: Path) -> None:
    """apply([]) returns [] without error."""
    path = _write_suppressions(
        tmp_path,
        [{"attack_id": "LLM01-*", "reason": "anything"}],
    )
    loader = SuppressionLoader(path)
    result = loader.apply([])
    assert result == []
