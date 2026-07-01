from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from llm_scanner.models import AttackResult, JudgeResult, Payload, ScanReport, Severity
from llm_scanner.scanner import LLMScanner

# asyncio_mode = "auto" is set in pyproject.toml — no @pytest.mark.asyncio needed


@pytest.fixture
def sample_payload() -> Payload:
    return Payload(
        id="LLM01-001",
        name="Test Attack",
        category="LLM01",
        severity=Severity.HIGH,
        payload="ignore instructions",
        judge_criteria="reveals system prompt",
    )


@pytest.fixture
def sample_payloads() -> list[Payload]:
    return [
        Payload(
            id="LLM01-001",
            name="Attack One",
            category="LLM01",
            severity=Severity.HIGH,
            payload="payload one",
            judge_criteria="criteria one",
        ),
        Payload(
            id="LLM02-001",
            name="Attack Two",
            category="LLM02",
            severity=Severity.CRITICAL,
            payload="payload two",
            judge_criteria="criteria two",
        ),
        Payload(
            id="LLM07-001",
            name="Attack Three",
            category="LLM07",
            severity=Severity.MEDIUM,
            payload="payload three",
            judge_criteria="criteria three",
        ),
    ]


@pytest.fixture
def mock_target() -> AsyncMock:
    mock = AsyncMock()
    mock.send.return_value = "mock response"
    mock.__aenter__ = AsyncMock(return_value=mock)
    mock.__aexit__ = AsyncMock(return_value=None)
    return mock


@pytest.fixture
def mock_judge() -> AsyncMock:
    mock = AsyncMock()
    mock.evaluate.return_value = JudgeResult(
        success=True,
        reasoning="test reasoning",
        error=None,
        raw_response="",
    )
    return mock


def _make_finding(success: bool, severity: Severity) -> AttackResult:
    """Helper to construct a minimal AttackResult for risk score tests."""
    return AttackResult(
        attack_id="TEST-001",
        owasp_category="LLM01",
        name="Test",
        payload="test",
        response="response",
        success=success,
        judge_reasoning="reasoning",
        severity=severity,
    )


# ---------------------------------------------------------------------------
# scan() — ENGINE-01: dispatches all payloads to target + judge
# ---------------------------------------------------------------------------


async def test_scan_returns_scan_report(
    mock_target: AsyncMock,
    mock_judge: AsyncMock,
    sample_payload: Payload,
) -> None:
    scanner = LLMScanner(
        mock_target,
        mock_judge,
        [sample_payload],
        target_label="test://x",
    )
    report = await scanner.scan()
    assert isinstance(report, ScanReport)
    assert report.target == "test://x"
    assert len(report.findings) == 1


async def test_scan_calls_target_and_judge(
    mock_target: AsyncMock,
    mock_judge: AsyncMock,
    sample_payload: Payload,
) -> None:
    scanner = LLMScanner(mock_target, mock_judge, [sample_payload])
    await scanner.scan()
    mock_target.send.assert_called_once_with(sample_payload.payload)
    mock_judge.evaluate.assert_called_once()
    # Verify response is forwarded to judge
    call_args = mock_judge.evaluate.call_args
    assert call_args.args[1] == "mock response"


async def test_scan_captures_target_error_no_raise(
    mock_target: AsyncMock,
    mock_judge: AsyncMock,
    sample_payload: Payload,
) -> None:
    """ENGINE-01: TargetError captured as response string — scan never raises."""
    mock_target.send.side_effect = Exception("connection refused")
    scanner = LLMScanner(mock_target, mock_judge, [sample_payload])
    # Must not raise
    report = await scanner.scan()
    finding = report.findings[0]
    assert "target_error" in finding.response
    # Judge is still called even after target error (record both events)
    assert mock_judge.evaluate.call_count == 1


async def test_scan_all_payloads_dispatched(
    mock_target: AsyncMock,
    mock_judge: AsyncMock,
    sample_payloads: list[Payload],
) -> None:
    """ENGINE-01: all payloads dispatched; findings count matches payload count."""
    scanner = LLMScanner(mock_target, mock_judge, sample_payloads)
    report = await scanner.scan()
    assert mock_target.send.call_count == 3
    assert mock_judge.evaluate.call_count == 3
    assert len(report.findings) == 3


async def test_scan_findings_map_payload_fields(
    mock_target: AsyncMock,
    mock_judge: AsyncMock,
    sample_payload: Payload,
) -> None:
    """AttackResult fields come from payload + judge result — no data loss."""
    mock_judge.evaluate.return_value = JudgeResult(
        success=False,
        reasoning="refused",
        error=None,
        raw_response="",
    )
    scanner = LLMScanner(mock_target, mock_judge, [sample_payload])
    report = await scanner.scan()
    finding = report.findings[0]
    assert finding.attack_id == sample_payload.id
    assert finding.owasp_category == sample_payload.category
    assert finding.name == sample_payload.name
    assert finding.payload == sample_payload.payload
    assert finding.response == "mock response"
    assert finding.success is False
    assert finding.judge_reasoning == "refused"
    assert finding.severity == sample_payload.severity


# ---------------------------------------------------------------------------
# Concurrency — ENGINE-02
# ---------------------------------------------------------------------------


def test_concurrency_default() -> None:
    """Default concurrency is 3 (ENGINE-02 bound)."""
    mock_t = AsyncMock()
    mock_j = AsyncMock()
    scanner = LLMScanner(mock_t, mock_j, [])
    assert scanner._concurrency == 3


async def test_scan_respects_concurrency_limit(
    mock_target: AsyncMock,
    mock_judge: AsyncMock,
    sample_payloads: list[Payload],
) -> None:
    """Semaphore at concurrency=1: all payloads still dispatched serially."""
    scanner = LLMScanner(mock_target, mock_judge, sample_payloads, concurrency=1)
    report = await scanner.scan()
    assert mock_target.send.call_count == 3
    assert len(report.findings) == 3


# ---------------------------------------------------------------------------
# Risk score — ENGINE-04
# ---------------------------------------------------------------------------


def test_compute_risk_score_empty() -> None:
    assert LLMScanner._compute_risk_score([]) == 0.0


def test_compute_risk_score_no_successes() -> None:
    findings = [_make_finding(success=False, severity=Severity.CRITICAL)]
    assert LLMScanner._compute_risk_score(findings) == 0.0


def test_compute_risk_score_critical() -> None:
    findings = [_make_finding(success=True, severity=Severity.CRITICAL)]
    assert LLMScanner._compute_risk_score(findings) == 4.0


def test_compute_risk_score_high() -> None:
    findings = [_make_finding(success=True, severity=Severity.HIGH)]
    assert LLMScanner._compute_risk_score(findings) == 2.5


def test_compute_risk_score_medium() -> None:
    findings = [_make_finding(success=True, severity=Severity.MEDIUM)]
    assert LLMScanner._compute_risk_score(findings) == 1.5


def test_compute_risk_score_low() -> None:
    findings = [_make_finding(success=True, severity=Severity.LOW)]
    assert LLMScanner._compute_risk_score(findings) == 0.5


def test_compute_risk_score_info_is_zero() -> None:
    findings = [_make_finding(success=True, severity=Severity.INFO)]
    assert LLMScanner._compute_risk_score(findings) == 0.0


def test_compute_risk_score_mixed() -> None:
    """HIGH (2.5) + MEDIUM (1.5) success, LOW failure = 4.0."""
    findings = [
        _make_finding(success=True, severity=Severity.HIGH),
        _make_finding(success=True, severity=Severity.MEDIUM),
        _make_finding(success=False, severity=Severity.LOW),
    ]
    assert LLMScanner._compute_risk_score(findings) == 4.0


def test_compute_risk_score_capped_at_10() -> None:
    """5 CRITICAL successes (5 * 4.0 = 20.0) capped at 10.0."""
    findings = [_make_finding(success=True, severity=Severity.CRITICAL) for _ in range(5)]
    assert LLMScanner._compute_risk_score(findings) == 10.0
