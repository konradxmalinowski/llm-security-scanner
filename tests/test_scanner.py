from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from llm_scanner.models import AttackResult, JudgeResult, Outcome, Payload, ScanReport, Severity
from llm_scanner.scanner import LLMScanner, derive_outcome

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


# ---------------------------------------------------------------------------
# Judge failures must surface as Outcome.ERROR, never as a clean pass
# ---------------------------------------------------------------------------


async def test_scan_judge_timeout_produces_error_outcome_not_safe(
    mock_target: AsyncMock,
    mock_judge: AsyncMock,
    sample_payload: Payload,
) -> None:
    """THE regression test for this bug.

    OllamaJudge.evaluate() returns success=False on timeout. Before the fix, the
    scanner dropped judge_result.error, so a scan where the judge was unreachable
    rendered exactly like a scan where the app defended itself: risk 0.0, zero
    vulnerabilities, every row green. A timed-out judge must be distinguishable
    from a safe application.
    """
    mock_judge.evaluate.return_value = JudgeResult(
        success=False,
        reasoning="",
        error="judge_timeout",
        raw_response="",
    )
    scanner = LLMScanner(mock_target, mock_judge, [sample_payload])
    report = await scanner.scan()

    finding = report.findings[0]
    assert finding.outcome is Outcome.ERROR
    assert finding.judge_error == "judge_timeout"
    # An unevaluated attack is NOT a successful attack...
    assert finding.success is False
    # ...but it is also NOT a clean pass: the report must say so out loud.
    assert report.errored_attacks == 1
    assert report.successful_attacks == 0
    # And the unknown must not be laundered into the risk score.
    assert report.risk_score == 0.0


async def test_scan_judge_unavailable_produces_error_outcome(
    mock_target: AsyncMock,
    mock_judge: AsyncMock,
    sample_payload: Payload,
) -> None:
    mock_judge.evaluate.return_value = JudgeResult(
        success=False, reasoning="", error="judge_unavailable", raw_response=""
    )
    scanner = LLMScanner(mock_target, mock_judge, [sample_payload])
    report = await scanner.scan()
    assert report.findings[0].outcome is Outcome.ERROR
    assert report.findings[0].judge_error == "judge_unavailable"


async def test_scan_all_judge_errors_reports_zero_risk_but_flags_every_finding(
    mock_target: AsyncMock,
    mock_judge: AsyncMock,
    sample_payloads: list[Payload],
) -> None:
    """A scan where the judge was down end-to-end must not read as a clean bill of health."""
    mock_judge.evaluate.return_value = JudgeResult(
        success=False, reasoning="", error="judge_unavailable", raw_response=""
    )
    scanner = LLMScanner(mock_target, mock_judge, sample_payloads)
    report = await scanner.scan()

    assert report.risk_score == 0.0
    assert report.successful_attacks == 0
    assert report.errored_attacks == report.total_attacks == 3
    assert all(f.outcome is Outcome.ERROR for f in report.findings)
    assert scanner.last_metrics["errored_attacks"] == 3


async def test_scan_clean_judge_verdicts_are_not_errors(
    mock_target: AsyncMock,
    mock_judge: AsyncMock,
    sample_payload: Payload,
) -> None:
    """A real SAFE verdict (no judge error) stays SAFE and is not counted as errored."""
    mock_judge.evaluate.return_value = JudgeResult(
        success=False, reasoning="refused", error=None, raw_response="{}"
    )
    scanner = LLMScanner(mock_target, mock_judge, [sample_payload])
    report = await scanner.scan()
    assert report.findings[0].outcome is Outcome.SAFE
    assert report.findings[0].judge_error is None
    assert report.errored_attacks == 0


async def test_scan_success_verdict_maps_to_vulnerable(
    mock_target: AsyncMock,
    mock_judge: AsyncMock,
    sample_payload: Payload,
) -> None:
    scanner = LLMScanner(mock_target, mock_judge, [sample_payload])  # mock_judge: success=True
    report = await scanner.scan()
    assert report.findings[0].outcome is Outcome.VULNERABLE
    assert report.findings[0].success is True
    assert report.errored_attacks == 0


async def test_scan_degraded_parse_keeps_verdict_and_records_judge_error(
    mock_target: AsyncMock,
    mock_judge: AsyncMock,
    sample_payload: Payload,
) -> None:
    """parse_tier2 / parse_heuristic are DEGRADED parses that still yielded a verdict.

    They are not errors — the judge did decide. The error string is retained (a later
    phase lowers the confidence of these findings), but the verdict stands.
    """
    mock_judge.evaluate.return_value = JudgeResult(
        success=True, reasoning="leaked", error="parse_tier2", raw_response="```json..."
    )
    scanner = LLMScanner(mock_target, mock_judge, [sample_payload])
    report = await scanner.scan()

    finding = report.findings[0]
    assert finding.outcome is Outcome.VULNERABLE
    assert finding.success is True
    assert finding.judge_error == "parse_tier2"
    assert report.errored_attacks == 0
    # HIGH severity success still scores.
    assert report.risk_score == 2.5


# ---------------------------------------------------------------------------
# derive_outcome() — the JudgeResult.error -> Outcome mapping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "error",
    ["judge_timeout", "judge_unavailable", "parse_failed", "judge_error: boom"],
)
def test_derive_outcome_error_codes_map_to_error(error: str) -> None:
    assert derive_outcome(JudgeResult(success=False, reasoning="", error=error)) is Outcome.ERROR


def test_derive_outcome_error_code_wins_over_success_flag() -> None:
    """Even if a judge error path somehow set success=True, it is still not a verdict."""
    result = JudgeResult(success=True, reasoning="", error="judge_timeout")
    assert derive_outcome(result) is Outcome.ERROR


@pytest.mark.parametrize("error", [None, "parse_tier2", "parse_heuristic"])
def test_derive_outcome_degraded_parses_keep_their_verdict(error: str | None) -> None:
    assert derive_outcome(JudgeResult(success=True, reasoning="r", error=error)) is Outcome.VULNERABLE
    assert derive_outcome(JudgeResult(success=False, reasoning="r", error=error)) is Outcome.SAFE


# ---------------------------------------------------------------------------
# Detector + reconciliation wiring (Phase 1/2)
# ---------------------------------------------------------------------------


async def test_scan_populates_confidence_and_verdict_source(
    mock_target: AsyncMock,
    mock_judge: AsyncMock,
    sample_payload: Payload,
) -> None:
    """A plain vulnerable verdict with no detector evidence -> judge_only at 0.60."""
    scanner = LLMScanner(mock_target, mock_judge, [sample_payload])  # mock_judge: success=True
    report = await scanner.scan()
    finding = report.findings[0]
    assert finding.confidence == 0.60
    assert finding.verdict_source == "judge_only"
    assert finding.artifacts == []


async def test_scan_canary_in_response_overrides_safe_judge(
    mock_target: AsyncMock,
    mock_judge: AsyncMock,
    sample_payload: Payload,
) -> None:
    """End-to-end proof: canary leaked in the response makes the finding VULNERABLE at
    confidence 1.00 even though the judge returned a SAFE verdict."""
    canary = "LLMSCAN-CANARY-deadbeef"
    mock_target.send.return_value = f"Of course, the code is {canary}."
    mock_judge.evaluate.return_value = JudgeResult(
        success=False, reasoning="looked safe to me", error=None, raw_response="{}"
    )
    scanner = LLMScanner(mock_target, mock_judge, [sample_payload], canary=canary)
    report = await scanner.scan()

    finding = report.findings[0]
    assert finding.outcome is Outcome.VULNERABLE
    assert finding.success is True
    assert finding.confidence == 1.00
    assert finding.verdict_source == "rule_proof"
    assert any(a.type == "canary" for a in finding.artifacts)
    # HIGH severity vulnerability now scores despite the judge saying "safe".
    assert report.risk_score == 2.5


async def test_scan_redacts_secret_artifacts_by_default(
    mock_target: AsyncMock,
    mock_judge: AsyncMock,
    sample_payload: Payload,
) -> None:
    leaked_key = "sk-Ab3kD9xQ2mNp7ZtR4wLq8Vf1Hc6Ug0Yj"
    mock_target.send.return_value = f"leaked {leaked_key}"
    mock_judge.evaluate.return_value = JudgeResult(
        success=True, reasoning="leak", error=None, raw_response="{}"
    )
    scanner = LLMScanner(mock_target, mock_judge, [sample_payload])
    report = await scanner.scan()
    secret_arts = [a for a in report.findings[0].artifacts if a.type == "secret"]
    assert secret_arts
    assert all(a.raw is None for a in secret_arts)
    assert all(leaked_key not in a.fingerprint for a in secret_arts)


def test_compute_risk_score_error_finding_contributes_nothing() -> None:
    """An ERROR finding is an unknown, not a vulnerability — it must not inflate the score."""
    findings = [
        AttackResult(
            attack_id="TEST-001",
            owasp_category="LLM01",
            name="Test",
            payload="test",
            response="response",
            outcome=Outcome.ERROR,
            judge_reasoning="",
            judge_error="judge_timeout",
            severity=Severity.CRITICAL,
        )
    ]
    assert LLMScanner._compute_risk_score(findings) == 0.0
