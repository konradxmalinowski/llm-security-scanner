from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)

from llm_scanner.detectors import run_detectors
from llm_scanner.judge.reconcile import derive_outcome, reconcile
from llm_scanner.models import AttackResult, Outcome, Payload, ScanReport, Severity
from llm_scanner.observability import get_logger

if TYPE_CHECKING:
    from llm_scanner.judge import OllamaJudge
    from llm_scanner.targets.base import AbstractTarget

_logger = get_logger()

# derive_outcome and reconcile now live in judge/reconcile.py (the reconciliation layer
# owns the JudgeResult.error -> Outcome mapping and the judge/detector combination).
# They are re-exported here so existing callers and tests that import derive_outcome from
# llm_scanner.scanner keep working.
__all__ = ["LLMScanner", "derive_outcome", "reconcile"]


# CVSS-inspired risk weights per OWASP LLM severity level (ENGINE-04)
_SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.CRITICAL: 4.0,
    Severity.HIGH: 2.5,
    Severity.MEDIUM: 1.5,
    Severity.LOW: 0.5,
    Severity.INFO: 0.0,
}
_MAX_RISK_SCORE: float = 10.0


class LLMScanner:
    """Bounded-concurrency scan engine.

    Drives the attack loop: for each payload, sends it to the target,
    evaluates the response with the judge, and aggregates results into
    a ScanReport with a computed risk score.

    Satisfies ENGINE-01 through ENGINE-04.
    """

    def __init__(
        self,
        target: AbstractTarget,
        judge: OllamaJudge,
        payloads: list[Payload],
        target_label: str = "unknown",
        concurrency: int = 3,
        scan_id: str = "",
        canary: str | None = None,
        system_prompt: str | None = None,
        include_raw_artifacts: bool = False,
    ) -> None:
        self._target = target
        self._judge = judge
        self._payloads = payloads
        self._target_label = target_label
        self._concurrency = concurrency
        self._scan_id = scan_id
        # Deterministic-detector inputs (Phase 1/2). canary: unique token expected in
        # responses if the system prompt leaked. system_prompt: the operator-supplied real
        # prompt, used only for shingle-overlap detection (never injected here).
        self._canary = canary
        self._system_prompt = system_prompt
        self._include_raw_artifacts = include_raw_artifacts
        # Populated at the end of scan() -- last scan's metrics summary, read by
        # cli.py to write metrics.json without adding fields to ScanReport itself.
        self.last_metrics: dict[str, float | int] = {}

    async def scan(self) -> ScanReport:
        """Run all payloads against target and return a ScanReport.

        ENGINE-01: iterates all payloads, dispatches to target + judge.
        ENGINE-02: asyncio.Semaphore limits concurrent attacks to self._concurrency.
        ENGINE-03: Rich progress bar shows attack name, %, M/N counter, elapsed time.
        """
        sem = asyncio.Semaphore(self._concurrency)
        scan_start = time.monotonic()
        target_latencies: list[float] = []
        judge_latencies: list[float] = []

        async def _run_one(payload: Payload) -> AttackResult:
            async with sem:
                progress.update(
                    task_id,
                    description=f"{payload.id}: {payload.name[:50]}",
                )
                target_start = time.monotonic()
                try:
                    response = await self._target.send(payload.payload)
                except Exception as exc:  # TargetError or unexpected -- captured, never re-raised
                    response = f"[target_error: {exc}]"
                target_latency_s = time.monotonic() - target_start

                judge_start = time.monotonic()
                judge_result = await self._judge.evaluate(payload, response)
                judge_latency_s = time.monotonic() - judge_start

                target_latencies.append(target_latency_s)
                judge_latencies.append(judge_latency_s)
                progress.advance(task_id)

                # Deterministic evidence layer (pure, no I/O), then reconcile it with the
                # judge verdict into a single outcome + confidence + verdict source.
                artifacts = run_detectors(
                    response,
                    payload=payload.payload,
                    canary=self._canary,
                    system_prompt=self._system_prompt,
                    include_raw=self._include_raw_artifacts,
                )
                reconciliation = reconcile(judge_result, artifacts)

                _logger.debug(
                    "attack completed",
                    extra={
                        "event": "attack_completed",
                        "scan_id": self._scan_id,
                        "attack_id": payload.id,
                        "target_latency_s": round(target_latency_s, 4),
                        "judge_latency_s": round(judge_latency_s, 4),
                        "success": judge_result.success,
                        "outcome": str(reconciliation.outcome),
                        "confidence": reconciliation.confidence,
                        "verdict_source": str(reconciliation.verdict_source),
                        "artifacts": len(artifacts),
                        "judge_error": judge_result.error,
                    },
                )
                return AttackResult(
                    attack_id=payload.id,
                    owasp_category=payload.category,
                    name=payload.name,
                    payload=payload.payload,
                    response=response,
                    outcome=reconciliation.outcome,
                    judge_reasoning=judge_result.reasoning,
                    judge_error=judge_result.error,
                    severity=payload.severity,
                    confidence=reconciliation.confidence,
                    verdict_source=str(reconciliation.verdict_source),
                    artifacts=artifacts,
                )

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
        ) as progress:
            task_id = progress.add_task("Starting scan...", total=len(self._payloads))
            results = await asyncio.gather(*[_run_one(p) for p in self._payloads])

        findings = list(results)
        risk_score = self._compute_risk_score(findings)
        total_duration_s = time.monotonic() - scan_start
        total_attacks = len(findings)
        successful_attacks = sum(1 for f in findings if f.success)
        errored_attacks = sum(1 for f in findings if f.outcome is Outcome.ERROR)

        self.last_metrics = {
            "total_attacks": total_attacks,
            "successful_attacks": successful_attacks,
            "errored_attacks": errored_attacks,
            "total_duration_s": round(total_duration_s, 4),
            "avg_target_latency_s": round(
                sum(target_latencies) / len(target_latencies), 4
            )
            if target_latencies
            else 0.0,
            "avg_judge_latency_s": round(sum(judge_latencies) / len(judge_latencies), 4)
            if judge_latencies
            else 0.0,
            "risk_score": risk_score,
        }
        _logger.info(
            "scan completed",
            extra={"event": "scan_completed", "scan_id": self._scan_id, **self.last_metrics},
        )

        return ScanReport(
            target=self._target_label,
            timestamp=datetime.now(UTC),
            risk_score=risk_score,
            findings=findings,
        )

    @staticmethod
    def _compute_risk_score(findings: list[AttackResult]) -> float:
        """Sum severity weights for successful attacks, capped at _MAX_RISK_SCORE.

        ENGINE-04: CRITICAL=4.0, HIGH=2.5, MEDIUM=1.5, LOW=0.5, INFO=0.0

        Outcome.ERROR findings contribute 0.0, because AttackResult guarantees
        success is True only for Outcome.VULNERABLE. That is deliberate: an
        unevaluated attack is an unknown, not a confirmed vulnerability, and
        inflating the score with unknowns would make the number meaningless.
        The visibility of those unknowns is the reporters' job (errored_attacks),
        not the score's.
        """
        total = sum(
            _SEVERITY_WEIGHTS.get(Severity(f.severity), 0.0)
            for f in findings
            if f.success
        )
        return min(total, _MAX_RISK_SCORE)
