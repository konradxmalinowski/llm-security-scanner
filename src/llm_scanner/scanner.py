from __future__ import annotations

import asyncio
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

from llm_scanner.models import AttackResult, Payload, ScanReport, Severity

if TYPE_CHECKING:
    from llm_scanner.judge import OllamaJudge
    from llm_scanner.targets.base import AbstractTarget

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
    ) -> None:
        self._target = target
        self._judge = judge
        self._payloads = payloads
        self._target_label = target_label
        self._concurrency = concurrency

    async def scan(self) -> ScanReport:
        """Run all payloads against target and return a ScanReport.

        ENGINE-01: iterates all payloads, dispatches to target + judge.
        ENGINE-02: asyncio.Semaphore limits concurrent attacks to self._concurrency.
        ENGINE-03: Rich progress bar shows attack name, %, M/N counter, elapsed time.
        """
        sem = asyncio.Semaphore(self._concurrency)

        async def _run_one(payload: Payload) -> AttackResult:
            async with sem:
                progress.update(
                    task_id,
                    description=f"{payload.id}: {payload.name[:50]}",
                )
                try:
                    response = await self._target.send(payload.payload)
                except Exception as exc:  # TargetError or unexpected -- captured, never re-raised
                    response = f"[target_error: {exc}]"
                judge_result = await self._judge.evaluate(payload, response)
                progress.advance(task_id)
                return AttackResult(
                    attack_id=payload.id,
                    owasp_category=payload.category,
                    name=payload.name,
                    payload=payload.payload,
                    response=response,
                    success=judge_result.success,
                    judge_reasoning=judge_result.reasoning,
                    severity=payload.severity,
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
        """
        total = sum(
            _SEVERITY_WEIGHTS.get(Severity(f.severity), 0.0)
            for f in findings
            if f.success
        )
        return min(total, _MAX_RISK_SCORE)
