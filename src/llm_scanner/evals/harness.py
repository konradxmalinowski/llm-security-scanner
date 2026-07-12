from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from llm_scanner.detectors import run_detectors
from llm_scanner.evals.corpus import CorpusEntry
from llm_scanner.evals.metrics import MetricSet, compute_metrics
from llm_scanner.judge.reconcile import derive_outcome, reconcile
from llm_scanner.models import Artifact, JudgeResult, Outcome

__all__ = [
    "PREDICTORS",
    "EntryResult",
    "EvalReport",
    "JudgeLike",
    "detector_says_vulnerable",
    "evaluate_corpus",
    "hybrid_says_vulnerable",
    "judge_says_vulnerable",
    "summary_dict",
]

# The three predictors we score against the human labels. Reported side by side so the
# detector layer's agreement is shown SEPARATELY from the judge's — the whole point being
# to demonstrate, not assert, that the deterministic rules barely ever false-alarm.
PREDICTORS: tuple[str, str, str] = ("judge", "detectors", "hybrid")

# Detector artifact types that constitute a standalone "vulnerable" verdict for the
# detectors-only predictor. Mirrors judge/reconcile.py: a canary is proof, secret and
# prompt_overlap are strong; prompt_marker is a weak hint that never stands alone.
_STANDALONE_RULE_TYPES: frozenset[str] = frozenset({"canary", "secret", "prompt_overlap"})


class JudgeLike(Protocol):
    """Structural type for anything the harness can replay a corpus through.

    The real OllamaJudge satisfies it; so does an offline fake in the test suite. This is
    what lets every metric/comparison path run fully offline — no Ollama, no network.
    """

    async def evaluate(self, payload: object, response: str) -> JudgeResult: ...


def judge_says_vulnerable(judge_result: JudgeResult) -> bool:
    """The judge-only prediction. A judge ERROR (timeout/unparseable) is NOT a vulnerability
    claim, so it counts as a negative here; errored entries are tallied separately so the
    headline judge metrics are never quietly inflated or deflated by outages."""
    return derive_outcome(judge_result) is Outcome.VULNERABLE


def detector_says_vulnerable(artifacts: list[Artifact]) -> bool:
    """The deterministic-detectors-only prediction: True iff a standalone rule fired."""
    return any(a.type in _STANDALONE_RULE_TYPES for a in artifacts)


def hybrid_says_vulnerable(judge_result: JudgeResult, artifacts: list[Artifact]) -> bool:
    """The reconciled prediction — the verdict a real scan would report (see reconcile).
    A CONFLICT reconciles to VULNERABLE, so it counts as a positive prediction here."""
    return reconcile(judge_result, artifacts).outcome is Outcome.VULNERABLE


@dataclass(frozen=True)
class EntryResult:
    """Per-entry replay outcome, retained for drill-down and conflict sampling."""

    entry: CorpusEntry
    judge_result: JudgeResult
    artifacts: list[Artifact]
    judge_positive: bool
    detector_positive: bool
    hybrid_positive: bool
    judge_errored: bool


@dataclass(frozen=True)
class EvalReport:
    """Full result of replaying a corpus: overall + per-category metric sets."""

    overall: dict[str, MetricSet]
    by_category: dict[str, dict[str, MetricSet]]
    entries: list[EntryResult]
    errored_count: int


async def evaluate_corpus(
    entries: list[CorpusEntry],
    judge: JudgeLike,
    *,
    key: bytes | None = None,
) -> EvalReport:
    """Replay every corpus entry through the real judge AND the deterministic detectors,
    then compute agreement of all three predictors against the human labels.

    Pure of I/O except for the judge calls it delegates to ``judge``; passing an offline
    fake makes the whole function deterministic and network-free for tests.
    """
    y_true: list[bool] = []
    preds: dict[str, list[bool]] = {name: [] for name in PREDICTORS}
    results: list[EntryResult] = []

    for entry in entries:
        payload = entry.to_payload()
        judge_result = await judge.evaluate(payload, entry.response)
        artifacts = run_detectors(
            entry.response,
            payload=entry.payload,
            canary=entry.canary,
            system_prompt=entry.system_prompt,
            key=key,
        )
        jp = judge_says_vulnerable(judge_result)
        dp = detector_says_vulnerable(artifacts)
        hp = hybrid_says_vulnerable(judge_result, artifacts)

        y_true.append(entry.human_verdict)
        preds["judge"].append(jp)
        preds["detectors"].append(dp)
        preds["hybrid"].append(hp)
        results.append(
            EntryResult(
                entry=entry,
                judge_result=judge_result,
                artifacts=artifacts,
                judge_positive=jp,
                detector_positive=dp,
                hybrid_positive=hp,
                judge_errored=derive_outcome(judge_result) is Outcome.ERROR,
            )
        )

    overall = {name: compute_metrics(y_true, preds[name]) for name in PREDICTORS}

    by_category: dict[str, dict[str, MetricSet]] = {}
    for category in sorted({r.entry.category for r in results}):
        idxs = [i for i, r in enumerate(results) if r.entry.category == category]
        cat_true = [y_true[i] for i in idxs]
        by_category[category] = {
            name: compute_metrics(cat_true, [preds[name][i] for i in idxs])
            for name in PREDICTORS
        }

    errored_count = sum(1 for r in results if r.judge_errored)
    return EvalReport(
        overall=overall,
        by_category=by_category,
        entries=results,
        errored_count=errored_count,
    )


def _metricset_dict(ms: MetricSet) -> dict[str, object]:
    return {
        "tp": ms.confusion.tp,
        "fp": ms.confusion.fp,
        "tn": ms.confusion.tn,
        "fn": ms.confusion.fn,
        "precision": round(ms.precision, 4),
        "recall": round(ms.recall, 4),
        "f1": round(ms.f1, 4),
        "kappa": round(ms.kappa, 4),
        "support": ms.support,
    }


def summary_dict(report: EvalReport) -> dict[str, object]:
    """Machine-readable metrics summary for --json output and regression gating.

    Deliberately excludes per-entry payload/response text: the summary is meant to land in
    CI logs, and the corpus responses may embed sample secrets.
    """
    return {
        "corpus_size": len(report.entries),
        "judge_errored": report.errored_count,
        "overall": {name: _metricset_dict(ms) for name, ms in report.overall.items()},
        "by_category": {
            category: {name: _metricset_dict(ms) for name, ms in per.items()}
            for category, per in report.by_category.items()
        },
    }
