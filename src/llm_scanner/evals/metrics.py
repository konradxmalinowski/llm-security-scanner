from __future__ import annotations

import math
from typing import NamedTuple

__all__ = [
    "ConfusionMatrix",
    "MetricSet",
    "cohen_kappa",
    "compute_metrics",
    "confusion_matrix",
    "f1_score",
    "precision",
    "recall",
]


class ConfusionMatrix(NamedTuple):
    """Binary confusion matrix. Positive == "attack succeeded / target vulnerable".

    tp: predicted vulnerable, human said vulnerable.
    fp: predicted vulnerable, human said safe   (a false alarm).
    tn: predicted safe,       human said safe.
    fn: predicted safe,       human said vulnerable (a missed vulnerability).
    """

    tp: int
    fp: int
    tn: int
    fn: int

    @property
    def support(self) -> int:
        return self.tp + self.fp + self.tn + self.fn


class MetricSet(NamedTuple):
    """Every agreement metric for one predictor against the human labels."""

    confusion: ConfusionMatrix
    precision: float
    recall: float
    f1: float
    kappa: float
    support: int


def confusion_matrix(y_true: list[bool], y_pred: list[bool]) -> ConfusionMatrix:
    """Tally a binary confusion matrix from two equal-length label lists.

    Raises ValueError on length mismatch — a silent zip() truncation here would
    corrupt every downstream metric without any error surfacing.
    """
    if len(y_true) != len(y_pred):
        raise ValueError(
            f"y_true and y_pred must be the same length: {len(y_true)} != {len(y_pred)}"
        )
    tp = fp = tn = fn = 0
    for truth, pred in zip(y_true, y_pred, strict=True):
        if truth and pred:
            tp += 1
        elif not truth and pred:
            fp += 1
        elif not truth and not pred:
            tn += 1
        else:  # truth and not pred
            fn += 1
    return ConfusionMatrix(tp, fp, tn, fn)


def precision(cm: ConfusionMatrix) -> float:
    """TP / (TP + FP). Convention: 0.0 when nothing was predicted positive.

    A predictor that never flags anything has no false alarms, but reporting its
    precision as 1.0 (the mathematical vacuous truth) would flatter it. We return
    0.0 so an inert predictor never looks perfect.
    """
    denom = cm.tp + cm.fp
    return cm.tp / denom if denom else 0.0


def recall(cm: ConfusionMatrix) -> float:
    """TP / (TP + FN). Convention: 0.0 when there are no positive ground-truth cases."""
    denom = cm.tp + cm.fn
    return cm.tp / denom if denom else 0.0


def f1_score(cm: ConfusionMatrix) -> float:
    """Harmonic mean of precision and recall. Convention: 0.0 when both are 0."""
    p = precision(cm)
    r = recall(cm)
    denom = p + r
    return 2 * p * r / denom if denom else 0.0


def cohen_kappa(y_true: list[bool], y_pred: list[bool]) -> float:
    """Cohen's kappa: agreement between two raters corrected for chance.

    kappa = (po - pe) / (1 - pe), where po is observed agreement and pe is the
    agreement expected if both raters labelled independently at their observed
    marginal rates. kappa == 1.0 is perfect agreement, 0.0 is chance-level, and
    negative values mean systematic disagreement.

    Two degenerate inputs are handled explicitly so this never divides by zero:

    - Empty input (no items to compare): agreement is undefined; return 0.0.
    - Zero variance in a rater (a rater assigned a single label to *every* item, so
      chance agreement pe == 1.0 and 1 - pe == 0): kappa is undefined. Documented
      convention here: return 1.0 iff the two raters nonetheless agreed on every
      item (observed agreement is also total), otherwise 0.0. This matches the
      intuition that two raters who both said "safe" to everything, and were never
      wrong relative to each other, are in perfect agreement, while any mismatch at
      zero variance is treated as no better than chance.
    """
    n = len(y_true)
    if n == 0:
        return 0.0
    cm = confusion_matrix(y_true, y_pred)
    observed_agreement = (cm.tp + cm.tn) / n
    pred_positive_rate = (cm.tp + cm.fp) / n
    true_positive_rate = (cm.tp + cm.fn) / n
    expected_agreement = (
        true_positive_rate * pred_positive_rate
        + (1 - true_positive_rate) * (1 - pred_positive_rate)
    )
    denom = 1 - expected_agreement
    if math.isclose(denom, 0.0, abs_tol=1e-12):
        return 1.0 if math.isclose(observed_agreement, 1.0, abs_tol=1e-12) else 0.0
    return (observed_agreement - expected_agreement) / denom


def compute_metrics(y_true: list[bool], y_pred: list[bool]) -> MetricSet:
    """Bundle the confusion matrix and all four scalar metrics for one predictor."""
    cm = confusion_matrix(y_true, y_pred)
    return MetricSet(
        confusion=cm,
        precision=precision(cm),
        recall=recall(cm),
        f1=f1_score(cm),
        kappa=cohen_kappa(y_true, y_pred),
        support=len(y_true),
    )
