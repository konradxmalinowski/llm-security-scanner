from __future__ import annotations

import json as _json
import math
from datetime import datetime
from enum import StrEnum
from typing import ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field, computed_field, model_validator


class Severity(StrEnum):
    """StrEnum ensures JSON serialization outputs "critical" not <Severity.CRITICAL>."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Outcome(StrEnum):
    """Tri-state verdict for a single attack.

    VULNERABLE and SAFE are real verdicts. ERROR means the judge could not
    reach a verdict at all (timeout, unreachable model, unparseable output) —
    the attack result is UNKNOWN, not safe. Collapsing ERROR into SAFE would
    let a scan where the judge was down render as a clean bill of health.
    """

    VULNERABLE = "vulnerable"
    SAFE = "safe"
    ERROR = "error"


class VerdictSource(StrEnum):
    """Where a finding's verdict came from once the LLM judge and the deterministic
    detector layer have been reconciled (see judge/reconcile.py).

    RULE_PROOF is the strongest: a canary token was found verbatim in the response,
    which is proof of leakage by string comparison — no model judgement involved.
    CONFLICT is the highest-value signal for a human reviewer: a deterministic
    detector fired but the judge disagreed, and that disagreement is surfaced rather
    than silently resolved.
    """

    RULE_PROOF = "rule_proof"
    BOTH_AGREE = "both_agree"
    JUDGE_ONLY = "judge_only"
    JUDGE_DEGRADED = "judge_degraded"
    CONFLICT = "conflict"
    JUDGE_ERROR = "judge_error"


OWASP_RECOMMENDATIONS: dict[str, str] = {
    "LLM01": "Implement input validation and context-aware output encoding; enforce least-privilege system prompts.",
    "LLM02": "Apply data minimization; audit training data; implement output filtering for PII.",
    "LLM03": "Verify third-party model and plugin provenance; pin dependency versions.",
    "LLM04": "Validate and sanitize fine-tuning data; monitor for behavioral drift post-training.",
    "LLM05": "Treat all LLM output as untrusted; apply output encoding before rendering.",
    "LLM06": "Enforce least-privilege for LLM actions; require human-in-the-loop for high-impact operations.",
    "LLM07": "Never embed secrets in system prompts; design prompts to be safe if disclosed.",
    "LLM08": "Sanitize and validate retrieved context before injection; implement retrieval access controls.",
    "LLM09": "Ground outputs in verifiable sources; implement confidence thresholds and human review.",
    "LLM10": "Implement rate limiting, token budgets, and resource quotas per user/session.",
}

# CWE identifiers per OWASP LLM Top 10 (2025) category, at category granularity.
# One or more real, published CWE IDs per category — see plans/2026-07-04-cwe-cvss-mapping.md
# for the rationale behind each mapping.
CWE_MAP: dict[str, list[str]] = {
    "LLM01": ["CWE-77", "CWE-94"],  # Prompt Injection: command / code injection territory
    "LLM02": ["CWE-200"],  # Sensitive Information Disclosure
    "LLM03": ["CWE-1104", "CWE-829"],  # Supply Chain: unmaintained/untrusted components
    "LLM04": ["CWE-20", "CWE-1039"],  # Data/Model Poisoning: adversarial input handling
    "LLM05": ["CWE-79", "CWE-116"],  # Improper Output Handling: XSS / improper encoding
    "LLM06": ["CWE-269", "CWE-863"],  # Excessive Agency: privilege management / authorization
    "LLM07": ["CWE-200", "CWE-522"],  # System Prompt Leakage: disclosure / protected credentials
    "LLM08": ["CWE-668"],  # Vector/Embedding Weaknesses: exposure to wrong sphere (cross-tenant)
    "LLM09": ["CWE-345"],  # Misinformation: insufficient verification of data authenticity
    "LLM10": ["CWE-400", "CWE-770"],  # Unbounded Consumption: uncontrolled resource consumption
}

# Full CVSS 3.1 vector strings per OWASP LLM Top 10 category, chosen to reflect each
# category's typical real-world impact profile. Base scores are computed at runtime
# by compute_cvss_score() — never hardcode a score disconnected from its vector.
CVSS_MAP: dict[str, str] = {
    "LLM01": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "LLM02": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "LLM03": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H",
    "LLM04": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:H/A:L",
    "LLM05": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "LLM06": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:H/A:H",
    "LLM07": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "LLM08": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:N",
    "LLM09": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
    "LLM10": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H",
}

# --- CVSS 3.1 base score formula (FIRST.org CVSS v3.1 specification, section 8.1) ---

_CVSS_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_CVSS_AC = {"L": 0.77, "H": 0.44}
_CVSS_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_CVSS_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_CVSS_UI = {"N": 0.85, "R": 0.62}
_CVSS_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _cvss_roundup(value: float) -> float:
    """Round up to one decimal place, per the CVSS 3.1 spec's exact algorithm.

    A naive round() on floating point base-score arithmetic can misround at the
    boundary (e.g. 4.02 vs 4.0); the spec mandates this integer-scaled approach.
    """
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def compute_cvss_score(vector: str) -> float:
    """Compute the CVSS 3.1 base score (0.0-10.0) from a full vector string.

    Implements the official base score formula from the CVSS v3.1 specification
    (Impact and Exploitability sub-scores -> base score). Only the standard 3.1
    base metric set (AV/AC/PR/UI/S/C/I/A) is supported. Returns 0.0 for an empty
    or unparseable vector rather than raising, so callers can use it defensively.
    """
    if not vector:
        return 0.0
    try:
        prefix, _, metrics_part = vector.partition("/")
        if not prefix.startswith("CVSS:3."):
            return 0.0
        metrics = dict(pair.split(":", 1) for pair in metrics_part.split("/") if pair)

        av = _CVSS_AV[metrics["AV"]]
        ac = _CVSS_AC[metrics["AC"]]
        ui = _CVSS_UI[metrics["UI"]]
        scope = metrics["S"]
        pr_table = _CVSS_PR_CHANGED if scope == "C" else _CVSS_PR_UNCHANGED
        pr = pr_table[metrics["PR"]]
        c = _CVSS_CIA[metrics["C"]]
        i = _CVSS_CIA[metrics["I"]]
        a = _CVSS_CIA[metrics["A"]]
    except (KeyError, ValueError):
        return 0.0

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    exploitability = 8.22 * av * ac * pr * ui

    if scope == "C":
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss

    if impact <= 0:
        return 0.0

    base = 1.08 * (impact + exploitability) if scope == "C" else impact + exploitability
    return _cvss_roundup(min(base, 10.0))


class Payload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    category: str
    severity: Severity
    payload: str
    judge_criteria: str


class JudgeResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    success: bool
    reasoning: str
    error: str | None = None  # set on parse/timeout/unavailability failure
    raw_response: str = ""    # always preserved; empty string on connection failure


class Artifact(BaseModel):
    """A single piece of deterministic (non-LLM) evidence found in a target response.

    Produced by the detectors package. Every field except ``raw`` is safe to publish:
    ``fingerprint`` is a redacted stand-in for the detected value (first4...last4 plus a
    sha256 prefix) so that a report which detects a leaked secret never becomes the leak
    vector by transcribing that secret in cleartext. ``raw`` holds the unredacted value
    and is populated ONLY when the operator explicitly passes --include-raw-artifacts.
    """

    model_config = ConfigDict(extra="forbid")

    type: Literal["canary", "secret", "prompt_marker", "prompt_overlap"]
    detector: str  # which rule fired, e.g. "aws_access_key" or "canary_exact"
    fingerprint: str  # REDACTED representation — never the raw secret
    span: tuple[int, int]  # (start, end) character offsets into the response
    confidence: float
    raw: str | None = None  # unredacted value; set only under --include-raw-artifacts


class AttackResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attack_id: str
    owasp_category: str
    name: str
    payload: str
    response: str
    # `success` stays a STORED field, never a computed_field: model_dump_json() emits
    # computed fields, and AttackResult is extra="forbid", so a computed `success`
    # would be rejected when a report is re-validated (BaselineManager.load()).
    # `_reconcile_outcome` keeps it in lockstep with `outcome` instead.
    success: bool = False
    outcome: Outcome = Outcome.SAFE
    judge_reasoning: str
    judge_error: str | None = None
    severity: Severity
    recommendation: str = ""
    suppressed: bool = False
    suppression_reason: str = ""
    cwe_ids: list[str] = Field(default_factory=list)
    cvss_vector: str = ""
    cvss_score: float = 0.0
    # Hybrid-verdict fields (judge + deterministic detectors, see judge/reconcile.py).
    # All default so pre-existing report.json files without these keys still load under
    # extra="forbid". verdict_source stores a VerdictSource value (kept as str for a
    # forgiving round-trip of older/unknown values).
    confidence: float = 0.0
    verdict_source: str = ""
    artifacts: list[Artifact] = Field(default_factory=list)

    @model_validator(mode="after")
    def _reconcile_outcome(self) -> AttackResult:
        """Keep `success` and `outcome` consistent, whichever one the caller supplied.

        Invariant enforced here: ``success is True`` if and only if
        ``outcome is Outcome.VULNERABLE``. An ERROR finding therefore never counts
        as a successful attack and never contributes to the risk score.

        - Only `success` given (legacy callers, pre-`outcome` JSON reports):
          derive `outcome` from it.
        - `outcome` given: it is authoritative and `success` is derived from it,
          because only `outcome` can express the ERROR state.
        """
        fields_set = self.model_fields_set
        if "outcome" not in fields_set and "success" in fields_set:
            self.outcome = Outcome.VULNERABLE if self.success else Outcome.SAFE
        else:
            self.success = self.outcome is Outcome.VULNERABLE
        return self

    @model_validator(mode="after")
    def _populate_recommendation(self) -> AttackResult:
        """Populate recommendation from OWASP_RECOMMENDATIONS if not set explicitly."""
        if not self.recommendation:
            self.recommendation = OWASP_RECOMMENDATIONS.get(self.owasp_category, "")
        return self

    @model_validator(mode="after")
    def _populate_cwe_cvss(self) -> AttackResult:
        """Populate CWE/CVSS fields from the category maps, mirroring _populate_recommendation.

        Unknown/missing category must not raise — falls back to empty list/string/0.0.
        Explicitly provided values are never overwritten.
        """
        if not self.cwe_ids:
            self.cwe_ids = list(CWE_MAP.get(self.owasp_category, []))
        if not self.cvss_vector:
            self.cvss_vector = CVSS_MAP.get(self.owasp_category, "")
        if not self.cvss_score:
            self.cvss_score = compute_cvss_score(self.cvss_vector)
        return self


class ScanReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str
    timestamp: datetime
    risk_score: float = Field(ge=0.0, le=10.0)
    findings: list[AttackResult]

    @computed_field
    @property
    def total_attacks(self) -> int:
        return len(self.findings)

    @computed_field
    @property
    def successful_attacks(self) -> int:
        return sum(1 for f in self.findings if f.success)

    @computed_field
    @property
    def errored_attacks(self) -> int:
        """Findings the judge could not evaluate — an unknown, not a pass."""
        return sum(1 for f in self.findings if f.outcome is Outcome.ERROR)

    # Computed fields appear in model_dump_json() output but are rejected
    # as extra inputs by extra="forbid" on the way back in.  Override
    # model_validate_json() to strip them before re-validation so callers
    # can round-trip JSON without a manual pop() workaround.
    _COMPUTED_FIELDS: ClassVar[frozenset[str]] = frozenset(
        {"total_attacks", "successful_attacks", "errored_attacks"}
    )

    @classmethod
    def model_validate_json(  # type: ignore[override]
        cls,
        json_data: str | bytes,
        **kwargs: object,
    ) -> ScanReport:
        try:
            data = _json.loads(json_data)
        except _json.JSONDecodeError as exc:
            # Re-raise as ValueError so callers catching ValidationError see a
            # consistent error type (Pydantic wraps ValueError in ValidationError).
            raise ValueError(f"Invalid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError(f"Expected a JSON object, got {type(data).__name__}")
        for k in cls._COMPUTED_FIELDS:
            data.pop(k, None)
        return cls.model_validate(data, **kwargs)
