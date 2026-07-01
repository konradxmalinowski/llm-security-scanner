from __future__ import annotations

import json as _json
from datetime import datetime
from enum import StrEnum
from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field, computed_field, model_validator


class Severity(StrEnum):
    """StrEnum ensures JSON serialization outputs "critical" not <Severity.CRITICAL>."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


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


class AttackResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attack_id: str
    owasp_category: str
    name: str
    payload: str
    response: str
    success: bool
    judge_reasoning: str
    severity: Severity
    recommendation: str = ""

    @model_validator(mode="after")
    def _populate_recommendation(self) -> AttackResult:
        """Populate recommendation from OWASP_RECOMMENDATIONS if not set explicitly."""
        if not self.recommendation:
            self.recommendation = OWASP_RECOMMENDATIONS.get(self.owasp_category, "")
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

    # Computed fields appear in model_dump_json() output but are rejected
    # as extra inputs by extra="forbid" on the way back in.  Override
    # model_validate_json() to strip them before re-validation so callers
    # can round-trip JSON without a manual pop() workaround.
    _COMPUTED_FIELDS: ClassVar[frozenset[str]] = frozenset({"total_attacks", "successful_attacks"})

    @classmethod
    def model_validate_json(  # type: ignore[override]
        cls,
        json_data: str | bytes,
        **kwargs: object,
    ) -> ScanReport:
        data = _json.loads(json_data)
        for k in cls._COMPUTED_FIELDS:
            data.pop(k, None)
        return cls.model_validate(data, **kwargs)
