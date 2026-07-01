"""False-positive suppression module for LLM Security Scanner.

Provides the ``Suppression`` Pydantic model and the ``SuppressionLoader``
class that applies user-defined suppression rules to scan findings.

suppressions.yaml schema
------------------------
The suppressions file must be a YAML mapping with a top-level
``suppressions`` key containing a list of entries.  Each entry supports:

- ``attack_id`` (str, required): exact attack ID (e.g. ``"LLM01-001"``) or
  fnmatch glob pattern (e.g. ``"LLM01-*"``).
- ``reason`` (str, required): human-readable justification for accepting the
  finding as a false positive.
- ``expires`` (str, optional): ISO 8601 date string after which the
  suppression should be reviewed (e.g. ``"2026-12-31"``).  Not enforced
  programmatically — treated as metadata only.

Example::

    suppressions:
      - attack_id: "LLM01-*"
        reason: "Accepted risk for internal tool — not user-facing"
      - attack_id: "LLM07-003"
        reason: "System prompt disclosure is intentional in demo mode"
        expires: "2026-12-31"
"""
from __future__ import annotations

import fnmatch
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict

from llm_scanner.models import AttackResult

__all__ = ["Suppression", "SuppressionLoader"]


class Suppression(BaseModel):
    """A single suppression rule loaded from suppressions.yaml.

    Uses ``extra="ignore"`` so that user-authored YAML files with additional
    metadata keys (comments-as-keys, tooling fields, etc.) do not cause
    validation errors.
    """

    model_config = ConfigDict(extra="ignore")

    attack_id: str
    reason: str
    expires: str | None = None


class SuppressionLoader:
    """Loads and applies suppression rules from a YAML file.

    Args:
        path: Path to the suppressions YAML file.  The file need not exist;
            :py:meth:`load` returns an empty list when the path is absent.
    """

    def __init__(self, path: Path) -> None:
        self._path = path

    def load(self) -> list[Suppression]:
        """Return all suppression rules from the YAML file.

        Returns an empty list if the file does not exist — callers do not
        need to check for file existence before calling this method.

        Raises:
            ValueError: If the file exists but cannot be parsed as valid YAML.
        """
        if not self._path.exists():
            return []
        # Always use safe_load — Ruff S506 enforces; yaml.load() is unsafe.
        data = yaml.safe_load(self._path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return []
        return [Suppression(**s) for s in data.get("suppressions", [])]

    def apply(self, findings: list[AttackResult]) -> list[AttackResult]:
        """Mark findings whose attack_id matches a suppression rule.

        For each finding, the suppression list is checked in order.  The
        **first** matching rule wins (exact string or fnmatch glob).  On a
        match, ``finding.suppressed`` is set to ``True`` and
        ``finding.suppression_reason`` is set to the rule's ``reason``.

        Returns the same list (mutated in-place) so callers can chain the
        call directly.
        """
        suppressions = self.load()
        if not suppressions:
            return findings
        for finding in findings:
            for sup in suppressions:
                if fnmatch.fnmatch(finding.attack_id, sup.attack_id):
                    finding.suppressed = True
                    finding.suppression_reason = sup.reason
                    break
        return findings
