from __future__ import annotations

import re
from pathlib import Path

from llm_scanner.models import AttackResult, ScanReport

__all__ = ["BaselineManager"]


class BaselineManager:
    """Save, load, and diff named scan baselines.

    Baselines are stored as JSON files under ``<output_dir>/baselines/<name>.json``.
    The name must contain only letters, digits, hyphens, and underscores to prevent
    path traversal attacks (T-05-10).
    """

    def __init__(self, output_dir: Path) -> None:
        self._output_dir = output_dir

    def _validate_name(self, name: str) -> None:
        """Raise ValueError if *name* contains characters outside [a-zA-Z0-9_-]."""
        if not re.match(r"^[a-zA-Z0-9_-]+$", name):
            raise ValueError(
                f"Invalid baseline name {name!r}. "
                "Use only letters, digits, hyphens, and underscores."
            )

    def save(self, name: str) -> Path:
        """Copy the most recent report.json under output_dir to baselines/{name}.json.

        Raises:
            ValueError: if *name* contains invalid characters.
            FileNotFoundError: if no report.json exists under output_dir.
        """
        self._validate_name(name)

        baselines_dir = self._output_dir / "baselines"

        # Find all report.json files, excluding those already inside baselines/
        candidates = [
            p
            for p in self._output_dir.rglob("report.json")
            if not p.is_relative_to(baselines_dir)
        ]

        if not candidates:
            raise FileNotFoundError(
                f"No report.json found in {self._output_dir}"
            )

        # Pick the most recently modified report
        most_recent = max(candidates, key=lambda p: p.stat().st_mtime)
        content = most_recent.read_text(encoding="utf-8")

        baselines_dir.mkdir(parents=True, exist_ok=True)
        dest = baselines_dir / f"{name}.json"
        dest.write_text(content, encoding="utf-8")
        return dest

    def load(self, name: str) -> ScanReport:
        """Deserialize baseline *name* and return a ScanReport.

        Raises:
            ValueError: if *name* contains invalid characters.
            FileNotFoundError: if the baseline file does not exist.
        """
        self._validate_name(name)
        path = self._output_dir / "baselines" / f"{name}.json"
        if not path.exists():
            raise FileNotFoundError(f"Baseline '{name}' not found at {path}")
        return ScanReport.model_validate_json(path.read_text(encoding="utf-8"))

    @staticmethod
    def diff_findings(
        baseline: ScanReport,
        current: ScanReport,
    ) -> list[AttackResult]:
        """Return findings that are new vulnerabilities compared to *baseline*.

        A finding is "new" when it is ``success=True`` in *current* and its
        ``attack_id`` was **not** ``success=True`` in *baseline*.
        """
        baseline_ids = {f.attack_id for f in baseline.findings if f.success}
        return [
            f
            for f in current.findings
            if f.success and f.attack_id not in baseline_ids
        ]
