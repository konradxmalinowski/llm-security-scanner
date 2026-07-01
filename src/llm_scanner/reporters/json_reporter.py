from __future__ import annotations

from pathlib import Path

from llm_scanner.models import ScanReport


class JsonReporter:
    """Save scan results as a JSON file containing the full ScanReport (REPORT-03)."""

    def save(self, report: ScanReport, output_dir: Path) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / "report.json"
        path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        return path
