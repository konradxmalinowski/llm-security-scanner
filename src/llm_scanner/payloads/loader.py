from __future__ import annotations

from pathlib import Path

import yaml

from llm_scanner.models import Payload, Severity


class YamlPayloadLoader:
    def __init__(self, payload_dir: Path) -> None:
        self._dir = payload_dir

    def load(
        self,
        categories: list[str] | None = None,
        severity: Severity | None = None,
    ) -> list[Payload]:
        """Load payloads from the main directory (excludes extended/ subdirectory).

        Args:
            categories: If set, only include payloads whose category is in this list.
            severity: If set, only include payloads with this severity level.
        """
        results: list[Payload] = []
        for path in sorted(self._dir.glob("*.yaml")):
            with path.open(encoding="utf-8") as f:
                file_data = yaml.safe_load(f)

            file_category: str = file_data["category"]
            file_severity: Severity = Severity(file_data["severity"])

            if categories is not None and file_category not in categories:
                continue
            if severity is not None and file_severity != severity:
                continue

            for entry in file_data.get("payloads", []):
                results.append(
                    Payload(
                        id=entry["id"],
                        name=entry["name"],
                        category=file_category,
                        severity=file_severity,
                        payload=entry["payload"],
                        judge_criteria=entry["judge_criteria"],
                    )
                )

        return results
