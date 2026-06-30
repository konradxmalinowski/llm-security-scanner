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
            try:
                with path.open(encoding="utf-8") as f:
                    file_data = yaml.safe_load(f)
            except (yaml.YAMLError, UnicodeDecodeError) as exc:
                raise ValueError(f"Failed to parse payload file {path}: {exc}") from exc

            if not isinstance(file_data, dict):
                raise ValueError(
                    f"Payload file {path} must be a YAML mapping; "
                    f"got {type(file_data).__name__!r}"
                )

            try:
                file_category: str = file_data["category"]
                file_severity: Severity = Severity(file_data["severity"])
            except KeyError as exc:
                raise ValueError(f"Missing required top-level key {exc} in {path}") from exc
            except ValueError as exc:
                raise ValueError(f"Invalid severity value in {path}: {exc}") from exc

            if categories is not None and file_category not in categories:
                continue
            if severity is not None and file_severity != severity:
                continue

            for i, entry in enumerate(file_data.get("payloads") or []):
                try:
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
                except KeyError as exc:
                    raise ValueError(
                        f"Payload entry #{i} in {path} is missing required field: {exc}"
                    ) from exc

        return results
