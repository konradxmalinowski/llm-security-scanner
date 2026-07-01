from __future__ import annotations

import json
from pathlib import Path

from llm_scanner.models import ScanReport, Severity

_LEVEL_MAP: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


class SarifReporter:
    """Save scan results as a SARIF 2.1.0 JSON file (ADV-04).

    SARIF (Static Analysis Results Interchange Format) is the industry standard
    for security tool output.  The produced file is consumable by GitHub Security
    tab and VS Code SARIF Viewer.

    Design notes:
    - artifactLocation.uri is hardcoded to "." (repo root placeholder).  LLM
      security findings have no source-file location; GitHub upload-sarif requires
      a non-empty URI — using "." satisfies the validator while conveying that the
      finding is a dynamic test result.
    - Only findings where success=True AND suppressed=False appear in results[].
    - Rules are deduplicated by owasp_category (one rule per OWASP category).
    """

    def save(self, report: ScanReport, output_dir: Path) -> Path:
        """Write SARIF JSON to output_dir/report.sarif and return the path."""
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / "report.sarif"
        path.write_text(json.dumps(self._build(report), indent=2), encoding="utf-8")
        return path

    def _build(self, report: ScanReport) -> dict:
        """Build and return the SARIF 2.1.0 dict for the given ScanReport."""
        # --- Deduplicate rules: one per OWASP category ---
        seen: set[str] = set()
        rules: list[dict] = []
        for f in report.findings:
            if f.owasp_category not in seen:
                seen.add(f.owasp_category)
                rules.append(
                    {
                        "id": f.owasp_category,
                        "shortDescription": {"text": f"OWASP {f.owasp_category}"},
                        "fullDescription": {
                            "text": f.recommendation or f.owasp_category
                        },
                        "help": {
                            "text": f.recommendation
                            or "See OWASP Top 10 for LLMs 2025."
                        },
                    }
                )

        # --- Results: only confirmed, non-suppressed vulnerabilities ---
        results: list[dict] = [
            {
                "ruleId": f.owasp_category,
                "level": _LEVEL_MAP.get(Severity(f.severity), "note"),
                "message": {"text": f"{f.name}: {f.judge_reasoning}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "."},
                            "region": {"startLine": 1, "startColumn": 1},
                        },
                        "logicalLocations": [
                            {
                                "name": report.target,
                                "kind": "function",
                                "fullyQualifiedName": f"llm-endpoint/{report.target}",
                            }
                        ],
                    }
                ],
                "partialFingerprints": {
                    "primaryLocationLineHash": f"{f.attack_id}:1"
                },
            }
            for f in report.findings
            if f.success and not getattr(f, "suppressed", False)
        ]

        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "LLM Security Scanner",
                            "version": "0.1.0",
                            "rules": rules,
                        }
                    },
                    "results": results,
                }
            ],
        }
