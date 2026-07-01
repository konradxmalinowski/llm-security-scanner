from __future__ import annotations

from pathlib import Path

from llm_scanner.models import ScanReport


class TextReporter:
    """Save scan results as a plain-text file without Rich markup (REPORT-05)."""

    def save(self, report: ScanReport, output_dir: Path) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / "report.txt"
        path.write_text(self._render(report), encoding="utf-8")
        return path

    def _render(self, report: ScanReport) -> str:
        lines = [
            f"LLM Security Scan — {report.target}",
            f"Timestamp : {report.timestamp.isoformat()}",
            f"Risk Score: {report.risk_score:.1f}/10.0",
            f"Attacks   : {report.successful_attacks}/{report.total_attacks} succeeded",
            "",
            f"{'ID':<12} {'Category':<10} {'Name':<50} {'Severity':<10} {'Result'}",
            "-" * 100,
        ]
        for f in report.findings:
            result = "VULNERABLE" if f.success else "Safe"
            lines.append(
                f"{f.attack_id:<12} {f.owasp_category:<10} {f.name[:50]:<50} {str(f.severity):<10} {result}"
            )

        # Recommendations grouped by category
        seen: set[str] = set()
        rec_lines: list[str] = []
        for f in report.findings:
            if f.owasp_category not in seen and f.recommendation:
                seen.add(f.owasp_category)
                rec_lines.append(f"{f.owasp_category}: {f.recommendation}")

        if rec_lines:
            lines += ["", "-" * 100, "RECOMMENDATIONS", "-" * 100]
            lines += rec_lines

        return "\n".join(lines) + "\n"
