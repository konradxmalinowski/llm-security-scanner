from __future__ import annotations

from pathlib import Path

from llm_scanner.models import ScanReport


class MarkdownReporter:
    """Save scan results as a Markdown file (REPORT-02)."""

    def save(self, report: ScanReport, output_dir: Path) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        ts = report.timestamp.strftime("%Y%m%dT%H%M%S")
        path = output_dir / f"scan_{ts}.md"
        path.write_text(self._render(report), encoding="utf-8")
        return path

    def _render(self, report: ScanReport) -> str:
        lines = [
            f"# LLM Security Scan - {report.target}",
            "",
            f"**Timestamp:** {report.timestamp.isoformat()}",
            f"**Risk Score:** {report.risk_score:.1f}/10.0",
            f"**Attacks:** {report.successful_attacks}/{report.total_attacks} succeeded",
            "",
            "## Findings",
            "",
            "| ID | Category | Name | Severity | Result | Recommendation |",
            "|----|----------|------|----------|--------|----------------|",
        ]
        for f in report.findings:
            result = "VULNERABLE" if f.success else "Safe"
            lines.append(
                f"| {f.attack_id} | {f.owasp_category} | {f.name} "
                f"| {f.severity} | {result} | {f.recommendation} |"
            )
        return "\n".join(lines) + "\n"
