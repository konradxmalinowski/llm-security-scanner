from __future__ import annotations

from pathlib import Path

from llm_scanner.models import ScanReport


def _sanitize_cell(value: str) -> str:
    """Escape Markdown table metacharacters in a cell value."""
    return value.replace("\n", " ").replace("|", "\\|")


class MarkdownReporter:
    """Save scan results as a Markdown file (REPORT-02)."""

    def save(self, report: ScanReport, output_dir: Path) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / "report.md"
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
            if getattr(f, "suppressed", False):
                result = "Accepted"
            elif f.success:
                result = "VULNERABLE"
            else:
                result = "Safe"
            lines.append(
                f"| {_sanitize_cell(f.attack_id)} | {_sanitize_cell(f.owasp_category)} "
                f"| {_sanitize_cell(f.name)} | {f.severity} "
                f"| {result} | {_sanitize_cell(f.recommendation)} |"
            )

        # CWE / CVSS mapping, one row per distinct category present in the findings.
        seen_mapping: set[str] = set()
        mapping_rows: list[str] = []
        for f in report.findings:
            if f.owasp_category not in seen_mapping and (f.cwe_ids or f.cvss_vector):
                seen_mapping.add(f.owasp_category)
                cwe_str = ", ".join(f.cwe_ids)
                mapping_rows.append(
                    f"| {_sanitize_cell(f.owasp_category)} | {_sanitize_cell(cwe_str)} "
                    f"| {_sanitize_cell(f.cvss_vector)} | {f.cvss_score:.1f} |"
                )

        if mapping_rows:
            lines += [
                "",
                "## CWE / CVSS Mapping",
                "",
                "| Category | CWE | CVSS Vector | CVSS Score |",
                "|----------|-----|-------------|------------|",
            ]
            lines += mapping_rows

        return "\n".join(lines) + "\n"
