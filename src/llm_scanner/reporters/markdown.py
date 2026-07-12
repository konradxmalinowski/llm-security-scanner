from __future__ import annotations

from pathlib import Path

from llm_scanner.models import Outcome, ScanReport, VerdictSource

_FINDINGS_COLUMNS = (
    "ID",
    "Category",
    "Name",
    "Severity",
    "Result",
    "Conf.",
    "Source",
    "Judge Error",
    "Recommendation",
)


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
        ]
        if report.errored_attacks:
            lines += [
                f"**Not evaluated:** {report.errored_attacks}/{report.total_attacks}",
                "",
                f"> **Warning:** the judge failed to evaluate {report.errored_attacks} attack(s). "
                "Their result is UNKNOWN, not safe. They are excluded from the risk score, "
                "so the score above is a lower bound on an incomplete scan.",
            ]
        lines += [
            "",
            "## Findings",
            "",
            "| " + " | ".join(_FINDINGS_COLUMNS) + " |",
            "|" + "|".join("-" * (len(c) + 2) for c in _FINDINGS_COLUMNS) + "|",
        ]
        for f in report.findings:
            is_conflict = f.verdict_source == VerdictSource.CONFLICT
            # ERROR first: a finding the judge never evaluated must never render as "Safe".
            if f.outcome is Outcome.ERROR:
                result = "ERROR"
            elif getattr(f, "suppressed", False):
                result = "Accepted"
            elif is_conflict:
                result = "VULNERABLE (CONFLICT)"
            elif f.success:
                result = "VULNERABLE"
            else:
                result = "Safe"
            lines.append(
                f"| {_sanitize_cell(f.attack_id)} | {_sanitize_cell(f.owasp_category)} "
                f"| {_sanitize_cell(f.name)} | {f.severity} "
                f"| {result} | {f.confidence:.2f} | {_sanitize_cell(f.verdict_source or '')} "
                f"| {_sanitize_cell(f.judge_error or '')} "
                f"| {_sanitize_cell(f.recommendation)} |"
            )

        # Per-finding detail: judge reasoning + deterministic artifacts (redacted).
        # Everything user/model-influenced runs through _sanitize_cell so a reasoning
        # string or artifact fingerprint containing '|' or a newline cannot break the
        # surrounding table or inject markup.
        lines += ["", "## Finding Details", ""]
        for f in report.findings:
            lines.append(f"### {_sanitize_cell(f.attack_id)} - {_sanitize_cell(f.name)}")
            lines.append("")
            lines.append(
                f"- **Outcome:** {f.outcome.value} "
                f"| **Confidence:** {f.confidence:.2f} "
                f"| **Source:** {_sanitize_cell(f.verdict_source or 'n/a')}"
            )
            if f.verdict_source == VerdictSource.CONFLICT:
                lines.append(
                    "- **Conflict:** a deterministic detector fired but the judge "
                    "disagreed -- review manually."
                )
            lines.append(
                f"- **Judge reasoning:** {_sanitize_cell(f.judge_reasoning or '(none)')}"
            )
            if f.judge_error:
                lines.append(f"- **Judge error:** {_sanitize_cell(f.judge_error)}")
            if f.artifacts:
                lines += [
                    "",
                    "| Type | Detector | Fingerprint | Span | Conf. |",
                    "|------|----------|-------------|------|-------|",
                ]
                for a in f.artifacts:
                    # Render the redacted fingerprint ONLY, never a.raw.
                    lines.append(
                        f"| {_sanitize_cell(a.type)} | {_sanitize_cell(a.detector)} "
                        f"| {_sanitize_cell(a.fingerprint)} "
                        f"| {a.span[0]}:{a.span[1]} | {a.confidence:.2f} |"
                    )
            lines.append("")

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
