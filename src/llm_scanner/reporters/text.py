from __future__ import annotations

from pathlib import Path

from llm_scanner.models import Outcome, ScanReport


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
        ]
        if report.errored_attacks:
            lines += [
                f"NOT EVALUATED: {report.errored_attacks}/{report.total_attacks} "
                "-- the judge failed on these attacks. Their result is UNKNOWN, not safe,",
                "and they are excluded from the risk score, so treat the score as a lower bound.",
            ]
        lines += [
            "",
            f"{'ID':<12} {'Category':<10} {'Name':<50} {'Severity':<10} {'Result':<12} {'Judge Error'}",
            "-" * 115,
        ]
        for f in report.findings:
            # ERROR first: a finding the judge never evaluated must never print as "Safe".
            if f.outcome is Outcome.ERROR:
                result = "ERROR"
            elif f.success:
                result = "VULNERABLE"
            else:
                result = "Safe"
            lines.append(
                f"{f.attack_id:<12} {f.owasp_category:<10} {f.name[:50]:<50} "
                f"{f.severity!s:<10} {result:<12} {f.judge_error or ''}"
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

        # CWE / CVSS mapping grouped by category
        seen_mapping: set[str] = set()
        mapping_lines: list[str] = []
        for f in report.findings:
            if f.owasp_category not in seen_mapping and (f.cwe_ids or f.cvss_vector):
                seen_mapping.add(f.owasp_category)
                cwe_str = ", ".join(f.cwe_ids)
                mapping_lines.append(
                    f"{f.owasp_category}: {cwe_str} | CVSS {f.cvss_score:.1f} ({f.cvss_vector})"
                )

        if mapping_lines:
            lines += ["", "-" * 100, "CWE / CVSS MAPPING", "-" * 100]
            lines += mapping_lines

        return "\n".join(lines) + "\n"
