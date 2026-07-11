from __future__ import annotations

from pathlib import Path

from llm_scanner.models import Artifact, Outcome, ScanReport, VerdictSource


def _artifact_line(artifact: Artifact) -> str:
    """One-line summary of a deterministic artifact.

    Renders the REDACTED ``fingerprint`` only -- never ``artifact.raw``. A report file
    lands in CI logs, so transcribing a live secret here would turn the scanner into the
    leak vector it is meant to detect.
    """
    start, end = artifact.span
    return (
        f"- {artifact.type}/{artifact.detector} {artifact.fingerprint} "
        f"span=[{start}:{end}] conf={artifact.confidence:.2f}"
    )


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
            f"{'ID':<12} {'Category':<10} {'Name':<40} {'Severity':<10} "
            f"{'Result':<20} {'Conf':<6} {'Source':<16} {'Judge Error'}",
            "-" * 130,
        ]
        for f in report.findings:
            is_conflict = f.verdict_source == VerdictSource.CONFLICT
            # ERROR first: a finding the judge never evaluated must never print as "Safe".
            if f.outcome is Outcome.ERROR:
                result = "ERROR"
            elif is_conflict:
                result = "VULNERABLE (CONFLICT)"
            elif f.success:
                result = "VULNERABLE"
            else:
                result = "Safe"
            lines.append(
                f"{f.attack_id:<12} {f.owasp_category:<10} {f.name[:40]:<40} "
                f"{f.severity!s:<10} {result:<20} {f.confidence:<6.2f} "
                f"{f.verdict_source or '':<16} {f.judge_error or ''}"
            )

        # Per-finding detail: judge reasoning, confidence source, and the deterministic
        # artifacts (redacted). Absent entirely before Phase 3 of the reporting plan.
        lines += ["", "-" * 100, "FINDING DETAILS", "-" * 100]
        for f in report.findings:
            lines.append(f"{f.attack_id} [{f.owasp_category}] {f.name}")
            lines.append(
                f"  Outcome: {f.outcome.value}  Confidence: {f.confidence:.2f}  "
                f"Source: {f.verdict_source or 'n/a'}"
            )
            if f.verdict_source == VerdictSource.CONFLICT:
                lines.append(
                    "  CONFLICT: a deterministic detector fired but the judge disagreed "
                    "-- review manually."
                )
            lines.append(f"  Judge reasoning: {f.judge_reasoning or '(none)'}")
            if f.judge_error:
                lines.append(f"  Judge error: {f.judge_error}")
            if f.artifacts:
                lines.append(f"  Artifacts ({len(f.artifacts)}):")
                lines += [f"    {_artifact_line(a)}" for a in f.artifacts]

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
