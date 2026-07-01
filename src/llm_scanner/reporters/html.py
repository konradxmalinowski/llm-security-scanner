from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from llm_scanner.models import ScanReport

# Templates live at src/llm_scanner/templates/ — two levels up from this file
_TEMPLATES_DIR = Path(__file__).parent.parent / "templates"


class HtmlReporter:
    """Save scan results as an HTML file via Jinja2 (REPORT-04).

    autoescape=True is mandatory: attack payloads may contain <script> tags and HTML
    injection strings; the browser must display them as literal text, not execute them.
    Ruff S701 flags autoescape=False as a security violation.
    """

    def __init__(self) -> None:
        self._env = Environment(
            loader=FileSystemLoader(str(_TEMPLATES_DIR)),
            autoescape=True,
        )

    def save(self, report: ScanReport, output_dir: Path) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / "report.html"
        template = self._env.get_template("report.html.j2")
        html = template.render(report=report)
        path.write_text(html, encoding="utf-8")
        return path
