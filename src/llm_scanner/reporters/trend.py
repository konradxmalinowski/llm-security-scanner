from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

# Templates live at src/llm_scanner/templates/ — two levels up from this file
_TEMPLATES_DIR = Path(__file__).parent.parent / "templates"


class TrendReporter:
    """Regenerate reports/index.html with a Risk Score trend chart after every scan (ADV-03).

    Reads all report.json files found recursively under output_dir, extracts timestamp
    and risk_score from each, and renders index.html.j2 with Chart.js data.

    autoescape=True is mandatory: scan targets and timestamps are user-controlled strings
    that could contain HTML characters. Ruff S701 flags autoescape=False as a security
    violation.

    Data is embedded in <script> blocks exclusively via {{ variable | tojson }} — never
    via | safe — which HTML-escapes < > & and returns Markup (no double-escape with
    autoescape=True).
    """

    def __init__(self) -> None:
        self._env = Environment(
            loader=FileSystemLoader(str(_TEMPLATES_DIR)),
            autoescape=True,
        )

    def _collect_scan_history(self, output_dir: Path) -> list[dict]:
        """Walk output_dir for all report.json files, extract timestamp + risk_score.

        Corrupt or partial files are skipped silently — index.html is always generated.
        Results are sorted ascending by timestamp string (ISO format sorts lexicographically).
        """
        history = []
        for json_file in sorted(output_dir.rglob("report.json")):
            try:
                data = json.loads(json_file.read_text())
                history.append(
                    {
                        "timestamp": data["timestamp"][:16],  # ISO date+time, trim seconds
                        "risk_score": data["risk_score"],
                        "target": data.get("target", "unknown"),
                    }
                )
            except (json.JSONDecodeError, KeyError, ValueError):
                continue  # corrupt or partial file — skip silently
        return sorted(history, key=lambda h: h["timestamp"])

    def save(self, output_dir: Path) -> Path:
        """Render index.html into output_dir and return the path.

        Creates output_dir if it does not exist. Always produces index.html even when
        no historical report.json files are found (empty chart).
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        history = self._collect_scan_history(output_dir)
        chart_data = {
            "labels": [h["timestamp"] for h in history],
            "scores": [h["risk_score"] for h in history],
            "targets": [h["target"] for h in history],
        }
        template = self._env.get_template("index.html.j2")
        html = template.render(chart_data=chart_data, scan_count=len(history))
        path = output_dir / "index.html"
        path.write_text(html, encoding="utf-8")
        return path
