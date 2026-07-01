from __future__ import annotations

import json
from pathlib import Path

from llm_scanner.reporters.trend import TrendReporter


def write_report_json(
    directory: Path,
    timestamp: str,
    risk_score: float,
    target: str,
) -> None:
    """Write a minimal valid report.json into directory.

    Matches the ScanReport output structure (must have 'timestamp', 'risk_score',
    'target' keys — additional keys like 'findings' can be empty list).
    """
    directory.mkdir(parents=True, exist_ok=True)
    report = {
        "timestamp": timestamp,
        "risk_score": risk_score,
        "target": target,
        "findings": [],
    }
    (directory / "report.json").write_text(json.dumps(report), encoding="utf-8")


def test_trend_reporter_creates_index(tmp_path: Path) -> None:
    """TrendReporter().save(output_dir) must create output_dir/index.html."""
    reporter = TrendReporter()
    path = reporter.save(tmp_path)
    assert path == tmp_path / "index.html"
    assert path.exists()


def test_trend_reporter_no_scans(tmp_path: Path) -> None:
    """save() with no report.json files still creates index.html (empty chart)."""
    reporter = TrendReporter()
    path = reporter.save(tmp_path)
    assert path.exists()
    content = path.read_text()
    # Chart canvas must be present even with no data
    assert "trendChart" in content
    # Data arrays should be empty JSON arrays
    assert "[]" in content


def test_trend_reporter_with_two_scans(tmp_path: Path) -> None:
    """After writing two report.json files, index.html contains both risk scores."""
    write_report_json(tmp_path / "scan1", "2025-01-01T10:00:00", 3.0, "http://target1")
    write_report_json(tmp_path / "scan2", "2025-01-02T11:00:00", 7.5, "http://target2")
    reporter = TrendReporter()
    path = reporter.save(tmp_path)
    content = path.read_text()
    # Both risk scores must appear (injected via tojson)
    assert "3.0" in content
    assert "7.5" in content


def test_trend_skips_corrupt_json(tmp_path: Path) -> None:
    """Writing an invalid JSON file as report.json does not raise; index.html is produced."""
    subdir = tmp_path / "corrupt_scan"
    subdir.mkdir()
    (subdir / "report.json").write_text("{not valid json}", encoding="utf-8")
    reporter = TrendReporter()
    # Must not raise despite corrupt file
    path = reporter.save(tmp_path)
    assert path.exists()


def test_trend_history_sorted_by_timestamp(tmp_path: Path) -> None:
    """History from _collect_scan_history is sorted ascending by timestamp string."""
    # Write scan_b first (later timestamp), scan_a second (earlier timestamp)
    write_report_json(tmp_path / "scan_b", "2025-03-01T09:00:00", 5.0, "http://b")
    write_report_json(tmp_path / "scan_a", "2025-01-01T08:00:00", 2.0, "http://a")
    reporter = TrendReporter()
    history = reporter._collect_scan_history(tmp_path)
    timestamps = [h["timestamp"] for h in history]
    assert timestamps == sorted(timestamps), "History must be sorted ascending by timestamp"
    # Verify the earlier-timestamp scan comes first regardless of filesystem order
    assert history[0]["target"] == "http://a"
    assert history[1]["target"] == "http://b"


def test_trend_chart_data_structure(tmp_path: Path) -> None:
    """_collect_scan_history returns dicts with 'timestamp', 'risk_score', 'target' keys."""
    write_report_json(tmp_path / "scan1", "2025-06-01T12:00:00", 4.2, "http://example.com")
    reporter = TrendReporter()
    history = reporter._collect_scan_history(tmp_path)
    assert len(history) == 1
    entry = history[0]
    assert "timestamp" in entry
    assert "risk_score" in entry
    assert "target" in entry
    assert entry["risk_score"] == 4.2
    assert entry["target"] == "http://example.com"
    # Timestamp must be truncated to minute precision (ISO[:16])
    assert len(entry["timestamp"]) == 16
    assert entry["timestamp"] == "2025-06-01T12:00"
