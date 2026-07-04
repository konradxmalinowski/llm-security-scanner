from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path

import pytest

import llm_scanner.cli as cli_module
from llm_scanner.models import Payload, ScanReport, Severity
from llm_scanner.observability import JsonFormatter, configure_logging, get_logger
from llm_scanner.targets.base import AbstractTarget

# asyncio_mode = "auto" is set in pyproject.toml — no @pytest.mark.asyncio needed


@pytest.fixture(autouse=True)
def _reset_logger() -> None:
    """Ensure each test starts from a clean "llm_scanner" logger state."""
    logger = logging.getLogger("llm_scanner")
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()
    yield
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()


def test_get_logger_returns_namespaced_logger() -> None:
    logger = get_logger()
    assert logger.name == "llm_scanner"


def test_json_formatter_produces_valid_parseable_json() -> None:
    formatter = JsonFormatter()
    record = logging.LogRecord(
        name="llm_scanner",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="scan completed",
        args=(),
        exc_info=None,
    )
    record.scan_id = "abc123"
    record.event = "scan_completed"

    line = formatter.format(record)
    data = json.loads(line)

    assert data["message"] == "scan completed"
    assert data["level"] == "INFO"
    assert data["logger"] == "llm_scanner"
    assert "timestamp" in data
    assert data["scan_id"] == "abc123"
    assert data["event"] == "scan_completed"


def test_json_formatter_merges_extra_fields_only() -> None:
    """Standard LogRecord attributes (pathname, lineno, etc.) must not leak into the payload."""
    formatter = JsonFormatter()
    record = logging.LogRecord(
        name="llm_scanner",
        level=logging.DEBUG,
        pathname=__file__,
        lineno=42,
        msg="attack completed",
        args=(),
        exc_info=None,
    )
    record.attack_id = "LLM01-001"
    data = json.loads(formatter.format(record))

    assert data["attack_id"] == "LLM01-001"
    assert "pathname" not in data
    assert "lineno" not in data
    assert "msg" not in data


def test_configure_logging_writes_json_lines_to_log_file(tmp_path: Path) -> None:
    log_file = tmp_path / "scan.log.jsonl"
    configure_logging("INFO", log_file)
    logger = get_logger()

    logger.info("scan completed", extra={"event": "scan_completed", "scan_id": "xyz"})
    for handler in logger.handlers:
        handler.flush()

    lines = log_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    data = json.loads(lines[0])
    assert data["event"] == "scan_completed"
    assert data["scan_id"] == "xyz"


def test_configure_logging_respects_level_filter_debug_suppressed(tmp_path: Path) -> None:
    log_file = tmp_path / "scan.log.jsonl"
    configure_logging("INFO", log_file)
    logger = get_logger()

    logger.debug("attack completed", extra={"event": "attack_completed"})
    for handler in logger.handlers:
        handler.flush()

    content = log_file.read_text(encoding="utf-8") if log_file.exists() else ""
    assert content == ""


def test_configure_logging_allows_debug_when_level_is_debug(tmp_path: Path) -> None:
    log_file = tmp_path / "scan.log.jsonl"
    configure_logging("DEBUG", log_file)
    logger = get_logger()

    logger.debug("attack completed", extra={"event": "attack_completed"})
    for handler in logger.handlers:
        handler.flush()

    lines = log_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    data = json.loads(lines[0])
    assert data["event"] == "attack_completed"


def test_configure_logging_without_log_file_has_no_file_handler() -> None:
    configure_logging("INFO", None)
    logger = get_logger()

    assert not any(isinstance(h, logging.FileHandler) for h in logger.handlers)
    assert any(isinstance(h, logging.StreamHandler) for h in logger.handlers)


def test_configure_logging_is_idempotent_no_handler_accumulation(tmp_path: Path) -> None:
    log_file = tmp_path / "scan.log.jsonl"
    configure_logging("INFO", log_file)
    configure_logging("INFO", log_file)
    configure_logging("INFO", log_file)

    logger = get_logger()
    stream_handlers = [h for h in logger.handlers if type(h) is logging.StreamHandler]
    file_handlers = [h for h in logger.handlers if isinstance(h, logging.FileHandler)]
    assert len(stream_handlers) == 1
    assert len(file_handlers) == 1


# ---------------------------------------------------------------------------
# Audit trail append behavior -- mirrors the cli.py `<output_dir>/audit.jsonl`
# convention: append one JSON line per completed scan, never overwrite.
# ---------------------------------------------------------------------------


def _append_audit_line(output_dir: Path, record: dict) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    with (output_dir / "audit.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")


def test_audit_trail_appends_across_multiple_scans(tmp_path: Path) -> None:
    for i in range(3):
        _append_audit_line(
            tmp_path,
            {
                "timestamp": f"2026-07-0{i + 1}T00:00:00+00:00",
                "scan_id": f"scan{i}",
                "target": "http://example.com",
                "target_type": "url",
                "judge_model": "llama3.2:3b",
                "categories": ["LLM01"],
                "total_attacks": 1,
                "successful_attacks": 0,
                "risk_score": 0.0,
                "formats_saved": ["json"],
                "duration_s": 1.23,
            },
        )

    audit_file = tmp_path / "audit.jsonl"
    lines = audit_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 3

    records = [json.loads(line) for line in lines]
    assert [r["scan_id"] for r in records] == ["scan0", "scan1", "scan2"]
    for record in records:
        assert set(record.keys()) == {
            "timestamp",
            "scan_id",
            "target",
            "target_type",
            "judge_model",
            "categories",
            "total_attacks",
            "successful_attacks",
            "risk_score",
            "formats_saved",
            "duration_s",
        }


# ---------------------------------------------------------------------------
# metrics.json shape
# ---------------------------------------------------------------------------


def test_metrics_json_has_expected_shape(tmp_path: Path) -> None:
    metrics = {
        "total_attacks": 5,
        "successful_attacks": 2,
        "total_duration_s": 3.4567,
        "avg_target_latency_s": 0.5,
        "avg_judge_latency_s": 0.8,
        "risk_score": 6.5,
    }
    scan_dir = tmp_path / "20260704T000000_example"
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")

    loaded = json.loads((scan_dir / "metrics.json").read_text(encoding="utf-8"))
    assert set(loaded.keys()) == {
        "total_attacks",
        "successful_attacks",
        "total_duration_s",
        "avg_target_latency_s",
        "avg_judge_latency_s",
        "risk_score",
    }
    assert loaded["total_attacks"] == 5
    assert loaded["successful_attacks"] == 2
    assert isinstance(loaded["risk_score"], float)


# ---------------------------------------------------------------------------
# End-to-end: cli._run() writes metrics.json and appends to audit.jsonl
# ---------------------------------------------------------------------------


class _FakeTarget(AbstractTarget):
    async def send(self, prompt: str) -> str:
        return "ok"


class _RecordingScanner:
    """Stands in for LLMScanner: records constructor kwargs, exposes last_metrics
    like the real scanner does after scan() completes."""

    def __init__(self, **kwargs: object) -> None:
        self.kwargs = kwargs
        self.last_metrics: dict[str, float | int] = {}

    async def scan(self) -> ScanReport:
        self.last_metrics = {
            "total_attacks": 1,
            "successful_attacks": 1,
            "total_duration_s": 0.42,
            "avg_target_latency_s": 0.1,
            "avg_judge_latency_s": 0.2,
            "risk_score": 2.5,
        }
        return ScanReport(
            target="http://example.com/chat",
            timestamp=datetime(2026, 7, 4, tzinfo=UTC),
            risk_score=2.5,
            findings=[],
        )


class _FakeLoader:
    def __init__(self, *_args: object, **_kwargs: object) -> None:
        pass

    def load(self, **_kwargs: object) -> list[Payload]:
        return [
            Payload(
                id="LLM01-001",
                name="Test",
                category="LLM01",
                severity=Severity.HIGH,
                payload="hi",
                judge_criteria="crit",
            )
        ]


def _patch_run_dependencies(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_module, "check_ollama_running", lambda *a, **k: None)
    monkeypatch.setattr(cli_module, "check_model_available", lambda *a, **k: None)
    monkeypatch.setattr(cli_module, "check_judge_differs_from_target", lambda *a, **k: None)
    monkeypatch.setattr(cli_module, "check_http_target_reachable", lambda *a, **k: None)

    async def _fake_warm_up(_judge: object) -> None:
        return None

    monkeypatch.setattr(cli_module, "warm_up_judge", _fake_warm_up)
    monkeypatch.setattr(cli_module, "YamlPayloadLoader", _FakeLoader)
    monkeypatch.setattr(cli_module.TargetFactory, "from_config", lambda **kw: _FakeTarget())
    monkeypatch.setattr(cli_module, "OllamaJudge", lambda **kw: object())
    monkeypatch.setattr(cli_module, "LLMScanner", _RecordingScanner)


async def test_run_writes_metrics_json_with_expected_shape(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_run_dependencies(monkeypatch)

    args = cli_module._build_parser().parse_args(
        [
            "--target", "http://example.com/chat",
            "--target-type", "url",
            "--judge-model", "llama3.2:3b",
        ]
    )
    args.output_dir = tmp_path
    args.formats = ""

    await cli_module._run(args)

    metrics_files = list(tmp_path.rglob("metrics.json"))
    assert len(metrics_files) == 1
    data = json.loads(metrics_files[0].read_text(encoding="utf-8"))
    assert set(data.keys()) == {
        "total_attacks",
        "successful_attacks",
        "total_duration_s",
        "avg_target_latency_s",
        "avg_judge_latency_s",
        "risk_score",
    }
    assert data["total_attacks"] == 1
    assert data["risk_score"] == 2.5


async def test_run_appends_audit_jsonl_across_multiple_scans(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_run_dependencies(monkeypatch)

    for _ in range(2):
        args = cli_module._build_parser().parse_args(
            [
                "--target", "http://example.com/chat",
                "--target-type", "url",
                "--judge-model", "llama3.2:3b",
            ]
        )
        args.output_dir = tmp_path
        args.formats = ""
        await cli_module._run(args)

    audit_file = tmp_path / "audit.jsonl"
    lines = audit_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2

    records = [json.loads(line) for line in lines]
    for record in records:
        assert set(record.keys()) == {
            "timestamp",
            "scan_id",
            "target",
            "target_type",
            "judge_model",
            "categories",
            "total_attacks",
            "successful_attacks",
            "risk_score",
            "formats_saved",
            "duration_s",
        }
        assert record["target"] == "http://example.com/chat"
        assert record["risk_score"] == 2.5
    # Each scan gets its own correlation id.
    assert records[0]["scan_id"] != records[1]["scan_id"]


async def test_run_passes_scan_id_to_scanner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, object] = {}

    class _CapturingScanner(_RecordingScanner):
        def __init__(self, **kwargs: object) -> None:
            super().__init__(**kwargs)
            captured.update(kwargs)

    _patch_run_dependencies(monkeypatch)
    monkeypatch.setattr(cli_module, "LLMScanner", _CapturingScanner)

    args = cli_module._build_parser().parse_args(
        [
            "--target", "http://example.com/chat",
            "--target-type", "url",
            "--judge-model", "llama3.2:3b",
        ]
    )
    args.output_dir = tmp_path
    args.formats = ""

    await cli_module._run(args)

    audit_file = tmp_path / "audit.jsonl"
    record = json.loads(audit_file.read_text(encoding="utf-8").strip())

    assert "scan_id" in captured
    assert captured["scan_id"] == record["scan_id"]
    assert len(captured["scan_id"]) == 12
