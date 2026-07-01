from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import ollama
import pytest

from llm_scanner.models import JudgeResult
from llm_scanner.preflight import (
    check_http_target_reachable,
    check_judge_differs_from_target,
    check_model_available,
    check_ollama_running,
    warm_up_judge,
)

# ---------------------------------------------------------------------------
# check_ollama_running
# ---------------------------------------------------------------------------


def test_check_ollama_running_success() -> None:
    """When httpx.get returns 200, no SystemExit is raised."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.raise_for_status = MagicMock()
    with patch("llm_scanner.preflight.httpx.get", return_value=mock_resp):
        check_ollama_running()  # Must not raise


def test_check_ollama_running_connect_error(capsys: pytest.CaptureFixture[str]) -> None:
    """ConnectError triggers SystemExit(1) with 'ollama serve' hint in stderr."""
    with patch("llm_scanner.preflight.httpx.get", side_effect=httpx.ConnectError("refused")):
        with pytest.raises(SystemExit) as exc:
            check_ollama_running("http://localhost:11434")
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "ollama serve" in captured.err


def test_check_ollama_running_timeout(capsys: pytest.CaptureFixture[str]) -> None:
    """TimeoutException triggers SystemExit(1)."""
    with patch(
        "llm_scanner.preflight.httpx.get",
        side_effect=httpx.TimeoutException("timed out"),
    ):
        with pytest.raises(SystemExit) as exc:
            check_ollama_running()
    assert exc.value.code == 1


# ---------------------------------------------------------------------------
# check_model_available
# ---------------------------------------------------------------------------


def test_check_model_available_success() -> None:
    """When client.show() returns normally, no SystemExit is raised."""
    with patch("llm_scanner.preflight.ollama.Client") as mock_client_class:
        mock_instance = MagicMock()
        mock_client_class.return_value = mock_instance
        mock_instance.show.return_value = MagicMock()
        check_model_available("llama3.2:3b")  # Must not raise


def test_check_model_available_not_found(capsys: pytest.CaptureFixture[str]) -> None:
    """ResponseError(status_code=404) triggers SystemExit(1) with 'ollama pull' hint."""
    with patch("llm_scanner.preflight.ollama.Client") as mock_client_class:
        mock_instance = MagicMock()
        mock_client_class.return_value = mock_instance
        mock_instance.show.side_effect = ollama.ResponseError("not found", status_code=404)
        with pytest.raises(SystemExit) as exc:
            check_model_available("llama3.2:3b")
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "ollama pull" in captured.err
    assert "llama3.2:3b" in captured.err


def test_check_model_available_connection_error(capsys: pytest.CaptureFixture[str]) -> None:
    """ConnectionError from the client triggers SystemExit(1)."""
    with patch("llm_scanner.preflight.ollama.Client") as mock_client_class:
        mock_instance = MagicMock()
        mock_client_class.return_value = mock_instance
        mock_instance.show.side_effect = ConnectionError("not running")
        with pytest.raises(SystemExit) as exc:
            check_model_available("llama3.2:3b")
    assert exc.value.code == 1


# ---------------------------------------------------------------------------
# check_http_target_reachable
# ---------------------------------------------------------------------------


def test_check_http_target_reachable_success() -> None:
    """When httpx.head returns 200, no SystemExit is raised."""
    with patch(
        "llm_scanner.preflight.httpx.head",
        return_value=MagicMock(status_code=200),
    ):
        check_http_target_reachable("http://example.com")  # Must not raise


def test_check_http_target_reachable_401_ok() -> None:
    """HTTP 401 is allowed — server is up, just requires authentication."""
    with patch(
        "llm_scanner.preflight.httpx.head",
        return_value=MagicMock(status_code=401),
    ):
        check_http_target_reachable("http://example.com")  # Must not raise


def test_check_http_target_unreachable(capsys: pytest.CaptureFixture[str]) -> None:
    """ConnectError triggers SystemExit(1) with the url in stderr."""
    with patch(
        "llm_scanner.preflight.httpx.head",
        side_effect=httpx.ConnectError("refused"),
    ):
        with pytest.raises(SystemExit) as exc:
            check_http_target_reachable("http://example.com")
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "http://example.com" in captured.err


def test_check_http_target_server_error(capsys: pytest.CaptureFixture[str]) -> None:
    """HTTP 500 triggers SystemExit(1) with status code in stderr."""
    with patch(
        "llm_scanner.preflight.httpx.head",
        return_value=MagicMock(status_code=500),
    ):
        with pytest.raises(SystemExit) as exc:
            check_http_target_reachable("http://example.com")
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "500" in captured.err


# ---------------------------------------------------------------------------
# check_judge_differs_from_target
# ---------------------------------------------------------------------------


def test_check_judge_differs_same_model(capsys: pytest.CaptureFixture[str]) -> None:
    """Same ollama model as judge and target triggers SystemExit(1)."""
    with pytest.raises(SystemExit) as exc:
        check_judge_differs_from_target("ollama", "llama3.2:3b", "llama3.2:3b")
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "llama3.2:3b" in captured.err


def test_check_judge_differs_url_target() -> None:
    """URL targets are exempt from the conflict-of-interest check — no SystemExit."""
    check_judge_differs_from_target("url", "http://example.com/api", "llama3.2:3b")


def test_check_judge_differs_different_models() -> None:
    """Different ollama models — no SystemExit raised."""
    check_judge_differs_from_target("ollama", "phi3:mini", "llama3.2:3b")


# ---------------------------------------------------------------------------
# warm_up_judge
# ---------------------------------------------------------------------------


async def test_warm_up_judge_calls_evaluate() -> None:
    """warm_up_judge calls judge.evaluate() exactly once with a WARMUP payload."""
    mock_judge = AsyncMock()
    mock_judge.evaluate.return_value = JudgeResult(
        success=False,
        reasoning="",
        error=None,
        raw_response="warmup",
    )

    await warm_up_judge(mock_judge)

    assert mock_judge.evaluate.call_count == 1
    call_args = mock_judge.evaluate.call_args
    # First positional arg is the Payload
    payload_arg = call_args.args[0]
    assert payload_arg.id == "WARMUP"
