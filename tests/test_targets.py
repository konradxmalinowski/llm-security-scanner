from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import ollama
import pytest

from llm_scanner.targets import AbstractTarget, TargetFactory
from llm_scanner.targets.base import TargetError
from llm_scanner.targets.http import HttpTarget
from llm_scanner.targets.ollama_target import OllamaTarget

# asyncio_mode = "auto" is set in pyproject.toml — no @pytest.mark.asyncio needed


# ---------------------------------------------------------------------------
# HttpTarget tests (TARGET-01)
# ---------------------------------------------------------------------------


async def test_http_target_sends_with_auth(mock_httpx_client: AsyncMock) -> None:
    with patch("llm_scanner.targets.http.httpx.AsyncClient", return_value=mock_httpx_client):
        target = HttpTarget(url="http://example.com/chat", api_key="secret")
        result = await target.send("hello")
    assert result == "mocked response"
    mock_httpx_client.post.assert_called_once()
    call_kwargs = mock_httpx_client.post.call_args
    assert call_kwargs[1]["json"] == {"prompt": "hello"}


async def test_http_target_sends_without_auth(mock_httpx_client: AsyncMock) -> None:
    with patch("llm_scanner.targets.http.httpx.AsyncClient", return_value=mock_httpx_client):
        target = HttpTarget(url="http://example.com/chat")
        await target.send("hello")
    call_kwargs = mock_httpx_client.post.call_args
    # No Authorization header set at construction time; verify json body is correct
    assert call_kwargs[1]["json"] == {"prompt": "hello"}


async def test_http_target_raises_on_timeout(mock_httpx_client: AsyncMock) -> None:
    mock_httpx_client.post.side_effect = httpx.ReadTimeout("timed out", request=MagicMock())
    with patch("llm_scanner.targets.http.httpx.AsyncClient", return_value=mock_httpx_client):
        target = HttpTarget(url="http://example.com/chat")
        with pytest.raises(TargetError, match="timed out"):
            await target.send("hello")


async def test_http_target_raises_on_5xx(
    mock_httpx_client: AsyncMock, mock_httpx_response: MagicMock
) -> None:
    mock_httpx_response.raise_for_status.side_effect = httpx.HTTPStatusError(
        "error",
        request=MagicMock(),
        response=MagicMock(status_code=500, text="server error"),
    )
    with patch("llm_scanner.targets.http.httpx.AsyncClient", return_value=mock_httpx_client):
        target = HttpTarget(url="http://example.com/chat")
        with pytest.raises(TargetError, match="HTTP 500"):
            await target.send("hello")


async def test_http_target_raises_on_connect_error(mock_httpx_client: AsyncMock) -> None:
    mock_httpx_client.post.side_effect = httpx.ConnectError("refused")
    with patch("llm_scanner.targets.http.httpx.AsyncClient", return_value=mock_httpx_client):
        target = HttpTarget(url="http://example.com/chat")
        with pytest.raises(TargetError, match="Connection failed"):
            await target.send("hello")


# ---------------------------------------------------------------------------
# OllamaTarget tests (TARGET-02, TARGET-04)
# ---------------------------------------------------------------------------


async def test_ollama_target_calls_chat(mock_ollama_client: AsyncMock) -> None:
    with patch(
        "llm_scanner.targets.ollama_target.ollama.AsyncClient",
        return_value=mock_ollama_client,
    ):
        target = OllamaTarget(model="llama3.2:3b")
        result = await target.send("test prompt")
    assert result == '{"success": false, "reasoning": "test"}'
    mock_ollama_client.chat.assert_called_once()
    call_kwargs = mock_ollama_client.chat.call_args
    assert call_kwargs[1]["model"] == "llama3.2:3b"


async def test_ollama_target_raises_on_response_error(mock_ollama_client: AsyncMock) -> None:
    mock_ollama_client.chat.side_effect = ollama.ResponseError(
        "model not found", status_code=404
    )
    with patch(
        "llm_scanner.targets.ollama_target.ollama.AsyncClient",
        return_value=mock_ollama_client,
    ):
        target = OllamaTarget(model="llama3.2:3b")
        with pytest.raises(TargetError, match="Ollama error"):
            await target.send("hello")


async def test_ollama_target_raises_on_connection_error(mock_ollama_client: AsyncMock) -> None:
    mock_ollama_client.chat.side_effect = ConnectionError("daemon not running")
    with patch(
        "llm_scanner.targets.ollama_target.ollama.AsyncClient",
        return_value=mock_ollama_client,
    ):
        target = OllamaTarget(model="llama3.2:3b")
        with pytest.raises(TargetError, match="not reachable"):
            await target.send("hello")


async def test_ollama_target_fresh_messages(mock_ollama_client: AsyncMock) -> None:
    """TARGET-04: each send() call passes a fresh single-item messages list."""
    with patch(
        "llm_scanner.targets.ollama_target.ollama.AsyncClient",
        return_value=mock_ollama_client,
    ):
        target = OllamaTarget(model="llama3.2:3b")
        await target.send("first prompt")
        await target.send("second prompt")
    # Each call must have passed a fresh single-item messages list
    for call in mock_ollama_client.chat.call_args_list:
        messages = call[1]["messages"]
        assert len(messages) == 1, "messages must not accumulate across send() calls"


# ---------------------------------------------------------------------------
# Interface compliance (TARGET-03)
# ---------------------------------------------------------------------------


def test_target_interface_compliance() -> None:
    assert issubclass(HttpTarget, AbstractTarget)
    assert issubclass(OllamaTarget, AbstractTarget)
    http = HttpTarget(url="http://x.com")
    ollama_t = OllamaTarget(model="x")
    assert isinstance(http, AbstractTarget)
    assert isinstance(ollama_t, AbstractTarget)


# ---------------------------------------------------------------------------
# TargetFactory tests (TargetFactory.from_config())
# ---------------------------------------------------------------------------


def test_factory_creates_http_target() -> None:
    result = TargetFactory.from_config("url", "http://example.com")
    assert isinstance(result, HttpTarget)


def test_factory_creates_ollama_target() -> None:
    result = TargetFactory.from_config(
        "ollama",
        "llama3.2:3b",
        ollama_host="http://ollama:11434",
    )
    assert isinstance(result, OllamaTarget)


def test_factory_passes_ollama_host() -> None:
    with patch("llm_scanner.targets.ollama_target.ollama.AsyncClient") as mock_client:
        TargetFactory.from_config(
            "ollama",
            "llama3.2:3b",
            ollama_host="http://ollama:11434",
        )
    mock_client.assert_called_once_with(host="http://ollama:11434", timeout=30.0)


def test_factory_raises_on_unknown_type() -> None:
    with pytest.raises(ValueError, match="Unknown target_type"):
        TargetFactory.from_config("grpc", "localhost:50051")
