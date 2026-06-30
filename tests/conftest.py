from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

# asyncio_mode = "auto" is set in pyproject.toml [tool.pytest.ini_options]
# No @pytest.mark.asyncio decorator needed on individual tests


@pytest.fixture
def payload_dir() -> Path:
    """Return path to real payloads/ directory for integration-style loader tests."""
    return Path(__file__).parent.parent / "payloads"


@pytest.fixture
def mock_httpx_response() -> MagicMock:
    """Reusable mock HTTP response with default 200/JSON success shape."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"response": "mocked response"}
    mock_resp.text = "mocked response"
    mock_resp.raise_for_status = MagicMock()  # no-op by default
    return mock_resp


@pytest.fixture
def mock_httpx_client(mock_httpx_response: MagicMock) -> AsyncMock:
    """Mock httpx.AsyncClient for HttpTarget tests."""
    mock = AsyncMock()
    mock.post.return_value = mock_httpx_response
    mock.aclose = AsyncMock()
    return mock


@pytest.fixture
def mock_ollama_client() -> AsyncMock:
    """Mock ollama.AsyncClient for OllamaTarget and OllamaJudge tests."""
    mock = AsyncMock()
    mock.chat.return_value = MagicMock(
        message=MagicMock(content='{"success": false, "reasoning": "test"}')
    )
    return mock
