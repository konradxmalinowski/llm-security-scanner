import pytest
from pathlib import Path

# asyncio_mode = "auto" is set in pyproject.toml [tool.pytest.ini_options]
# No @pytest.mark.asyncio decorator needed on individual tests


@pytest.fixture
def payload_dir() -> Path:
    """Return path to real payloads/ directory for integration-style loader tests."""
    return Path(__file__).parent.parent / "payloads"
