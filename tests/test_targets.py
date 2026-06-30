from __future__ import annotations

import pytest
from pydantic import ValidationError


# --- RED phase stubs: verify <behavior> assertions from Task 1 ---
# These tests import from modules that do not exist yet.
# All tests below MUST fail with ImportError or ModuleNotFoundError until
# Task 1 (GREEN) creates the implementation files.


def test_judge_result_error_default_is_none() -> None:
    from llm_scanner.models import JudgeResult  # noqa: PLC0415

    jr = JudgeResult(success=True, reasoning="ok")
    assert jr.error is None


def test_judge_result_raw_response_empty_string() -> None:
    from llm_scanner.models import JudgeResult  # noqa: PLC0415

    jr = JudgeResult(success=False, reasoning="", error="judge_timeout", raw_response="")
    assert jr.raw_response == ""


def test_judge_result_extra_field_raises() -> None:
    from llm_scanner.models import JudgeResult  # noqa: PLC0415

    with pytest.raises(ValidationError):
        JudgeResult(success=True, reasoning="", extra_field="x")  # type: ignore[call-arg]


def test_factory_raises_on_unknown_type() -> None:
    from llm_scanner.targets import TargetFactory  # noqa: PLC0415

    with pytest.raises(ValueError, match="Unknown target_type"):
        TargetFactory.from_config("grpc", "localhost:50051")


def test_target_interface_compliance() -> None:
    from llm_scanner.targets import AbstractTarget  # noqa: PLC0415
    from llm_scanner.targets.http import HttpTarget  # noqa: PLC0415
    from llm_scanner.targets.ollama_target import OllamaTarget  # noqa: PLC0415

    assert issubclass(HttpTarget, AbstractTarget)
    assert issubclass(OllamaTarget, AbstractTarget)
    http = HttpTarget(url="http://x.com")
    ollama_t = OllamaTarget(model="x")
    assert isinstance(http, AbstractTarget)
    assert isinstance(ollama_t, AbstractTarget)


def test_factory_creates_http_target() -> None:
    from llm_scanner.targets import TargetFactory  # noqa: PLC0415
    from llm_scanner.targets.http import HttpTarget  # noqa: PLC0415

    result = TargetFactory.from_config("url", "http://example.com")
    assert isinstance(result, HttpTarget)


def test_factory_creates_ollama_target() -> None:
    from llm_scanner.targets import TargetFactory  # noqa: PLC0415
    from llm_scanner.targets.ollama_target import OllamaTarget  # noqa: PLC0415

    result = TargetFactory.from_config("ollama", "llama3.2:3b")
    assert isinstance(result, OllamaTarget)
