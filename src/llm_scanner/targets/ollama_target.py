from __future__ import annotations

import ollama

from llm_scanner.targets.base import AbstractTarget, TargetError


class OllamaTarget(AbstractTarget):
    """AbstractTarget implementation that sends prompts to a local Ollama model."""

    def __init__(
        self,
        model: str,
        host: str = "http://localhost:11434",
        timeout: float = 60.0,
        system_prompt: str | None = None,
    ) -> None:
        # Dedicated client; separate from judge's client (TARGET-02)
        self._client = ollama.AsyncClient(host=host, timeout=timeout)
        self._model = model
        # Optional system prompt the scanner controls end to end. This is where a canary
        # token is auto-injected for Ollama targets: because we own the system prompt, a
        # canary appearing in a response is provable system-prompt leakage.
        self._system_prompt = system_prompt

    async def send(self, prompt: str) -> str:
        """Send prompt to local Ollama model. Returns raw text response.

        Each call constructs a fresh messages list — no history bleeds between
        attacks (TARGET-04 isolation guarantee). When a system prompt is configured it is
        prepended on every call (still a fresh list, so isolation holds).

        Raises:
            TargetError: on Ollama HTTP error, connection failure, or unexpected error.
        """
        try:
            # CRITICAL: fresh list literal every call — TARGET-04 isolation guarantee
            messages: list[dict[str, str]] = []
            if self._system_prompt:
                messages.append({"role": "system", "content": self._system_prompt})
            messages.append({"role": "user", "content": prompt})
            resp = await self._client.chat(
                model=self._model,
                messages=messages,
            )
            return resp.message.content or ""
        except ollama.ResponseError as exc:
            raise TargetError(
                f"Ollama error ({exc.status_code}): {exc.error}"
            ) from exc
        except ConnectionError as exc:
            # Ollama SDK wraps httpx.ConnectError → Python built-in ConnectionError
            raise TargetError("Ollama is not running or not reachable") from exc
        except Exception as exc:  # BLE001 not enabled in ruff config; broad catch needed for httpx timeout
            # httpx.TimeoutException propagates uncaught through the ollama SDK
            raise TargetError(f"Unexpected target error: {exc}") from exc
