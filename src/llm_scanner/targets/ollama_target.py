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
    ) -> None:
        # Dedicated client; separate from judge's client (TARGET-02)
        self._client = ollama.AsyncClient(host=host, timeout=timeout)
        self._model = model

    async def send(self, prompt: str) -> str:
        """Send prompt to local Ollama model. Returns raw text response.

        Each call constructs a fresh messages list — no history bleeds between
        attacks (TARGET-04 isolation guarantee).

        Raises:
            TargetError: on Ollama HTTP error, connection failure, or unexpected error.
        """
        try:
            # CRITICAL: fresh list literal every call — TARGET-04 isolation guarantee
            resp = await self._client.chat(
                model=self._model,
                messages=[{"role": "user", "content": prompt}],
            )
            return resp.message.content or ""
        except ollama.ResponseError as exc:
            raise TargetError(
                f"Ollama error ({exc.status_code}): {exc.error}"
            ) from exc
        except ConnectionError as exc:
            # Ollama SDK wraps httpx.ConnectError → Python built-in ConnectionError
            raise TargetError("Ollama is not running or not reachable") from exc
        except Exception as exc:  # noqa: BLE001
            # httpx.TimeoutException propagates uncaught through the ollama SDK
            raise TargetError(f"Unexpected target error: {exc}") from exc
