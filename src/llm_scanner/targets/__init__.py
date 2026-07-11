from __future__ import annotations

from llm_scanner.targets.base import AbstractTarget, TargetError
from llm_scanner.targets.http import HttpTarget
from llm_scanner.targets.ollama_target import OllamaTarget


class TargetFactory:
    """Instantiates the correct AbstractTarget implementation from CLI config."""

    @staticmethod
    def from_config(
        target_type: str,
        target: str,
        api_key: str | None = None,
        ollama_host: str = "http://localhost:11434",
        timeout: float = 30.0,
        retries: int = 2,
        system_prompt: str | None = None,
    ) -> AbstractTarget:
        """Instantiate the correct target implementation.

        Args:
            target_type: "url" or "ollama"
            target: URL (for "url") or Ollama model name (for "ollama")
            api_key: Optional Bearer token (URL targets only)
            timeout: Read timeout in seconds
            retries: Retry attempts on transient errors (URL targets only)
            system_prompt: Optional system prompt for Ollama targets (used to auto-inject
                a canary token). Ignored for URL targets — we do not control a remote
                application's system prompt and must not pretend to.

        Returns:
            An AbstractTarget instance ready to receive send() calls.

        Raises:
            ValueError: if target_type is not "url" or "ollama"
        """
        match target_type:
            case "url":
                return HttpTarget(url=target, api_key=api_key, timeout=timeout, retries=retries)
            case "ollama":
                return OllamaTarget(
                    model=target,
                    host=ollama_host,
                    timeout=timeout,
                    system_prompt=system_prompt,
                )
            case _:
                raise ValueError(
                    f"Unknown target_type: {target_type!r}. Expected 'url' or 'ollama'."
                )


__all__ = ["AbstractTarget", "TargetError", "TargetFactory"]
