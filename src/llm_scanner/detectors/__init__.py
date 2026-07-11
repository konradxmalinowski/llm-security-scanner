from __future__ import annotations

from llm_scanner.detectors.canary import detect_canary
from llm_scanner.detectors.entropy import shannon_entropy
from llm_scanner.detectors.prompt_markers import detect_prompt_markers, shingle_overlap
from llm_scanner.detectors.redaction import fingerprint
from llm_scanner.detectors.secrets import detect_secrets
from llm_scanner.models import Artifact

__all__ = [
    "detect_canary",
    "detect_prompt_markers",
    "detect_secrets",
    "fingerprint",
    "run_detectors",
    "shannon_entropy",
    "shingle_overlap",
]


def run_detectors(
    response: str,
    *,
    payload: str = "",
    canary: str | None = None,
    system_prompt: str | None = None,
    include_raw: bool = False,
) -> list[Artifact]:
    """Run every deterministic detector over a single target response and return the
    combined artifact list.

    Pure and synchronous: zero I/O, zero LLM calls. Any detector for which no input is
    available (no canary, no system prompt) degrades silently to producing nothing.
    """
    artifacts: list[Artifact] = []
    artifacts.extend(detect_canary(response, canary, include_raw=include_raw))
    artifacts.extend(detect_secrets(response, payload=payload, include_raw=include_raw))
    artifacts.extend(
        detect_prompt_markers(response, system_prompt=system_prompt, include_raw=include_raw)
    )
    return artifacts
