from __future__ import annotations

from llm_scanner.detectors.canary import detect_canary
from llm_scanner.detectors.entropy import shannon_entropy
from llm_scanner.detectors.prompt_markers import detect_prompt_markers, shingle_overlap
from llm_scanner.detectors.redaction import (
    fingerprint,
    generate_fingerprint_key,
    redact_response,
    redact_values_in_text,
)
from llm_scanner.detectors.secrets import detect_secrets
from llm_scanner.models import Artifact

__all__ = [
    "MAX_DETECTOR_INPUT_CHARS",
    "detect_canary",
    "detect_prompt_markers",
    "detect_secrets",
    "fingerprint",
    "generate_fingerprint_key",
    "redact_response",
    "redact_values_in_text",
    "run_detectors",
    "shannon_entropy",
    "shingle_overlap",
]

# Upper bound on how many characters of a target response are fed to the regex/shingle
# detectors. A target the operator chose to test could stream a multi-megabyte response;
# capping the SCANNED text bounds worst-case detection cost (six finditer passes plus
# shingle-set construction) without affecting the stored/displayed response, which is never
# truncated. Because the cap keeps a prefix, every detected span's offsets remain valid
# against the full response used for redaction downstream. No catastrophic-backtracking
# pattern exists; this is a belt-and-suspenders bound on input size.
MAX_DETECTOR_INPUT_CHARS = 100_000


def run_detectors(
    response: str,
    *,
    payload: str = "",
    canary: str | None = None,
    system_prompt: str | None = None,
    include_raw: bool = False,
    key: bytes | None = None,
) -> list[Artifact]:
    """Run every deterministic detector over a single target response and return the
    combined artifact list.

    Pure and synchronous: zero I/O, zero LLM calls. Any detector for which no input is
    available (no canary, no system prompt) degrades silently to producing nothing.

    ``key`` is the per-run fingerprint key (see generate_fingerprint_key); it is threaded to
    every detector so redacted fingerprints cannot be dictionary-confirmed offline. Detectors
    stay pure -- the key is passed in, never generated as global state.
    """
    scanned = response[:MAX_DETECTOR_INPUT_CHARS]
    artifacts: list[Artifact] = []
    artifacts.extend(detect_canary(scanned, canary, include_raw=include_raw, key=key))
    artifacts.extend(
        detect_secrets(scanned, payload=payload, include_raw=include_raw, key=key)
    )
    artifacts.extend(
        detect_prompt_markers(
            scanned, system_prompt=system_prompt, include_raw=include_raw, key=key
        )
    )
    return artifacts
