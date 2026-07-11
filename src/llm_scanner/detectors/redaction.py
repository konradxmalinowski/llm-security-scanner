from __future__ import annotations

import hashlib
import hmac
import secrets as _secrets

from llm_scanner.models import Artifact

__all__ = [
    "FULL_MASK_MAX_LEN",
    "fingerprint",
    "generate_fingerprint_key",
    "redact_response",
    "redact_values_in_text",
]

# Values this length or shorter are masked ENTIRELY (no first4/last4 window). Raised from
# the original 8 to 12: at length 12 a first4/last4 window already exposes 8 of 12
# characters, i.e. more than it hides. Masking everything up to 12 guarantees a fingerprint
# never reveals the majority of a short/low-entropy value.
FULL_MASK_MAX_LEN = 12

# Artifact types whose detected span is a live secret and must be scrubbed from any stored
# text. prompt_marker / prompt_overlap are instruction-shaped hints, not credentials, so
# they are deliberately left intact for the human reviewer.
_SECRET_ARTIFACT_TYPES = frozenset({"secret", "canary"})


def generate_fingerprint_key() -> bytes:
    """Return a fresh random key for per-run fingerprinting.

    Generated once per scan by the scanner and threaded into the detector run, so that two
    scans produce unrelated digests for the same value and an attacker holding a fingerprint
    cannot confirm a guessed secret against a precomputed sha256 table.
    """
    return _secrets.token_bytes(32)


def fingerprint(value: str, key: bytes | None = None) -> str:
    """Return a redacted stand-in for a detected value.

    Format: ``first4...last4:HMAC(value)[:8]`` for longer values, or
    ``[redacted:{len}]:HMAC(value)[:8]`` when the value is short enough that a first4/last4
    window would expose most of it (``len <= FULL_MASK_MAX_LEN``).

    Redaction is a hard requirement: reports (HTML/JSON/SARIF/markdown/text) are published
    as CI artifacts, so only the fingerprint -- never the raw value -- is written unless the
    operator opts in with --include-raw-artifacts.

    Guarantee (conditional on the caller): when *key* is a per-run random key (see
    :func:`generate_fingerprint_key`) AND the value is high-entropy and sufficiently long,
    the digest cannot be brute-forced against a precomputed table and the visible window
    discloses too little to reconstruct the value. That guarantee does NOT hold for
    arbitrary low-entropy or short inputs: callers that fingerprint operator-supplied or
    unbounded text (e.g. a canary of unknown length) rely on the full-mask branch, not on
    irreversibility of the digest. This is exactly why the secret detector independently
    enforces a minimum length and entropy before trusting a fingerprint to stand in for a
    credential. The keyless default (``key is None``) is deterministic and intended only for
    direct unit/tool calls; production scans always thread a per-run key.
    """
    digest = hmac.new(key or b"", value.encode("utf-8"), hashlib.sha256).hexdigest()[:8]
    if len(value) <= FULL_MASK_MAX_LEN:
        return f"[redacted:{len(value)}]:{digest}"
    return f"{value[:4]}...{value[-4:]}:{digest}"


def redact_response(response: str, artifacts: list[Artifact]) -> str:
    """Return *response* with every detected secret/canary span replaced by its fingerprint.

    Applied once at the scanner/model boundary so that ALL reporters inherit the redaction
    (the stored ``AttackResult.response`` is the single source every format serializes).

    Spans are applied by rebuilding the string from left-to-right segments, which is immune
    to the offset drift that in-place splicing would cause when a replacement changes length.
    Overlapping or adjacent secret spans are coalesced and never leave a raw byte of the
    covered region behind.
    """
    spans = sorted(
        (
            (max(0, a.span[0]), min(len(response), a.span[1]), a.fingerprint)
            for a in artifacts
            if a.type in _SECRET_ARTIFACT_TYPES
        ),
        key=lambda s: (s[0], s[1]),
    )
    if not spans:
        return response

    out: list[str] = []
    cursor = 0
    for start, end, fp in spans:
        if end <= start:
            continue
        if start >= cursor:
            out.append(response[cursor:start])
            out.append(f"[REDACTED:{fp}]")
            cursor = end
        elif end > cursor:
            # Overlaps a span already redacted: drop the raw tail so no covered byte of a
            # secret survives. Do not emit a second marker for the same region.
            cursor = end
    out.append(response[cursor:])
    return "".join(out)


def redact_values_in_text(text: str, response: str, artifacts: list[Artifact]) -> str:
    """Return *text* with any verbatim occurrence of a detected secret/canary value replaced
    by its fingerprint.

    Used to scrub the judge's free-form reasoning, which is copied verbatim into SARIF result
    messages (and surfaced by other formats). The raw values are read back out of *response*
    via each artifact's span -- available there even when --include-raw-artifacts is off -- so
    no separate cleartext store is required.
    """
    if not text:
        return text
    redacted = text
    for a in artifacts:
        if a.type not in _SECRET_ARTIFACT_TYPES:
            continue
        start, end = max(0, a.span[0]), min(len(response), a.span[1])
        raw_value = response[start:end]
        if raw_value:
            redacted = redacted.replace(raw_value, f"[REDACTED:{a.fingerprint}]")
    return redacted
