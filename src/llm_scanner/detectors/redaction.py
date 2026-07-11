from __future__ import annotations

import hashlib

__all__ = ["fingerprint"]


def fingerprint(value: str) -> str:
    """Return a redacted, non-reversible stand-in for a detected secret.

    Format: ``first4...last4:sha256(value)[:8]``. This is a HARD security requirement:
    scan reports (HTML/JSON/SARIF) are published as CI artifacts and pasted into logs,
    so a detector that transcribed a live secret into its output would itself become the
    leak vector. Only the fingerprint is ever written to a report unless the operator
    explicitly opts in with --include-raw-artifacts.

    The first4/last4 window gives a human just enough to correlate a finding with a known
    key without disclosing it; the sha256 prefix disambiguates two secrets that happen to
    share those eight characters. For pathologically short values (<= 8 chars) the
    first4/last4 windows would overlap and reveal the whole string, so those are masked
    entirely — real credentials matched by the secret detector are always far longer.
    """
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]
    if len(value) <= 8:
        return f"[redacted:{len(value)}]:{digest}"
    return f"{value[:4]}...{value[-4:]}:{digest}"
