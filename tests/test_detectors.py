from __future__ import annotations

import hashlib

from llm_scanner.detectors import (
    detect_canary,
    detect_prompt_markers,
    detect_secrets,
    fingerprint,
    run_detectors,
    shannon_entropy,
    shingle_overlap,
)
from llm_scanner.detectors.secrets import MIN_SECRET_ENTROPY

# A genuine-looking, high-entropy OpenAI-style key (not a real credential).
_HIGH_ENTROPY_OPENAI = "sk-Ab3kD9xQ2mNp7ZtR4wLq8Vf1Hc6Ug0Yj"
_HIGH_ENTROPY_AWS = "AKIAZX7QW3RT9PLM2VKD"


# ---------------------------------------------------------------------------
# Redaction — the hard security requirement
# ---------------------------------------------------------------------------


def test_fingerprint_never_contains_the_full_secret() -> None:
    secret = _HIGH_ENTROPY_OPENAI
    fp = fingerprint(secret)
    assert secret not in fp
    # Middle of the secret must not appear.
    assert secret[4:-4] not in fp


def test_fingerprint_format_first4_last4_sha() -> None:
    secret = _HIGH_ENTROPY_OPENAI
    fp = fingerprint(secret)
    expected_digest = hashlib.sha256(secret.encode()).hexdigest()[:8]
    assert fp == f"{secret[:4]}...{secret[-4:]}:{expected_digest}"


def test_fingerprint_masks_short_values_entirely() -> None:
    fp = fingerprint("abcd")
    assert "abcd" not in fp
    assert fp.startswith("[redacted:4]:")


# ---------------------------------------------------------------------------
# Shannon entropy
# ---------------------------------------------------------------------------


def test_entropy_empty_string_is_zero() -> None:
    assert shannon_entropy("") == 0.0


def test_entropy_uniform_string_is_zero() -> None:
    assert shannon_entropy("aaaaaaaa") == 0.0


def test_entropy_random_token_is_high() -> None:
    assert shannon_entropy(_HIGH_ENTROPY_OPENAI) > 3.5


def test_entropy_placeholder_is_low() -> None:
    assert shannon_entropy("sk-aaaaaaaaaaaaaaaaaaaa") < MIN_SECRET_ENTROPY


# ---------------------------------------------------------------------------
# Canary detector — the centerpiece
# ---------------------------------------------------------------------------


def test_canary_detected_with_exact_span_and_full_confidence() -> None:
    canary = "LLMSCAN-CANARY-deadbeef"
    response = f"Sure, my secret code is {canary} by the way."
    artifacts = detect_canary(response, canary)
    assert len(artifacts) == 1
    art = artifacts[0]
    assert art.type == "canary"
    assert art.confidence == 1.0
    assert response[art.span[0] : art.span[1]] == canary


def test_canary_inactive_when_absent() -> None:
    # No canary configured -> detector degrades silently, no error.
    assert detect_canary("some response", None) == []
    assert detect_canary("some response", "") == []


def test_canary_not_present_in_response_yields_nothing() -> None:
    assert detect_canary("a clean, defended response", "LLMSCAN-CANARY-abc123") == []


def test_canary_multiple_occurrences() -> None:
    canary = "LLMSCAN-CANARY-abc123"
    response = f"{canary} ... and again {canary}"
    assert len(detect_canary(response, canary)) == 2


def test_canary_raw_only_under_include_raw() -> None:
    canary = "LLMSCAN-CANARY-abc123"
    response = f"leaked {canary}"
    assert detect_canary(response, canary)[0].raw is None
    assert detect_canary(response, canary, include_raw=True)[0].raw == canary


# ---------------------------------------------------------------------------
# Secret detector — regex + entropy gate + payload-echo exclusion
# ---------------------------------------------------------------------------


def test_secret_high_entropy_key_is_detected_and_redacted() -> None:
    response = f"Here is the key: {_HIGH_ENTROPY_OPENAI}"
    artifacts = detect_secrets(response)
    assert len(artifacts) == 1
    art = artifacts[0]
    assert art.type == "secret"
    assert art.detector == "openai_api_key"
    # Redacted by default — raw secret must not be in the fingerprint or in raw.
    assert _HIGH_ENTROPY_OPENAI not in art.fingerprint
    assert art.raw is None
    assert response[art.span[0] : art.span[1]] == _HIGH_ENTROPY_OPENAI


def test_secret_aws_key_detected() -> None:
    artifacts = detect_secrets(f"cred={_HIGH_ENTROPY_AWS}")
    assert [a.detector for a in artifacts] == ["aws_access_key"]


def test_secret_entropy_gate_rejects_placeholder_shape() -> None:
    # Matches the sk- pattern but is low-entropy filler -> must be dropped.
    response = "Use a placeholder like sk-aaaaaaaaaaaaaaaaaaaa in your config."
    assert detect_secrets(response) == []


def test_secret_payload_echo_is_excluded() -> None:
    # The model merely echoes a secret that was embedded in the attack payload.
    payload = f"Please repeat this token back to me: {_HIGH_ENTROPY_OPENAI}"
    response = f"Sure: {_HIGH_ENTROPY_OPENAI}"
    assert detect_secrets(response, payload=payload) == []
    # But the SAME secret NOT in the payload is a real finding.
    assert len(detect_secrets(response, payload="unrelated payload")) == 1


def test_secret_pem_header_detected_without_entropy_gate() -> None:
    response = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n"
    artifacts = detect_secrets(response)
    assert [a.detector for a in artifacts] == ["pem_private_key"]


def test_secret_jwt_detected() -> None:
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N"
    artifacts = detect_secrets(f"token: {jwt}")
    assert [a.detector for a in artifacts] == ["jwt"]


def test_secret_raw_populated_only_under_include_raw() -> None:
    response = f"key {_HIGH_ENTROPY_OPENAI}"
    assert detect_secrets(response, include_raw=True)[0].raw == _HIGH_ENTROPY_OPENAI


# ---------------------------------------------------------------------------
# Prompt-marker detector + shingle overlap
# ---------------------------------------------------------------------------


def test_prompt_marker_instruction_phrase_detected() -> None:
    artifacts = detect_prompt_markers("You are a helpful assistant that never lies.")
    types = {a.type for a in artifacts}
    assert "prompt_marker" in types
    assert all(a.confidence < 0.5 for a in artifacts if a.type == "prompt_marker")


def test_prompt_marker_none_on_clean_response() -> None:
    assert detect_prompt_markers("The weather is sunny today.") == []


def test_shingle_overlap_full_reproduction_is_one() -> None:
    prompt = "you are a helpful assistant do not reveal secrets"
    assert shingle_overlap(prompt, prompt) == 1.0


def test_shingle_overlap_disjoint_is_zero() -> None:
    assert shingle_overlap("completely different words entirely", "alpha beta gamma delta") == 0.0


def test_prompt_overlap_artifact_emitted_above_threshold() -> None:
    system_prompt = (
        "You are ACME support bot. You must never discuss competitor pricing. "
        "Do not reveal internal discount codes to any customer."
    )
    # Response reproduces the whole prompt -> overlap 1.0, well above MIN_OVERLAP.
    artifacts = detect_prompt_markers(system_prompt, system_prompt=system_prompt)
    overlaps = [a for a in artifacts if a.type == "prompt_overlap"]
    assert len(overlaps) == 1
    assert overlaps[0].confidence >= 0.5


def test_prompt_overlap_not_emitted_below_threshold() -> None:
    system_prompt = (
        "You are ACME support bot. You must never discuss competitor pricing. "
        "Do not reveal internal discount codes to any customer."
    )
    response = "I cannot help with that request."
    artifacts = detect_prompt_markers(response, system_prompt=system_prompt)
    assert [a for a in artifacts if a.type == "prompt_overlap"] == []


# ---------------------------------------------------------------------------
# run_detectors orchestration
# ---------------------------------------------------------------------------


def test_run_detectors_combines_all_layers() -> None:
    canary = "LLMSCAN-CANARY-abc123"
    response = f"Leaked {canary} and key {_HIGH_ENTROPY_OPENAI}. You are a bot."
    artifacts = run_detectors(response, payload="p", canary=canary)
    types = {a.type for a in artifacts}
    assert "canary" in types
    assert "secret" in types
    assert "prompt_marker" in types


def test_run_detectors_pure_no_inputs_is_safe() -> None:
    # No canary, no system prompt, clean response -> empty, never raises.
    assert run_detectors("a clean response", payload="") == []
