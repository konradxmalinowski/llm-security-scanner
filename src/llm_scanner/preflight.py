from __future__ import annotations

import sys
from typing import TYPE_CHECKING

import httpx
import ollama

if TYPE_CHECKING:
    from llm_scanner.judge import OllamaJudge


def check_ollama_running(host: str = "http://localhost:11434") -> None:
    """Verify Ollama daemon is running. Exits with error message if not."""
    try:
        resp = httpx.get(f"{host}/api/version", timeout=3.0)
        resp.raise_for_status()
    except (httpx.ConnectError, httpx.TimeoutException, ConnectionError):
        print(
            f"[ERROR] Ollama is not running at {host}.\n"
            "Start it with: ollama serve",
            file=sys.stderr,
        )
        sys.exit(1)
    except httpx.HTTPStatusError as exc:
        print(
            f"[ERROR] Ollama returned HTTP {exc.response.status_code} at {host}.",
            file=sys.stderr,
        )
        sys.exit(1)


def check_model_available(model: str, host: str = "http://localhost:11434") -> None:
    """Verify an Ollama model is pulled. Exits with error message if not."""
    client = ollama.Client(host=host)
    try:
        client.show(model)
    except ollama.ResponseError as exc:
        if exc.status_code == 404:
            print(
                f"[ERROR] Model '{model}' is not available.\n"
                f"Pull it first: ollama pull {model}",
                file=sys.stderr,
            )
            sys.exit(1)
        print(f"[ERROR] Ollama error checking model '{model}': {exc.error}", file=sys.stderr)
        sys.exit(1)
    except ConnectionError:
        print(
            f"[ERROR] Cannot connect to Ollama at {host} to verify model '{model}'.",
            file=sys.stderr,
        )
        sys.exit(1)


def check_http_target_reachable(url: str, api_key: str | None = None) -> None:
    """Verify HTTP target responds. Exits with error message if unreachable.

    HTTP 401 and 403 are allowed — they indicate the server is up but requires auth.
    HTTP 5xx responses are treated as failures.
    The api_key value is never included in error output.
    """
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    try:
        resp = httpx.head(url, headers=headers, timeout=httpx.Timeout(10.0, connect=5.0))
        if resp.status_code == 404:
            print(
                f"[ERROR] HTTP target at {url} returned 404 Not Found.\n"
                "Verify the endpoint path is correct.",
                file=sys.stderr,
            )
            sys.exit(1)
        if resp.status_code >= 500:
            print(
                f"[ERROR] HTTP target at {url} returned server error {resp.status_code}.",
                file=sys.stderr,
            )
            sys.exit(1)
    except (httpx.ConnectError, httpx.TimeoutException) as exc:
        print(f"[ERROR] HTTP target at {url} is not reachable: {exc}", file=sys.stderr)
        sys.exit(1)


def check_judge_differs_from_target(
    target_type: str, target: str, judge_model: str
) -> None:
    """Enforce judge model differs from target model (conflict-of-interest check).

    Only applies when target_type == 'ollama'. URL targets are never evaluated
    for model conflict because a URL cannot be the same as a model name.
    """
    if target_type == "ollama" and target == judge_model:
        print(
            f"[ERROR] Judge model and target model cannot be the same ('{judge_model}').\n"
            "Specify a different judge model with --judge-model.",
            file=sys.stderr,
        )
        sys.exit(1)


async def warm_up_judge(judge: OllamaJudge) -> None:
    """Force Ollama to load the judge model into VRAM before the scan starts.

    Creates a dummy payload and calls evaluate() once. The result is discarded.
    This prevents a cold-start timeout on the first real attack evaluation.
    """
    from llm_scanner.models import Payload, Severity

    dummy = Payload(
        id="WARMUP",
        name="warm-up",
        category="WARMUP",
        severity=Severity.INFO,
        payload="Hi",
        judge_criteria="respond with success: false",
    )
    await judge.evaluate(dummy, "Hi")
    # Result is discarded — only the model loading matters
