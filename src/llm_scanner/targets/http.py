from __future__ import annotations

import httpx

from llm_scanner.targets.base import AbstractTarget, TargetError


class HttpTarget(AbstractTarget):
    """AbstractTarget implementation that sends POST requests to an HTTP endpoint."""

    def __init__(
        self,
        url: str,
        api_key: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        headers: dict[str, str] = {}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        # One client per scan; connection pool reused across attacks
        # timeout is the default for all; connect overridden to 5.0 (fast connect, slow read)
        self._client = httpx.AsyncClient(
            headers=headers,
            timeout=httpx.Timeout(timeout, connect=5.0),
        )
        self._url = url

    async def send(self, prompt: str) -> str:
        """Send prompt via HTTP POST. Returns raw text response.

        Raises:
            TargetError: on timeout, HTTP error status, or connection failure.
        """
        try:
            resp = await self._client.post(self._url, json={"prompt": prompt})
            resp.raise_for_status()
            data = resp.json()
            # Accept both {"response": "..."} and {"message": "..."} response shapes
            return data.get("response") or data.get("message") or resp.text
        except httpx.TimeoutException as exc:
            raise TargetError(
                f"Request timed out after {self._client.timeout.read}s"
            ) from exc
        except httpx.HTTPStatusError as exc:
            raise TargetError(
                f"HTTP {exc.response.status_code}: {exc.response.text[:200]}"
            ) from exc
        except httpx.RequestError as exc:
            raise TargetError(f"Connection failed: {exc}") from exc

    async def close(self) -> None:
        """Close the underlying httpx client and release connections."""
        await self._client.aclose()
