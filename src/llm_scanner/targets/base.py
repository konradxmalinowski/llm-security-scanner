from __future__ import annotations

from abc import ABC, abstractmethod


class TargetError(Exception):
    """Raised by AbstractTarget.send() on connection failure, timeout, or HTTP error."""


class AbstractTarget(ABC):
    """Single-method interface: send one prompt, return raw text response."""

    @abstractmethod
    async def send(self, prompt: str) -> str:
        """Send prompt to target. Returns raw text response.

        Raises:
            TargetError: on connection failure, timeout, or HTTP error.
        """
        ...

    async def __aenter__(self) -> AbstractTarget:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close()

    async def close(self) -> None:
        """Release any underlying connections. Override in subclasses."""
