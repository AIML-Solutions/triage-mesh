"""Model provider adapter.

Default is the deterministic mock so tests and the demo run with zero token
spend; MODEL_PROVIDER=anthropic switches the same code path onto real Claude
calls. Agents must not import SDKs directly — the harness owns model access.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod


class ModelProvider(ABC):
    @abstractmethod
    async def complete(self, system: str, prompt: str) -> str: ...


class MockProvider(ModelProvider):
    """Deterministic completions keyed on prompt shape; no network, no spend."""

    async def complete(self, system: str, prompt: str) -> str:
        if "exploitability" in prompt.lower():
            return (
                "Mock assessment: the pinned version falls inside the advisory's "
                "affected range; treat as exploitable until upgraded."
            )
        return "Mock summary: findings compiled from validated advisory data; see table."


class AnthropicProvider(ModelProvider):
    def __init__(self, model: str | None = None):
        import anthropic

        self._client = anthropic.AsyncAnthropic()
        self._model = model or os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-5")

    async def complete(self, system: str, prompt: str) -> str:
        response = await self._client.messages.create(
            model=self._model,
            max_tokens=1024,
            system=system,
            messages=[{"role": "user", "content": prompt}],
        )
        return "".join(block.text for block in response.content if block.type == "text")


def get_provider() -> ModelProvider:
    name = os.environ.get("MODEL_PROVIDER", "mock").lower()
    if name == "anthropic":
        return AnthropicProvider()
    if name == "mock":
        return MockProvider()
    raise ValueError(f"unknown MODEL_PROVIDER: {name!r}")
