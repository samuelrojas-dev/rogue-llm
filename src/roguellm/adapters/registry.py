"""Adapter registry — discovers which frameworks are installed."""

from __future__ import annotations

from roguellm.adapters.base import Adapter
from roguellm.adapters.stdlib_adapter import StdlibAdapter
from roguellm.adapters.openai_adapter import OpenAIAdapter
from roguellm.adapters.langchain_adapter import LangChainAdapter
from roguellm.adapters.litellm_adapter import LiteLLMAdapter
from roguellm.adapters.pydantic_ai_adapter import PydanticAIAdapter


ALL_ADAPTERS: list[type[Adapter]] = [
    StdlibAdapter,
    OpenAIAdapter,
    LangChainAdapter,
    LiteLLMAdapter,
    PydanticAIAdapter,
]


def get_available() -> list[Adapter]:
    """Return instances of all adapters whose frameworks are installed."""
    available = []
    for cls in ALL_ADAPTERS:
        adapter = cls()
        if adapter.available():
            available.append(adapter)
    return available


def get_adapter(name: str) -> Adapter | None:
    """Get a specific adapter by name."""
    for cls in ALL_ADAPTERS:
        adapter = cls()
        if adapter.name == name:
            return adapter if adapter.available() else None
    return None
