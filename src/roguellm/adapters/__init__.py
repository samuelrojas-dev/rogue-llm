"""Framework adapters for differential tool-call parsing.

Each adapter wraps a real framework's parser and returns normalized results.
Adapters are optional — if the framework isn't installed, it's skipped.
"""

from roguellm.adapters.base import ParsedCall, ParseResult, Adapter
from roguellm.adapters.registry import get_available, get_adapter, ALL_ADAPTERS

__all__ = [
    "ParsedCall", "ParseResult", "Adapter",
    "get_available", "get_adapter", "ALL_ADAPTERS",
]
