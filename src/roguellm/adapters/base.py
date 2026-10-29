"""Base adapter interface and shared types."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ParsedCall:
    """A single tool call as extracted by a framework's parser."""
    name: str | None
    arguments: dict | str | None  # dict if parsed, str if raw, None if missing
    id: str | None = None

    def normalized(self) -> tuple[str | None, dict | None]:
        """Return (name, arguments_as_dict) for comparison."""
        args = self.arguments
        if isinstance(args, str):
            import json
            try:
                args = json.loads(args)
            except (json.JSONDecodeError, TypeError):
                args = None
        return (self.name, args if isinstance(args, dict) else None)


@dataclass
class ParseResult:
    """What a framework's parser produced from a raw response."""
    adapter: str                          # adapter name
    calls: list[ParsedCall]               # extracted tool calls
    error: str | None = None              # if the parser raised an exception
    raw_output: str | None = None         # the framework's raw representation
    warnings: list[str] = field(default_factory=list)

    @property
    def outcome(self) -> str:
        """Summarize what happened: 'error', 'no_calls', or 'N calls'."""
        if self.error:
            return "error"
        if not self.calls:
            return "no_calls"
        return f"{len(self.calls)} calls"

    def call_summary(self) -> list[tuple[str | None, dict | None]]:
        """Normalized list of (name, args) for divergence comparison."""
        return [c.normalized() for c in self.calls]


class Adapter(ABC):
    """Base class for framework adapters."""

    name: str = "base"
    version: str = "unknown"

    @abstractmethod
    def parse(self, raw_json: str) -> ParseResult:
        """Parse a raw OpenAI-format JSON response and return extracted tool calls."""
        ...

    def available(self) -> bool:
        """Check if this framework is installed and importable."""
        return True

    def __repr__(self) -> str:
        return f"{self.name} ({self.version})"
