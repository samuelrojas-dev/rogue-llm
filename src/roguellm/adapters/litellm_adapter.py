"""Adapter for LiteLLM response parsing.

LiteLLM wraps provider responses into its own ModelResponse object.
It has its own JSON repair logic and argument handling.
"""

from __future__ import annotations

import json

from roguellm.adapters.base import Adapter, ParsedCall, ParseResult


class LiteLLMAdapter(Adapter):
    name = "litellm"

    def available(self) -> bool:
        try:
            import litellm  # noqa: F401
            return True
        except ImportError:
            return False

    @property
    def version(self) -> str:
        try:
            from importlib.metadata import version
            return version("litellm")
        except Exception:
            return "not installed"

    def parse(self, raw_json: str) -> ParseResult:
        try:
            from litellm.types.utils import ModelResponse
        except ImportError:
            return ParseResult(
                adapter=self.name, calls=[],
                error="litellm not installed",
            )

        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError as e:
            return ParseResult(adapter=self.name, calls=[], error=f"JSONDecodeError: {e}")

        calls = []
        warnings = []
        try:
            response = ModelResponse(**data)
            choice = response.choices[0] if response.choices else None
            if not choice:
                return ParseResult(adapter=self.name, calls=[], warnings=["no choices"])

            msg = choice.message
            if not hasattr(msg, "tool_calls") or not msg.tool_calls:
                return ParseResult(adapter=self.name, calls=[], warnings=["no tool_calls"])

            for tc in msg.tool_calls:
                fn = tc.function
                raw_args = fn.arguments if fn else ""
                name = fn.name if fn else None

                args: dict | str | None = raw_args
                if isinstance(raw_args, str):
                    try:
                        args = json.loads(raw_args) if raw_args else {}
                    except json.JSONDecodeError:
                        warnings.append(f"Bad arguments for {name}: {raw_args[:50]}")
                        args = raw_args

                calls.append(ParsedCall(name=name, arguments=args, id=tc.id))

        except Exception as e:
            return ParseResult(adapter=self.name, calls=calls, error=str(e))

        return ParseResult(
            adapter=self.name, calls=calls, warnings=warnings,
            raw_output=str(response) if 'response' in dir() else None,
        )
