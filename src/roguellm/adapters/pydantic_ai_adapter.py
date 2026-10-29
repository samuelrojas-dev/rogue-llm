"""Adapter for Pydantic-AI tool call parsing.

Pydantic-AI (pydantic_ai) has its own response handling that builds
on the openai SDK but with additional validation layers.
"""

from __future__ import annotations

import json

from roguellm.adapters.base import Adapter, ParsedCall, ParseResult


class PydanticAIAdapter(Adapter):
    name = "pydantic-ai"

    def available(self) -> bool:
        try:
            import pydantic_ai  # noqa: F401
            return True
        except ImportError:
            return False

    @property
    def version(self) -> str:
        try:
            import pydantic_ai
            return getattr(pydantic_ai, "__version__", "unknown")
        except ImportError:
            return "not installed"

    def parse(self, raw_json: str) -> ParseResult:
        # Pydantic-AI uses the openai SDK under the hood for OpenAI models.
        # We test its specific response conversion path.
        try:
            from pydantic_ai.models.openai import OpenAIModel  # noqa: F401
            from openai.types.chat import ChatCompletion
        except ImportError:
            return ParseResult(
                adapter=self.name, calls=[],
                error="pydantic-ai or openai not installed",
            )

        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError as e:
            return ParseResult(adapter=self.name, calls=[], error=f"JSONDecodeError: {e}")

        calls = []
        warnings = []
        try:
            completion = ChatCompletion.model_validate(data)
            choice = completion.choices[0] if completion.choices else None
            if not choice:
                return ParseResult(adapter=self.name, calls=[], warnings=["no choices"])

            tool_calls = choice.message.tool_calls
            if not tool_calls:
                return ParseResult(adapter=self.name, calls=[], warnings=["no tool_calls"])

            for tc in tool_calls:
                raw_args = tc.function.arguments
                args: dict | str | None = raw_args
                if isinstance(raw_args, str):
                    try:
                        args = json.loads(raw_args)
                    except json.JSONDecodeError:
                        warnings.append(f"Bad arguments for {tc.function.name}")
                        args = raw_args

                calls.append(ParsedCall(
                    name=tc.function.name,
                    arguments=args,
                    id=tc.id,
                ))
        except Exception as e:
            return ParseResult(adapter=self.name, calls=calls, error=str(e))

        return ParseResult(adapter=self.name, calls=calls, warnings=warnings)
