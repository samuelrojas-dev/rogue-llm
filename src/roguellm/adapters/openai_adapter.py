"""Adapter for the OpenAI Python SDK (openai >= 1.0).

Uses openai.types.chat.ChatCompletion.model_validate() which runs Pydantic
validation on the raw response dict. This is what the official openai SDK does.
"""

from __future__ import annotations

import json

from roguellm.adapters.base import Adapter, ParsedCall, ParseResult


class OpenAIAdapter(Adapter):
    name = "openai-sdk"

    def available(self) -> bool:
        try:
            import openai  # noqa: F401
            return True
        except ImportError:
            return False

    @property
    def version(self) -> str:
        try:
            import openai
            return openai.__version__
        except ImportError:
            return "not installed"

    def parse(self, raw_json: str) -> ParseResult:
        try:
            import openai.types.chat as chat_types
        except ImportError:
            return ParseResult(
                adapter=self.name, calls=[],
                error="openai package not installed",
            )

        try:
            # Parse JSON first (duplicate keys resolved by json.loads: last wins)
            data = json.loads(raw_json)
        except json.JSONDecodeError as e:
            return ParseResult(adapter=self.name, calls=[], error=f"JSONDecodeError: {e}")

        try:
            completion = chat_types.ChatCompletion.model_validate(data)
        except Exception as e:
            return ParseResult(
                adapter=self.name, calls=[],
                error=f"Pydantic validation: {type(e).__name__}: {e}",
            )

        calls = []
        warnings = []
        try:
            choice = completion.choices[0] if completion.choices else None
            if not choice:
                return ParseResult(adapter=self.name, calls=[], warnings=["no choices"])

            tool_calls = choice.message.tool_calls
            if not tool_calls:
                return ParseResult(adapter=self.name, calls=[], warnings=["no tool_calls"])

            for tc in tool_calls:
                args: dict | str | None = tc.function.arguments
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except json.JSONDecodeError:
                        warnings.append(f"Bad arguments JSON for {tc.function.name}")
                        args = tc.function.arguments

                calls.append(ParsedCall(
                    name=tc.function.name,
                    arguments=args,
                    id=tc.id,
                ))
        except Exception as e:
            return ParseResult(adapter=self.name, calls=calls, error=str(e))

        return ParseResult(
            adapter=self.name, calls=calls, warnings=warnings,
            raw_output=str(completion),
        )
