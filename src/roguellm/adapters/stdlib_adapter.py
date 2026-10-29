"""Baseline adapter: Python stdlib json.loads only.

This is the control. It shows what plain json.loads does with the raw response,
which is what most hand-rolled agents use. It's always available (no deps).
"""

from __future__ import annotations

import json

from roguellm.adapters.base import Adapter, ParsedCall, ParseResult


class StdlibAdapter(Adapter):
    name = "stdlib-json"
    version = json.__spec__.parent if hasattr(json, '__spec__') and json.__spec__ else "builtin"

    def available(self) -> bool:
        return True

    def parse(self, raw_json: str) -> ParseResult:
        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError as e:
            return ParseResult(adapter=self.name, calls=[], error=f"JSONDecodeError: {e}")

        calls = []
        warnings = []
        try:
            choices = data.get("choices", [])
            if not choices:
                return ParseResult(adapter=self.name, calls=[], warnings=["no choices"])

            msg = choices[0].get("message", {})
            tool_calls = msg.get("tool_calls")

            if tool_calls is None:
                return ParseResult(adapter=self.name, calls=[], warnings=["no tool_calls"])

            for tc in tool_calls:
                fn = tc.get("function", {})
                name = fn.get("name")
                raw_args = fn.get("arguments")

                # Try to parse arguments
                args: dict | str | None = raw_args
                if isinstance(raw_args, str):
                    try:
                        args = json.loads(raw_args)
                    except json.JSONDecodeError:
                        warnings.append(f"Bad arguments JSON for {name}: {raw_args[:50]}")
                        args = raw_args  # keep raw

                calls.append(ParsedCall(
                    name=name,
                    arguments=args,
                    id=tc.get("id"),
                ))

        except Exception as e:
            return ParseResult(adapter=self.name, calls=calls, error=str(e))

        return ParseResult(adapter=self.name, calls=calls, warnings=warnings)
