"""Adapter for LangChain / LangGraph tool call parsing.

LangChain uses langchain_core.messages.AIMessage to represent assistant
responses with tool calls. The OpenAI integration converts raw API responses
through _convert_dict_to_message.
"""

from __future__ import annotations

import json

from roguellm.adapters.base import Adapter, ParsedCall, ParseResult


class LangChainAdapter(Adapter):
    name = "langchain"

    def available(self) -> bool:
        try:
            import langchain_core  # noqa: F401
            return True
        except ImportError:
            return False

    @property
    def version(self) -> str:
        try:
            import langchain_core
            return langchain_core.__version__
        except (ImportError, AttributeError):
            return "not installed"

    def parse(self, raw_json: str) -> ParseResult:
        try:
            from langchain_core.messages import AIMessage
        except ImportError:
            return ParseResult(
                adapter=self.name, calls=[],
                error="langchain-core not installed",
            )

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

            msg_data = choices[0].get("message", {})
            raw_tool_calls = msg_data.get("tool_calls")

            # LangChain constructs AIMessage from the raw dict
            # Simulate what langchain_openai.ChatOpenAI does
            tool_calls_for_lc = []
            invalid_tool_calls = []

            if raw_tool_calls:
                for tc in raw_tool_calls:
                    fn = tc.get("function", {})
                    raw_args = fn.get("arguments", "")
                    tc_name = fn.get("name", "")
                    tc_id = tc.get("id", "")

                    try:
                        parsed_args = json.loads(raw_args) if isinstance(raw_args, str) and raw_args else {}
                        if not isinstance(parsed_args, dict):
                            parsed_args = {}
                        tool_calls_for_lc.append({
                            "name": tc_name,
                            "args": parsed_args,
                            "id": tc_id,
                            "type": "tool_call",
                        })
                    except (json.JSONDecodeError, TypeError):
                        invalid_tool_calls.append({
                            "name": tc_name,
                            "args": raw_args,
                            "id": tc_id,
                            "error": "Malformed args",
                            "type": "invalid_tool_call",
                        })

            if invalid_tool_calls:
                warnings.append(
                    f"{len(invalid_tool_calls)} invalid tool call(s) — "
                    "LangChain puts these in invalid_tool_calls, not tool_calls"
                )

            # Build the AIMessage as LangChain would
            ai_msg = AIMessage(
                content=msg_data.get("content", "") or "",
                tool_calls=tool_calls_for_lc,
                invalid_tool_calls=invalid_tool_calls,
            )

            # Extract what LangChain considers valid tool calls
            for tc in ai_msg.tool_calls:
                calls.append(ParsedCall(
                    name=tc.get("name"),
                    arguments=tc.get("args", {}),
                    id=tc.get("id"),
                ))

        except Exception as e:
            return ParseResult(adapter=self.name, calls=calls, error=str(e))

        return ParseResult(
            adapter=self.name, calls=calls, warnings=warnings,
            raw_output=str({"tool_calls": len(calls), "invalid": len(invalid_tool_calls)}),
        )
