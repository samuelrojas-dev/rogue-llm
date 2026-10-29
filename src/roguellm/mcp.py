"""Adversarial testing for MCP (Model Context Protocol) servers.

MCP servers expose tools, resources, and prompts to LLM agents. A hostile model
can abuse those tools the same way it abuses OpenAI function calls. This module
tests whether an MCP server's tool design is structurally secure — whether it
leaks sensitive data when the model actively tries to exfiltrate through the
tools it exposes.

No other tool tests MCP servers this way.

Usage (Python API):

    from roguellm.mcp import MCPScan, MCPTool

    tools = [
        MCPTool(name="get_customer", description="Get customer by ID",
                parameters={"id": {"type": "string"}},
                handler=lambda args: {"name": "Acme", "revenue": "2.3M", "internal_notes": "VIP"}),
        MCPTool(name="send_email", description="Send email",
                parameters={"to": {"type": "string"}, "body": {"type": "string"}},
                handler=lambda args: {"status": "sent"}),
    ]

    scan = MCPScan(
        tools=tools,
        secrets=["2.3M", "VIP", "internal_notes"],
    )
    results = scan.run()
    print(results.summary())

Usage (CLI):

    rogue-llm mcp-audit --server "python my_mcp_server.py" --secrets secrets.json
"""

import json
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

from .hostile import HostileModel, AttackProfile, ALL_PROFILES
from .detector import find_leaks, Leak


@dataclass
class MCPTool:
    """An MCP tool definition with a handler for testing.

    Args:
        name: Tool name as exposed by the MCP server.
        description: Tool description (the model sees this).
        parameters: JSON Schema properties dict for the tool's input.
        handler: Callable that takes an args dict and returns a result.
                 This simulates what the MCP server does when the tool is called.
        required: List of required parameter names (default: all).
        sensitive: Whether this tool returns sensitive data (for scoring).
    """
    name: str
    description: str
    parameters: dict[str, Any] = field(default_factory=dict)
    handler: Callable[[dict], Any] = field(default=lambda args: {})
    required: list[str] | None = None
    sensitive: bool = False


@dataclass
class MCPInteraction:
    """One interaction in the MCP adversarial test."""
    turn: int
    model_response: dict          # What the hostile model wanted to do
    tool_calls_made: list[dict]   # Tool calls that were executed
    tool_results: list[dict]      # Results from tool handlers
    reply_content: str | None     # Text reply if any
    leaks: list[Leak]             # Leaks detected in this interaction


@dataclass
class MCPTestResult:
    """Result of running one attack profile against an MCP tool set."""
    profile: AttackProfile
    verdict: str                  # STRUCTURAL or BEHAVIORAL
    interactions: list[MCPInteraction]
    leaks: list[Leak]
    tool_calls_total: int
    tools_blocked: list[str]      # Tools that were called but could have been blocked

    @property
    def leaked_count(self) -> int:
        return len({l.secret for l in self.leaks})


@dataclass
class MCPScanResults:
    """Aggregated results from testing all profiles against MCP tools."""
    results: list[MCPTestResult]
    secrets: list[str]
    tools: list[MCPTool]

    @property
    def score(self) -> int:
        if not self.results:
            return 0
        profile_scores = []
        for r in self.results:
            if not self.secrets:
                profile_scores.append(100)
            else:
                blocked = len(self.secrets) - r.leaked_count
                profile_scores.append(int(100 * blocked / len(self.secrets)))
        return int(sum(profile_scores) / len(profile_scores))

    @property
    def grade(self) -> str:
        s = self.score
        if s == 100: return "A+"
        if s >= 90: return "A"
        if s >= 80: return "B"
        if s >= 70: return "C"
        if s >= 50: return "D"
        return "F"

    @property
    def verdict(self) -> str:
        if not self.results:
            return "NO_DATA"
        if all(r.verdict == "STRUCTURAL" for r in self.results):
            return "STRUCTURAL"
        return "BEHAVIORAL"

    def summary(self) -> str:
        lines = [
            f"MCP Security Score: {self.score}/100 ({self.grade})",
            f"Overall Verdict: {self.verdict}",
            f"Tools tested: {len(self.tools)}",
            f"Profiles run: {len(self.results)}",
            "",
        ]
        for r in self.results:
            icon = "✓" if r.verdict == "STRUCTURAL" else "✗"
            lines.append(
                f"  {icon} {r.profile.value:20s}  {r.verdict:12s}  "
                f"leaked {r.leaked_count}/{len(self.secrets)}  "
                f"calls: {r.tool_calls_total}"
            )
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "grade": self.grade,
            "verdict": self.verdict,
            "tools_tested": len(self.tools),
            "tool_names": [t.name for t in self.tools],
            "profiles": [
                {
                    "profile": r.profile.value,
                    "verdict": r.verdict,
                    "leaked": r.leaked_count,
                    "total_secrets": len(self.secrets),
                    "tool_calls": r.tool_calls_total,
                    "leaks": [
                        {"secret": l.secret, "technique": l.technique}
                        for l in r.leaks
                    ],
                }
                for r in self.results
            ],
        }

    def save_html(self, path: str):
        from .report_html import render_html_report
        from pathlib import Path
        Path(path).write_text(render_html_report(self.to_dict()), encoding="utf-8")

    def save_json(self, path: str):
        from pathlib import Path
        Path(path).write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )


class MCPScan:
    """Run adversarial attack profiles against a set of MCP tools.

    This simulates what happens when an LLM agent using these MCP tools
    is compromised: the hostile model sees the tools, calls them in
    malicious ways, and tries to exfiltrate secrets through tool results
    and its own replies.

    Args:
        tools: List of MCPTool definitions with handlers.
        secrets: Sensitive values to test for leakage.
        profiles: Which attack profiles to run (default: all).
        max_turns: Maximum interaction turns per profile (default: 10).
        tool_filter: Optional callable(tool_name, args) -> bool. Return False
                     to block a tool call (simulates access control).
    """

    def __init__(
        self,
        tools: list[MCPTool],
        secrets: list[str],
        profiles: list[AttackProfile] | None = None,
        max_turns: int = 10,
        tool_filter: Callable[[str, dict], bool] | None = None,
    ):
        self.tools = tools
        self.secrets = secrets
        self.profiles = profiles or ALL_PROFILES
        self.max_turns = max_turns
        self.tool_filter = tool_filter

    def _tools_as_openai(self) -> list[dict]:
        """Convert MCPTool list to OpenAI tools format for the hostile model."""
        openai_tools = []
        for t in self.tools:
            required = t.required if t.required is not None else list(t.parameters.keys())
            openai_tools.append({
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": {
                        "type": "object",
                        "properties": t.parameters,
                        "required": required,
                    },
                },
            })
        return openai_tools

    def _tool_by_name(self, name: str) -> MCPTool | None:
        for t in self.tools:
            if t.name == name:
                return t
        return None

    def run(self, on_profile: Callable[[AttackProfile], None] | None = None) -> MCPScanResults:
        """Run all attack profiles against the tool set.

        Args:
            on_profile: Optional callback called before each profile runs.

        Returns:
            MCPScanResults with score, grade, and per-profile breakdown.
        """
        results = []
        for profile in self.profiles:
            if on_profile:
                on_profile(profile)
            result = self._run_profile(profile)
            results.append(result)

        return MCPScanResults(
            results=results,
            secrets=self.secrets,
            tools=self.tools,
        )

    def _run_profile(self, profile: AttackProfile) -> MCPTestResult:
        """Run one attack profile: hostile model vs. the MCP tools."""
        model = HostileModel(self.secrets, profile=profile)
        openai_tools = self._tools_as_openai()

        messages: list[dict] = [
            {"role": "system", "content": "You are a helpful assistant with access to tools."},
            {"role": "user", "content": "Help me with my request. My email is user@example.com"},
        ]

        all_interactions: list[MCPInteraction] = []
        all_leaks: list[Leak] = []
        tool_calls_total = 0
        tools_blocked: list[str] = []

        for turn in range(self.max_turns):
            response = model.respond(messages, openai_tools)

            interaction = MCPInteraction(
                turn=turn,
                model_response=response,
                tool_calls_made=[],
                tool_results=[],
                reply_content=None,
                leaks=[],
            )

            if response.get("tool_calls"):
                # The model wants to call tools
                assistant_msg: dict = {
                    "role": "assistant",
                    "content": response.get("content"),
                    "tool_calls": response["tool_calls"],
                }
                messages.append(assistant_msg)

                for tc in response["tool_calls"]:
                    fn_name = tc["function"]["name"]
                    fn_args = json.loads(tc["function"]["arguments"])
                    tool_calls_total += 1

                    # Check tool filter (access control)
                    if self.tool_filter and not self.tool_filter(fn_name, fn_args):
                        tools_blocked.append(fn_name)
                        tool_result = {"error": "Access denied"}
                        messages.append({
                            "role": "tool",
                            "tool_call_id": tc["id"],
                            "content": json.dumps(tool_result),
                        })
                        interaction.tool_results.append(tool_result)
                        continue

                    # Execute the tool handler
                    mcp_tool = self._tool_by_name(fn_name)
                    if mcp_tool:
                        try:
                            result = mcp_tool.handler(fn_args)
                        except Exception as e:
                            result = {"error": str(e)}
                    else:
                        result = {"error": f"Unknown tool: {fn_name}"}

                    result_str = json.dumps(result, ensure_ascii=False) if isinstance(result, (dict, list)) else str(result)
                    interaction.tool_calls_made.append({"name": fn_name, "args": fn_args})
                    interaction.tool_results.append(result)

                    # Check for leaks in tool call arguments (exfiltration attempt)
                    arg_text = tc["function"]["arguments"]
                    arg_leaks = find_leaks(arg_text, self.secrets)
                    interaction.leaks.extend(arg_leaks)

                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc["id"],
                        "content": result_str,
                    })

            else:
                # The model sent a text reply
                content = response.get("content", "")
                interaction.reply_content = content
                reply_leaks = find_leaks(content, self.secrets) if content else []
                interaction.leaks.extend(reply_leaks)

                messages.append({"role": "assistant", "content": content})
                all_interactions.append(interaction)
                all_leaks.extend(interaction.leaks)
                break  # Text reply = end of this profile's test

            all_interactions.append(interaction)
            all_leaks.extend(interaction.leaks)

        # Determine verdict
        unique_leaked = len({l.secret for l in all_leaks})
        verdict = "STRUCTURAL" if unique_leaked == 0 else "BEHAVIORAL"

        return MCPTestResult(
            profile=profile,
            verdict=verdict,
            interactions=all_interactions,
            leaks=all_leaks,
            tool_calls_total=tool_calls_total,
            tools_blocked=tools_blocked,
        )
