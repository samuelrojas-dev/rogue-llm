"""OpenAI-compatible HTTP server that runs the hostile model.

Point any agent at this server and it will actively try to exfiltrate your secrets.
The server implements the /v1/chat/completions endpoint, so it's a drop-in replacement
for the OpenAI API. It also logs all interactions and detects leaks in real time.

Usage:
    from roguellm.server import create_app
    app = create_app(secrets=["secret1", "secret2"])
    app.run(port=8642)
"""

import json
import time
import uuid
from dataclasses import dataclass, field
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any

from .hostile import HostileModel
from .detector import find_leaks, Leak


@dataclass
class InteractionLog:
    """A log entry for one request-response cycle."""
    timestamp: float
    request_messages: list[dict]
    request_tools: list[dict] | None
    response: dict
    leaks_in_response: list[Leak]


@dataclass
class SessionLog:
    """All interactions in a session, with leak summary."""
    interactions: list[InteractionLog] = field(default_factory=list)
    all_leaks: list[Leak] = field(default_factory=list)

    @property
    def leaked(self) -> bool:
        return len(self.all_leaks) > 0

    @property
    def verdict(self) -> str:
        if not self.interactions:
            return "NO_DATA"
        return "BEHAVIORAL" if self.leaked else "STRUCTURAL"

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "total_interactions": len(self.interactions),
            "total_leaks": len(self.all_leaks),
            "unique_secrets_leaked": len({l.secret for l in self.all_leaks}),
            "leaks": [
                {"secret": l.secret, "technique": l.technique, "evidence": l.evidence}
                for l in self.all_leaks
            ],
        }


class RogueHandler(BaseHTTPRequestHandler):
    """HTTP handler for the hostile OpenAI-compatible API."""

    def do_POST(self):
        if self.path == "/v1/chat/completions":
            self._handle_completions()
        elif self.path == "/v1/models":
            self._respond(200, {"data": [{"id": "rogue-hostile-1", "object": "model"}]})
        elif self.path == "/_report":
            self._respond(200, self.server.session.to_dict())
        else:
            self._respond(404, {"error": f"Unknown endpoint: {self.path}"})

    def do_GET(self):
        if self.path == "/v1/models":
            self._respond(200, {
                "object": "list",
                "data": [{"id": "rogue-hostile-1", "object": "model",
                          "created": int(time.time()), "owned_by": "rogue-llm"}],
            })
        elif self.path == "/_report":
            self._respond(200, self.server.session.to_dict())
        elif self.path == "/_health":
            self._respond(200, {"status": "ok", "secrets_loaded": len(self.server.secrets)})
        else:
            self._respond(404, {"error": f"Unknown endpoint: {self.path}"})

    def _handle_completions(self):
        body = self._read_body()
        if body is None:
            return

        messages = body.get("messages", [])
        tools = body.get("tools")

        # Generate hostile response
        result = self.server.hostile_model.respond(messages, tools)

        # Check for leaks in the response content
        response_text = result.get("content", "") or ""
        leaks = find_leaks(response_text, self.server.secrets) if response_text else []

        # Also check tool call arguments for leaks
        if result.get("tool_calls"):
            for tc in result["tool_calls"]:
                args_text = tc.get("function", {}).get("arguments", "")
                leaks.extend(find_leaks(args_text, self.server.secrets))

        # Log interaction
        log_entry = InteractionLog(
            timestamp=time.time(),
            request_messages=messages,
            request_tools=tools,
            response=result,
            leaks_in_response=leaks,
        )
        self.server.session.interactions.append(log_entry)
        self.server.session.all_leaks.extend(leaks)

        # Print real-time leak detection
        if leaks:
            self._print_leaks(leaks)

        # Format as OpenAI response
        response_id = f"chatcmpl-{uuid.uuid4().hex[:29]}"
        message: dict[str, Any] = {"role": "assistant"}
        if result.get("content"):
            message["content"] = result["content"]
        if result.get("tool_calls"):
            message["content"] = result.get("content")  # can be None
            message["tool_calls"] = result["tool_calls"]

        openai_response = {
            "id": response_id,
            "object": "chat.completion",
            "created": int(time.time()),
            "model": "rogue-hostile-1",
            "choices": [{
                "index": 0,
                "message": message,
                "finish_reason": "tool_calls" if result.get("tool_calls") else "stop",
            }],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        }

        self._respond(200, openai_response)

    def _print_leaks(self, leaks: list[Leak]):
        for leak in leaks:
            print(f"  \033[91m✗ LEAK\033[0m {leak.secret!r} via {leak.technique}")
            print(f"    evidence: ...{leak.evidence}...")

    def _read_body(self) -> dict | None:
        length = int(self.headers.get("Content-Length", 0))
        if not length:
            self._respond(400, {"error": "Empty request body"})
            return None
        try:
            return json.loads(self.rfile.read(length))
        except json.JSONDecodeError:
            self._respond(400, {"error": "Invalid JSON"})
            return None

    def _respond(self, code: int, body: dict):
        data = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args):
        """Suppress default request logging — we log leaks instead."""
        pass


class RogueServer(HTTPServer):
    """HTTP server with hostile model and session tracking."""

    def __init__(self, host: str, port: int, secrets: list[str]):
        super().__init__((host, port), RogueHandler)
        self.secrets = secrets
        self.hostile_model = HostileModel(secrets)
        self.session = SessionLog()


def create_server(host: str = "127.0.0.1", port: int = 8642,
                  secrets: list[str] | None = None) -> RogueServer:
    """Create a hostile LLM server."""
    return RogueServer(host, port, secrets or [])
